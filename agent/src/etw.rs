use std::{ffi::c_void, mem::size_of, sync::mpsc::{self, Receiver, Sender}, thread, time::{SystemTime, UNIX_EPOCH}};
use anyhow::{anyhow, Context, Result};
use serde_json::json;
use tracing::{debug, info};
use windows::core::PCWSTR;
use windows::Win32::System::Diagnostics::Etw::*;
use crate::{EndpointEvent, EventKind};

const SESSION_NAME: PCWSTR = windows::core::w!("SentinelKernel");
const WNODE_FLAG_TRACED_GUID_VALUE: u32 = 0x0002_0000;

pub struct EtwCollector {
    session: CONTROLTRACE_HANDLE,
    consumer: PROCESSTRACE_HANDLE,
    receiver: Receiver<EndpointEvent>,
    context: *mut CallbackContext,
}

unsafe impl Send for EtwCollector {}

impl EtwCollector {
    pub fn start(host_id: impl Into<String>) -> Result<Self> {
        let host_id = host_id.into();
        anyhow::ensure!(!host_id.trim().is_empty(), "host_id is required");

        let session = start_kernel_session().context("start Sentinel ETW kernel session")?;
        let (tx, receiver) = mpsc::channel();
        let context = Box::into_raw(Box::new(CallbackContext { host_id, tx }));

        let mut logfile: EVENT_TRACE_LOGFILEW = unsafe { std::mem::zeroed() };
        logfile.LoggerName = SESSION_NAME.0 as *mut u16;
        logfile.ProcessTraceMode = EVENT_TRACE_REAL_TIME_MODE;
        logfile.Context = context as *mut c_void;
        logfile.Anonymous2.EventRecordCallback = Some(event_record_callback);

        let consumer = unsafe { OpenTraceW(&mut logfile) };
        if consumer == INVALID_PROCESSTRACE_HANDLE {
            let _ = stop_kernel_session(session);
            unsafe { drop(Box::from_raw(context)); }
            return Err(anyhow!("OpenTraceW failed"));
        }

        info!("Sentinel kernel ETW session started");
        Ok(Self { session, consumer, receiver, context })
    }

    pub fn run(self, mut sink: impl FnMut(EndpointEvent) + Send + 'static) -> Result<()> {
        let handle = self.consumer;
        let receiver = self.receiver;
        let consumer_thread = thread::spawn(move || {
            while let Ok(event) = receiver.recv() {
                sink(event);
            }
        });

        let status = unsafe { ProcessTrace(&[handle], None, None) };
        unsafe { let _ = CloseTrace(handle); }
        let _ = stop_kernel_session(self.session);
        unsafe { drop(Box::from_raw(self.context)); }
        let _ = consumer_thread.join();

        if status != 0 {
            return Err(anyhow!("ProcessTrace failed with Win32 status {status}"));
        }
        Ok(())
    }
}

struct CallbackContext { host_id: String, tx: Sender<EndpointEvent> }

unsafe extern "system" fn event_record_callback(record: *mut EVENT_RECORD) {
    if record.is_null() { return; }
    let record = &*record;
    let ctx_ptr = record.UserContext as *mut CallbackContext;
    if ctx_ptr.is_null() { return; }
    let ctx = &*ctx_ptr;

    let descriptor = record.EventHeader.EventDescriptor;
    let kind = match descriptor.Opcode {
        1 => EventKind::ProcessStart,
        2 => EventKind::ProcessStop,
        _ => EventKind::Unknown,
    };
    let pid = record.EventHeader.ProcessId;
    let event_id = format!("etw-{:016x}-{}-{}", record.EventHeader.TimeStamp as u64, pid, descriptor.Id);
    let observed_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| format!("{}.{}Z", d.as_secs(), format!("{:09}", d.subsec_nanos())))
        .unwrap_or_else(|_| "0Z".to_string());

    let event = EndpointEvent {
        schema_version: EndpointEvent::SCHEMA_VERSION,
        event_id,
        observed_at,
        kind,
        host_id: ctx.host_id.clone(),
        pid: Some(pid),
        parent_pid: None,
        image: None,
        command_line: None,
        remote_address: None,
        remote_port: None,
        payload: json!({
            "provider_id": format!("{:?}", record.EventHeader.ProviderId),
            "event_id": descriptor.Id,
            "version": descriptor.Version,
            "opcode": descriptor.Opcode,
            "level": descriptor.Level,
            "keywords": descriptor.Keyword,
            "thread_id": record.EventHeader.ThreadId,
            "event_timestamp": record.EventHeader.TimeStamp,
            "user_data_length": record.UserDataLength,
        }),
    };
    if event.validate().is_ok() { let _ = ctx.tx.send(event); }
}

fn start_kernel_session() -> Result<CONTROLTRACE_HANDLE> {
    let mut properties: EVENT_TRACE_PROPERTIES = unsafe { std::mem::zeroed() };
    properties.Wnode.BufferSize = size_of::<EVENT_TRACE_PROPERTIES>() as u32;
    properties.Wnode.Flags = WNODE_FLAG_TRACED_GUID_VALUE;
    properties.Wnode.ClientContext = 1;
    properties.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    properties.EnableFlags = EVENT_TRACE_FLAG_PROCESS;
    properties.BufferSize = 64;
    properties.MinimumBuffers = 8;
    properties.MaximumBuffers = 64;

    let mut session = CONTROLTRACE_HANDLE(0);
    let status = unsafe { StartTraceW(&mut session, SESSION_NAME, &mut properties) };
    if status != 0 { return Err(anyhow!("StartTraceW failed with Win32 status {status}")); }
    Ok(session)
}

fn stop_kernel_session(session: CONTROLTRACE_HANDLE) -> Result<()> {
    let mut properties: EVENT_TRACE_PROPERTIES = unsafe { std::mem::zeroed() };
    properties.Wnode.BufferSize = size_of::<EVENT_TRACE_PROPERTIES>() as u32;
    let status = unsafe { ControlTraceW(session, SESSION_NAME, &mut properties, EVENT_TRACE_CONTROL_STOP) };
    if status != 0 { debug!(status, "ETW session stop returned non-zero status"); }
    Ok(())
}
