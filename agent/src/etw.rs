use std::{
    ffi::c_void,
    fs::OpenOptions,
    io::Write,
    mem::size_of,
    sync::mpsc::{self, Receiver, Sender},
    thread,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{anyhow, Context, Result};
use serde_json::json;
use tracing::{debug, info};
use windows::core::PCWSTR;
use windows::Win32::Foundation::WIN32_ERROR;
use windows::Win32::System::Diagnostics::Etw::*;

use crate::{EndpointEvent, EventKind};

const SESSION_NAME: PCWSTR = windows::core::w!("SentinelKernel");
const WNODE_FLAG_TRACED_GUID_VALUE: u32 = 0x0002_0000;
const CALLBACK_ERROR_LOG: &str = r"C:\ProgramData\Sentinel\agent-errors.log";

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
        logfile.Anonymous1.ProcessTraceMode =
            PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        logfile.Context = context as *mut c_void;
        logfile.Anonymous2.EventRecordCallback = Some(event_record_callback);

        let consumer = unsafe { OpenTraceW(&mut logfile) };
        if consumer.Value == u64::MAX {
            let _ = stop_kernel_session(session);
            unsafe { drop(Box::from_raw(context)); }
            return Err(anyhow!("OpenTraceW failed"));
        }

        info!("Sentinel kernel ETW session started");
        Ok(Self { session, consumer, receiver, context })
    }

    pub fn run(mut self, mut sink: impl FnMut(EndpointEvent) + Send + 'static) -> Result<()> {
        let handle = self.consumer;
        let receiver = &self.receiver;

        let consumer_thread = thread::scope(|scope| {
            let thread_handle = scope.spawn(|| {
                while let Ok(event) = receiver.recv() {
                    sink(event);
                }
            });

            let status = unsafe { ProcessTrace(&[handle], None, None) };
            let _ = thread_handle.join();
            status
        });

        unsafe { let _ = CloseTrace(handle); }
        let _ = stop_kernel_session(self.session);
        unsafe { drop(Box::from_raw(self.context)); }

        // Prevent Drop from closing/freeing resources a second time.
        self.consumer = PROCESSTRACE_HANDLE { Value: 0 };
        self.session = CONTROLTRACE_HANDLE { Value: 0 };
        self.context = std::ptr::null_mut();

        if consumer_thread != WIN32_ERROR(0) {
            return Err(anyhow!("ProcessTrace failed with Win32 status {:?}", consumer_thread));
        }
        Ok(())
    }
}

impl Drop for EtwCollector {
    fn drop(&mut self) {
        if self.consumer.Value != 0 {
            unsafe { let _ = CloseTrace(self.consumer); }
            self.consumer = PROCESSTRACE_HANDLE { Value: 0 };
        }
        if self.session.Value != 0 {
            let _ = stop_kernel_session(self.session);
            self.session = CONTROLTRACE_HANDLE { Value: 0 };
        }
        if !self.context.is_null() {
            unsafe { drop(Box::from_raw(self.context)); }
            self.context = std::ptr::null_mut();
        }
    }
}

struct CallbackContext {
    host_id: String,
    tx: Sender<EndpointEvent>,
}

fn log_callback_panic() {
    let _ = OpenOptions::new()
        .create(true)
        .append(true)
        .open(CALLBACK_ERROR_LOG)
        .and_then(|mut file| {
            writeln!(file, "etw callback panic at {:?}", SystemTime::now())
        });
}

unsafe extern "system" fn event_record_callback(record: *mut EVENT_RECORD) {
    // ETW invokes this callback from a tracing thread. Never allow a Rust
    // panic to unwind across the FFI boundary.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        process_record(record);
    }));
    if result.is_err() {
        log_callback_panic();
    }
}

unsafe fn process_record(record: *mut EVENT_RECORD) {
    if record.is_null() {
        return;
    }
    let record = &*record;
    let ctx_ptr = record.UserContext as *mut CallbackContext;
    if ctx_ptr.is_null() {
        return;
    }
    let ctx = &*ctx_ptr;

    let descriptor = record.EventHeader.EventDescriptor;
    let kind = classify_event(descriptor.Opcode, descriptor.Id);
    let pid = record.EventHeader.ProcessId;
    let event_id = format!(
        "etw-{:016x}-{}-{}",
        record.EventHeader.TimeStamp as u64,
        pid,
        descriptor.Id
    );
    let observed_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| format!("{}.{:09}Z", d.as_secs(), d.subsec_nanos()))
        .unwrap_or_else(|_| "0Z".to_string());

    let payload = json!({
        "provider_id": format!("{:?}", record.EventHeader.ProviderId),
        "event_id": descriptor.Id,
        "version": descriptor.Version,
        "opcode": descriptor.Opcode,
        "level": descriptor.Level,
        "keywords": descriptor.Keyword,
        "thread_id": record.EventHeader.ThreadId,
        "event_timestamp": record.EventHeader.TimeStamp,
        "user_data_length": record.UserDataLength,
        "user_data": user_data_hex(record),
    });

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
        payload,
    };

    if event.validate().is_ok() && ctx.tx.send(event).is_err() {
        debug!("ETW consumer channel closed");
    }
}

fn classify_event(opcode: u8, _id: u16) -> EventKind {
    match opcode {
        1 => EventKind::ProcessStart,
        2 => EventKind::ProcessStop,
        _ => EventKind::Unknown,
    }
}

unsafe fn user_data_hex(record: &EVENT_RECORD) -> String {
    if record.UserData.is_null() || record.UserDataLength == 0 {
        return String::new();
    }
    let bytes = std::slice::from_raw_parts(
        record.UserData as *const u8,
        record.UserDataLength as usize,
    );
    hex::encode(bytes)
}

fn start_kernel_session() -> Result<CONTROLTRACE_HANDLE> {
    let mut properties: EVENT_TRACE_PROPERTIES = unsafe { std::mem::zeroed() };
    properties.Wnode.BufferSize = size_of::<EVENT_TRACE_PROPERTIES>() as u32;
    properties.Wnode.Flags = WNODE_FLAG_TRACED_GUID_VALUE;
    properties.Wnode.ClientContext = 1;
    properties.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    // Kernel process telemetry is the stable capability already supported by
    // this agent. Keep the session narrow until provider-specific schemas are
    // decoded and normalized rather than emitting misleading network/file data.
    properties.EnableFlags = EVENT_TRACE_FLAG_PROCESS;
    properties.BufferSize = 64;
    properties.MinimumBuffers = 8;
    properties.MaximumBuffers = 64;

    let mut session = CONTROLTRACE_HANDLE { Value: 0 };
    let status = unsafe { StartTraceW(&mut session, SESSION_NAME, &mut properties) };
    if status != WIN32_ERROR(0) {
        return Err(anyhow!("StartTraceW failed with Win32 status {:?}", status));
    }
    Ok(session)
}

fn stop_kernel_session(session: CONTROLTRACE_HANDLE) -> Result<()> {
    let mut properties: EVENT_TRACE_PROPERTIES = unsafe { std::mem::zeroed() };
    properties.Wnode.BufferSize = size_of::<EVENT_TRACE_PROPERTIES>() as u32;
    let status = unsafe {
        ControlTraceW(session, SESSION_NAME, &mut properties, EVENT_TRACE_CONTROL_STOP)
    };
    if status != WIN32_ERROR(0) {
        debug!(status = ?status, "ETW session stop returned non-zero status");
    }
    Ok(())
}
