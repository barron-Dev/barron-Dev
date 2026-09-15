use std::{
    ffi::c_void,
    fs::OpenOptions,
    io::Write,
    mem::size_of,
    ptr::null_mut,
    sync::mpsc::{self, Receiver, Sender},
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
const EVENT_HEADER_FLAG_32_BIT_HEADER_VALUE: u16 = 0x0020;
const EVENT_HEADER_FLAG_64_BIT_HEADER_VALUE: u16 = 0x0040;

const PROCESS_GUID_DATA1: u32 = 0x3d6fa8d0;
const PROCESS_GUID_DATA2: u16 = 0xfe05;
const PROCESS_GUID_DATA3: u16 = 0x11d0;
const PROCESS_GUID_DATA4: [u8; 8] = [0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c];

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

        // Windows 0.62 exposes the modern real-time consumer API directly;
        // use it instead of the legacy EVENT_TRACE_LOGFILEW/OpenTraceW pair.
        let options = ETW_OPEN_TRACE_OPTIONS {
            ProcessTraceModes: ETW_PROCESS_TRACE_MODE_NONE,
            EventCallback: Some(event_record_callback),
            EventCallbackContext: context as *mut c_void,
            BufferCallback: None,
            BufferCallbackContext: null_mut(),
        };

        let consumer = unsafe {
            OpenTraceFromRealTimeLogger(SESSION_NAME, &options, null_mut())
        };
        if consumer.Value == u64::MAX {
            let _ = stop_kernel_session(session);
            unsafe { drop(Box::from_raw(context)); }
            return Err(anyhow!("OpenTraceFromRealTimeLogger failed"));
        }

        info!("Sentinel kernel ETW session started");
        Ok(Self { session, consumer, receiver, context })
    }

    pub fn run(mut self, mut sink: impl FnMut(EndpointEvent) + Send + 'static) -> Result<()> {
        let handle = self.consumer;
        let receiver = std::mem::replace(&mut self.receiver, mpsc::channel().1);
        let context = self.context;
        self.context = null_mut();

        let consumer_thread = std::thread::spawn(move || {
            while let Ok(event) = receiver.recv() {
                sink(event);
            }
        });

        let process_status = unsafe { ProcessTrace(&[handle], None, None) };

        unsafe { drop(Box::from_raw(context)); }
        let _ = consumer_thread.join();

        unsafe { let _ = CloseTrace(handle); }
        let _ = stop_kernel_session(self.session);

        self.consumer = PROCESSTRACE_HANDLE { Value: 0 };
        self.session = CONTROLTRACE_HANDLE { Value: 0 };

        if process_status != WIN32_ERROR(0) {
            return Err(anyhow!(
                "ProcessTrace failed with Win32 status {:?}",
                process_status
            ));
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
            self.context = null_mut();
        }
    }
}

pub fn stop_named_session() -> Result<()> {
    let session = CONTROLTRACE_HANDLE { Value: 0 };
    stop_kernel_session(session)
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
        .and_then(|mut file| writeln!(file, "etw callback panic at {:?}", SystemTime::now()));
}

unsafe extern "system" fn event_record_callback(record: *mut EVENT_RECORD) {
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
    let process_schema = if is_process_guid(&record.EventHeader.ProviderId) {
        decode_process_payload(
            descriptor.Version,
            descriptor.Opcode,
            record.EventHeader.Flags,
            record.UserData,
            record.UserDataLength,
        )
    } else {
        None
    };

    let kind = classify_event(descriptor.Opcode);
    let event_id = format!(
        "etw-{:016x}-{}-{}",
        record.EventHeader.TimeStamp as u64,
        record.EventHeader.ProcessId,
        descriptor.Id
    );
    let observed_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| format!("{}.{:09}Z", d.as_secs(), d.subsec_nanos()))
        .unwrap_or_else(|_| "0Z".to_string());

    let mut payload = json!({
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

    let (pid, parent_pid, image, command_line) = if let Some(decoded) = process_schema {
        payload["process_schema"] = json!({
            "version": decoded.version,
            "session_id": decoded.session_id,
            "exit_status": decoded.exit_status,
            "schema": "Process_TypeGroup1",
            "provider": "ProcessGuid",
        });
        (
            Some(decoded.pid),
            Some(decoded.parent_pid),
            if decoded.image.is_empty() { None } else { Some(decoded.image) },
            decoded.command_line,
        )
    } else {
        (None, None, None, None)
    };

    let event = EndpointEvent {
        schema_version: EndpointEvent::SCHEMA_VERSION,
        event_id,
        observed_at,
        kind,
        host_id: ctx.host_id.clone(),
        pid,
        parent_pid,
        image,
        command_line,
        remote_address: None,
        remote_port: None,
        payload,
    };

    if event.validate().is_ok() && ctx.tx.send(event).is_err() {
        debug!("ETW consumer channel closed");
    }
}

#[derive(Debug, PartialEq, Eq)]
struct DecodedProcess {
    version: u8,
    pid: u32,
    parent_pid: u32,
    session_id: u32,
    exit_status: i32,
    image: String,
    command_line: Option<String>,
}

fn is_process_guid(guid: &windows::core::GUID) -> bool {
    guid.data1 == PROCESS_GUID_DATA1
        && guid.data2 == PROCESS_GUID_DATA2
        && guid.data3 == PROCESS_GUID_DATA3
        && guid.data4 == PROCESS_GUID_DATA4
}

fn decode_process_payload(
    version: u8,
    opcode: u8,
    header_flags: u16,
    user_data: *mut c_void,
    user_data_length: u16,
) -> Option<DecodedProcess> {
    let bytes = unsafe {
        if user_data.is_null() || user_data_length == 0 {
            return None;
        }
        std::slice::from_raw_parts(user_data as *const u8, user_data_length as usize)
    };

    match opcode {
        1 | 3 => decode_process_start_bytes(version, header_flags, bytes),
        2 => decode_process_end_bytes(version, header_flags, bytes),
        _ => None,
    }
}

fn decode_process_start_bytes(version: u8, header_flags: u16, bytes: &[u8]) -> Option<DecodedProcess> {
    if version > 3 {
        return None;
    }

    let pointer_size = pointer_size_from_header_flags(header_flags);
    let mut cursor = 0usize;

    if version >= 1 {
        read_pointer(bytes, &mut cursor, pointer_size)?;
    }

    let (pid, parent_pid) = if version == 0 {
        (
            read_pointer(bytes, &mut cursor, pointer_size)? as u32,
            read_pointer(bytes, &mut cursor, pointer_size)? as u32,
        )
    } else {
        (read_u32(bytes, &mut cursor)?, read_u32(bytes, &mut cursor)?)
    };

    let (session_id, exit_status) = if version >= 1 {
        (read_u32(bytes, &mut cursor)?, read_i32(bytes, &mut cursor)?)
    } else {
        (0, 0)
    };

    if version >= 3 {
        read_pointer(bytes, &mut cursor, pointer_size)?;
    }

    skip_sid(bytes, &mut cursor)?;
    let image = read_ansi_z(bytes, &mut cursor)?;
    let command_line = if version >= 2 {
        Some(read_utf16_z(bytes, &mut cursor)?)
    } else {
        None
    };

    Some(DecodedProcess {
        version,
        pid,
        parent_pid,
        session_id,
        exit_status,
        image,
        command_line,
    })
}

fn decode_process_end_bytes(version: u8, header_flags: u16, bytes: &[u8]) -> Option<DecodedProcess> {
    if version > 3 {
        return None;
    }
    let pointer_size = pointer_size_from_header_flags(header_flags);
    let mut cursor = 0usize;
    let pid = if version == 0 {
        read_pointer(bytes, &mut cursor, pointer_size)? as u32
    } else {
        read_pointer(bytes, &mut cursor, pointer_size)?;
        read_u32(bytes, &mut cursor)?
    };

    Some(DecodedProcess {
        version,
        pid,
        parent_pid: 0,
        session_id: 0,
        exit_status: 0,
        image: String::new(),
        command_line: None,
    })
}

fn pointer_size_from_header_flags(flags: u16) -> usize {
    if flags & EVENT_HEADER_FLAG_32_BIT_HEADER_VALUE != 0 {
        4
    } else if flags & EVENT_HEADER_FLAG_64_BIT_HEADER_VALUE != 0 {
        8
    } else {
        size_of::<usize>()
    }
}

fn read_pointer(bytes: &[u8], cursor: &mut usize, pointer_size: usize) -> Option<u64> {
    match pointer_size {
        4 => Some(read_u32(bytes, cursor)? as u64),
        8 => {
            let end = cursor.checked_add(8)?;
            let chunk = bytes.get(*cursor..end)?;
            *cursor = end;
            Some(u64::from_le_bytes(chunk.try_into().ok()?))
        }
        _ => None,
    }
}

fn read_u32(bytes: &[u8], cursor: &mut usize) -> Option<u32> {
    let end = cursor.checked_add(4)?;
    let chunk = bytes.get(*cursor..end)?;
    *cursor = end;
    Some(u32::from_le_bytes(chunk.try_into().ok()?))
}

fn read_i32(bytes: &[u8], cursor: &mut usize) -> Option<i32> {
    Some(read_u32(bytes, cursor)? as i32)
}

fn skip_sid(bytes: &[u8], cursor: &mut usize) -> Option<()> {
    let revision = *bytes.get(*cursor)?;
    let sub_authority_count = *bytes.get(cursor.checked_add(1)?)?;
    if revision == 0 || sub_authority_count > 15 {
        return None;
    }
    let sid_len = 8usize.checked_add((sub_authority_count as usize).checked_mul(4)?)?;
    let end = cursor.checked_add(sid_len)?;
    bytes.get(*cursor..end)?;
    *cursor = end;
    Some(())
}

fn read_ansi_z(bytes: &[u8], cursor: &mut usize) -> Option<String> {
    let start = *cursor;
    let relative_end = bytes.get(start..)?.iter().position(|b| *b == 0)?;
    let end = start.checked_add(relative_end)?;
    *cursor = end.checked_add(1)?;
    Some(String::from_utf8_lossy(bytes.get(start..end)?).into_owned())
}

fn read_utf16_z(bytes: &[u8], cursor: &mut usize) -> Option<String> {
    let mut units = Vec::new();
    loop {
        let lo = *bytes.get(*cursor)?;
        let hi = *bytes.get(cursor.checked_add(1)?)?;
        *cursor = cursor.checked_add(2)?;
        let unit = u16::from_le_bytes([lo, hi]);
        if unit == 0 {
            return String::from_utf16(&units).ok();
        }
        units.push(unit);
    }
}

fn classify_event(opcode: u8) -> EventKind {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn push_u32(out: &mut Vec<u8>, value: u32) { out.extend_from_slice(&value.to_le_bytes()); }
    fn push_u64(out: &mut Vec<u8>, value: u64) { out.extend_from_slice(&value.to_le_bytes()); }
    fn push_utf16_z(out: &mut Vec<u8>, value: &str) {
        for unit in value.encode_utf16() { out.extend_from_slice(&unit.to_le_bytes()); }
        out.extend_from_slice(&0u16.to_le_bytes());
    }

    #[test]
    fn process_opcodes_are_normalized() {
        assert_eq!(classify_event(1), EventKind::ProcessStart);
        assert_eq!(classify_event(2), EventKind::ProcessStop);
        assert_eq!(classify_event(0), EventKind::Unknown);
        assert_eq!(classify_event(255), EventKind::Unknown);
    }

    #[test]
    fn decodes_process_v3_payload_without_using_header_pid() {
        let mut payload = Vec::new();
        push_u64(&mut payload, 0x1122_3344_5566_7788);
        push_u32(&mut payload, 4242);
        push_u32(&mut payload, 1337);
        push_u32(&mut payload, 2);
        push_u32(&mut payload, 259);
        push_u64(&mut payload, 0x8877_6655_4433_2211);
        payload.extend_from_slice(&[1, 1, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0]);
        payload.extend_from_slice(b"C:\\Windows\\System32\\cmd.exe\0");
        push_utf16_z(&mut payload, "cmd.exe /c whoami");

        let decoded = decode_process_start_bytes(3, EVENT_HEADER_FLAG_64_BIT_HEADER_VALUE, &payload)
            .expect("valid Process v3 payload");

        assert_eq!(decoded.version, 3);
        assert_eq!(decoded.pid, 4242);
        assert_eq!(decoded.parent_pid, 1337);
        assert_eq!(decoded.session_id, 2);
        assert_eq!(decoded.exit_status, 259);
        assert_eq!(decoded.image, "C:\\Windows\\System32\\cmd.exe");
        assert_eq!(decoded.command_line.as_deref(), Some("cmd.exe /c whoami"));
    }

    #[test]
    fn rejects_truncated_process_payload() {
        let payload = [0u8; 24];
        assert!(decode_process_start_bytes(3, EVENT_HEADER_FLAG_64_BIT_HEADER_VALUE, &payload).is_none());
    }
}
