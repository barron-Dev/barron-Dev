use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::os::windows::io::FromRawHandle;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{GetLastError, INVALID_HANDLE_VALUE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_NONE, OPEN_EXISTING,
};

pub const PIPE_NAME: &str = r"\\.\pipe\CyclothoneAgent";

#[derive(Debug, Serialize, Deserialize)]
pub struct IpcRequest {
    pub version: u16,
    pub request_id: String,
    pub operation: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AgentStatus {
    pub version: u16,
    pub request_id: String,
    pub status: String,
    pub device_id: Option<String>,
    pub tenant_id: Option<String>,
    pub protection: String,
    pub api_configured: bool,
}

pub fn query_status() -> Result<AgentStatus> {
    let wide = to_wide(PIPE_NAME);
    let handle = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0,
            FILE_SHARE_NONE,
            None,
            OPEN_EXISTING,
            Default::default(),
            None,
        )
    }
    .context("open Cyclothone agent IPC pipe")?;

    if handle == INVALID_HANDLE_VALUE {
        anyhow::bail!(
            "Cyclothone agent IPC pipe is unavailable: {}",
            unsafe { GetLastError().0 }
        );
    }

    let mut file = unsafe { File::from_raw_handle(handle.0 as *mut _) };
    let request = IpcRequest {
        version: 1,
        request_id: format!("{:x}", std::process::id()),
        operation: "GetStatus".to_owned(),
    };
    writeln!(file, "{}", serde_json::to_string(&request)?)?;
    file.flush()?;

    let mut reader = BufReader::new(file);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    serde_json::from_str(line.trim()).context("decode agent IPC response")
}

fn to_wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_round_trip() {
        let request = IpcRequest {
            version: 1,
            request_id: "test".into(),
            operation: "GetStatus".into(),
        };
        let encoded = serde_json::to_string(&request).unwrap();
        let decoded: IpcRequest = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded.version, 1);
        assert_eq!(decoded.operation, "GetStatus");
    }
}
