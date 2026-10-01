use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::os::windows::io::FromRawHandle;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, GetLastError, HLOCAL, INVALID_HANDLE_VALUE};
use windows::Win32::Security::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
    SDDL_REVISION_1,
};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, PIPE_ACCESS_DUPLEX, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE,
    PIPE_WAIT,
};
use windows::Win32::System::Memory::LocalFree;

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

pub fn spawn_status_server(api_configured: bool, device_id: Option<String>, tenant_id: Option<String>) {
    std::thread::Builder::new()
        .name("cyclothone-ipc".into())
        .spawn(move || {
            if let Err(error) = server_loop(api_configured, device_id, tenant_id) {
                tracing::error!(%error, "agent IPC server stopped");
            }
        })
        .expect("spawn Cyclothone IPC server");
}

fn server_loop(api_configured: bool, device_id: Option<String>, tenant_id: Option<String>) -> Result<()> {
    loop {
        let mut security_descriptor: PSECURITY_DESCRIPTOR = PSECURITY_DESCRIPTOR::default();
        let sddl = to_wide(r"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)");
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(sddl.as_ptr()),
                SDDL_REVISION_1,
                &mut security_descriptor,
                None,
            )
            .context("create IPC security descriptor")?;
        }

        let mut attrs = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: security_descriptor.0 as *mut _,
            bInheritHandle: false.into(),
        };

        let name = to_wide(PIPE_NAME);
        let pipe = unsafe {
            CreateNamedPipeW(
                PCWSTR(name.as_ptr()),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                1,
                8192,
                8192,
                5000,
                Some(&mut attrs),
            )
        };

        unsafe {
            LocalFree(HLOCAL(security_descriptor.0 as *mut _));
        }

        if pipe == INVALID_HANDLE_VALUE {
            anyhow::bail!("CreateNamedPipeW failed: {}", unsafe { GetLastError().0 });
        }

        if unsafe { ConnectNamedPipe(pipe, None) }.is_err() {
            unsafe { CloseHandle(pipe) };
            continue;
        }

        let mut file = unsafe { File::from_raw_handle(pipe.0 as *mut _) };
        let mut line = String::new();
        let request = {
            let mut reader = BufReader::new(&mut file);
            reader.read_line(&mut line).ok();
            serde_json::from_str::<IpcRequest>(line.trim())
        };

        let response = match request {
            Ok(req) if req.version == 1 && req.operation == "GetStatus" => AgentStatus {
                version: 1,
                request_id: req.request_id,
                status: "connected".into(),
                device_id: device_id.clone(),
                tenant_id: tenant_id.clone(),
                protection: "agent-active".into(),
                api_configured,
            },
            Ok(req) => AgentStatus {
                version: 1,
                request_id: req.request_id,
                status: "rejected".into(),
                device_id: None,
                tenant_id: None,
                protection: format!("unsupported operation: {}", req.operation),
                api_configured,
            },
            Err(_) => AgentStatus {
                version: 1,
                request_id: "invalid".into(),
                status: "rejected".into(),
                device_id: None,
                tenant_id: None,
                protection: "invalid IPC request".into(),
                api_configured,
            },
        };

        writeln!(file, "{}", serde_json::to_string(&response)?)?;
        file.flush()?;
    }
}

fn to_wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_serializes_status_request() {
        let request = IpcRequest {
            version: 1,
            request_id: "test".into(),
            operation: "GetStatus".into(),
        };
        let encoded = serde_json::to_string(&request).unwrap();
        assert!(encoded.contains("GetStatus"));
        assert_eq!(serde_json::from_str::<IpcRequest>(&encoded).unwrap().version, 1);
    }
}
