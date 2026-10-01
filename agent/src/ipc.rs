use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::os::windows::io::FromRawHandle;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{
    CloseHandle, GetLastError, HLOCAL, LocalFree, ERROR_PIPE_CONNECTED, INVALID_HANDLE_VALUE,
};
use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Storage::FileSystem::PIPE_ACCESS_DUPLEX;
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_WAIT,
};

pub const PIPE_NAME: &str = r"\\.\pipe\CyclothoneAgent";
const PIPE_SDDL: &str = r"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)";
const MAX_REQUEST_BYTES: usize = 4096;
const MAX_REQUEST_ID_BYTES: usize = 128;

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

pub fn spawn_status_server(
    api_configured: bool,
    device_id: Option<String>,
    tenant_id: Option<String>,
) {
    std::thread::Builder::new()
        .name("cyclothone-ipc".into())
        .spawn(move || {
            if let Err(error) = server_loop(api_configured, device_id, tenant_id) {
                tracing::error!(%error, "agent IPC server stopped");
            }
        })
        .expect("spawn Cyclothone IPC server");
}

fn server_loop(
    api_configured: bool,
    device_id: Option<String>,
    tenant_id: Option<String>,
) -> Result<()> {
    loop {
        let mut security_descriptor: PSECURITY_DESCRIPTOR = PSECURITY_DESCRIPTOR::default();
        let sddl = to_wide(PIPE_SDDL);
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
            LocalFree(Some(HLOCAL(security_descriptor.0 as *mut _)));
        }

        if pipe == INVALID_HANDLE_VALUE {
            anyhow::bail!("CreateNamedPipeW failed: {}", unsafe { GetLastError().0 });
        }

        let connected = unsafe { ConnectNamedPipe(pipe, None) };
        if let Err(error) = connected {
            let last_error = unsafe { GetLastError() };
            if last_error != ERROR_PIPE_CONNECTED {
                unsafe { CloseHandle(pipe) };
                tracing::debug!(%error, code = last_error.0, "agent IPC client connection failed");
                continue;
            }
        }

        let mut file = unsafe { File::from_raw_handle(pipe.0 as *mut _) };
        let mut line = String::new();
        let request = {
            let mut reader = BufReader::new(&mut file);
            read_line_bounded(&mut reader, &mut line, MAX_REQUEST_BYTES)
                .and_then(|_| serde_json::from_str::<IpcRequest>(line.trim()).context("decode IPC request"))
        };

        let response = match request {
            Ok(req) if valid_request(&req) && req.operation == "GetStatus" => AgentStatus {
                version: 1,
                request_id: req.request_id,
                status: "connected".into(),
                device_id: device_id.clone(),
                tenant_id: tenant_id.clone(),
                protection: "agent-reachable".into(),
                api_configured,
            },
            Ok(req) => AgentStatus {
                version: 1,
                request_id: if req.request_id.len() <= MAX_REQUEST_ID_BYTES {
                    req.request_id
                } else {
                    "rejected".into()
                },
                status: "rejected".into(),
                device_id: None,
                tenant_id: None,
                protection: "unsupported or invalid IPC request".into(),
                api_configured: false,
            },
            Err(_) => AgentStatus {
                version: 1,
                request_id: "invalid".into(),
                status: "rejected".into(),
                device_id: None,
                tenant_id: None,
                protection: "invalid IPC request".into(),
                api_configured: false,
            },
        };

        writeln!(file, "{}", serde_json::to_string(&response)?)?;
        file.flush()?;
    }
}

fn valid_request(request: &IpcRequest) -> bool {
    request.version == 1
        && !request.request_id.is_empty()
        && request.request_id.len() <= MAX_REQUEST_ID_BYTES
}

fn read_line_bounded<R: std::io::BufRead>(
    reader: &mut R,
    output: &mut String,
    limit: usize,
) -> Result<usize> {
    output.clear();
    let mut bytes = Vec::with_capacity(limit.min(256));
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            break;
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let take = newline.map(|index| index + 1).unwrap_or(available.len());
        if bytes.len() + take > limit {
            anyhow::bail!("IPC request exceeds {} bytes", limit);
        }
        bytes.extend_from_slice(&available[..take]);
        reader.consume(take);
        if newline.is_some() {
            break;
        }
    }
    *output = String::from_utf8(bytes).context("IPC request is not UTF-8")?;
    Ok(output.len())
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
        let decoded = serde_json::from_str::<IpcRequest>(&encoded).unwrap();
        assert_eq!(decoded.version, 1);
        assert!(valid_request(&decoded));
    }

    #[test]
    fn request_validation_rejects_empty_or_oversized_ids() {
        let empty = IpcRequest {
            version: 1,
            request_id: String::new(),
            operation: "GetStatus".into(),
        };
        assert!(!valid_request(&empty));

        let oversized = IpcRequest {
            version: 1,
            request_id: "x".repeat(MAX_REQUEST_ID_BYTES + 1),
            operation: "GetStatus".into(),
        };
        assert!(!valid_request(&oversized));
    }

    #[test]
    fn bounded_reader_rejects_oversized_input() {
        let mut input = std::io::Cursor::new(vec![b'x'; MAX_REQUEST_BYTES + 1]);
        let mut output = String::new();
        assert!(read_line_bounded(&mut input, &mut output, MAX_REQUEST_BYTES).is_err());
    }

    #[test]
    fn ipc_acl_targets_interactive_users_not_all_authenticated_users() {
        assert!(PIPE_SDDL.contains(";;;IU)"));
        assert!(!PIPE_SDDL.contains(";;;AU)"));
    }
}
