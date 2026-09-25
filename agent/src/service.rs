#[cfg(windows)]
pub mod windows_service {
    use std::{ffi::OsString, time::Duration};
    use anyhow::Result;
    use windows_service::{
        define_windows_service,
        service::{ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType},
        service_control_handler::{self, ServiceControlHandlerResult},
        service_dispatcher,
    };
    const SERVICE_NAME: &str = "CyclothoneAgent";
    const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;
    define_windows_service!(ffi_service_main, service_main);
    pub fn run() -> windows_service::Result<()> { service_dispatcher::start(SERVICE_NAME, ffi_service_main) }
    fn service_main(_args: Vec<OsString>) {
        if let Err(error) = run_service() {
            let path = r"C:\ProgramData\Cyclothone\service-error.log";
            let _ = std::fs::create_dir_all(r"C:\ProgramData\Cyclothone");
            let _ = std::fs::write(path, format!("{error:#}"));
        }
    }
    fn run_service() -> Result<()> {
        let (shutdown_tx, shutdown_rx) = std::sync::mpsc::channel::<()>();
        let handler = move |control| match control {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                let _ = shutdown_tx.send(());
                let _ = crate::etw::stop_named_session();
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        };
        let status_handle = service_control_handler::register(SERVICE_NAME, handler)?;
        status_handle.set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE, current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            exit_code: ServiceExitCode::Win32(0), checkpoint: 0, wait_hint: Duration::default(), process_id: None,
        })?;
        let runtime = tokio::runtime::Runtime::new()?;
        let result = runtime.block_on(crate::run_agent());
        let _ = shutdown_rx.try_recv();
        let exit_code = match result {
            Ok(()) => ServiceExitCode::Win32(0),
            Err(error) => {
                let _ = std::fs::create_dir_all(r"C:\ProgramData\Cyclothone");
                let _ = std::fs::write(r"C:\ProgramData\Cyclothone\service-error.log", format!("{error:#}"));
                ServiceExitCode::Win32(1)
            }
        };
        status_handle.set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE, current_state: ServiceState::Stopped,
            controls_accepted: ServiceControlAccept::empty(), exit_code,
            checkpoint: 0, wait_hint: Duration::default(), process_id: None,
        })?;
        Ok(())
    }
}