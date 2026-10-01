#![cfg_attr(not(windows), windows_subsystem = "windows")]

#[cfg(windows)]
mod app;
#[cfg(windows)]
mod ipc;

#[cfg(windows)]
fn main() -> eframe::Result<()> {
    eframe::run_native(
        "Cyclothone",
        eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default()
                .with_inner_size([1180.0, 760.0])
                .with_min_inner_size([980.0, 640.0]),
            ..Default::default()
        },
        Box::new(|cc| Ok(Box::new(app::CyclothoneApp::new(cc)))),
    )
}

#[cfg(not(windows))]
fn main() {
    eprintln!("Cyclothone Desktop is Windows-only.");
}
