use crate::ipc::{query_status, AgentStatus};
use eframe::egui;
use std::time::{Duration, Instant};

pub struct CyclothoneApp {
    status: Option<AgentStatus>,
    last_poll: Instant,
    message: String,
}

impl CyclothoneApp {
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        Self {
            status: None,
            last_poll: Instant::now() - Duration::from_secs(10),
            message: "Connecting to Cyclothone Agent…".into(),
        }
    }

    fn refresh(&mut self) {
        match query_status() {
            Ok(status) => {
                self.message = "Connected to Cyclothone Agent".into();
                self.status = Some(status);
            }
            Err(error) => {
                self.message = format!("Agent unavailable: {error:#}");
                self.status = None;
            }
        }
        self.last_poll = Instant::now();
    }
}

impl eframe::App for CyclothoneApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.last_poll.elapsed() >= Duration::from_secs(2) {
            self.refresh();
        }

        let panel = egui::Color32::from_rgb(5, 18, 29);
        let surface = egui::Color32::from_rgb(10, 31, 45);
        let text = egui::Color32::from_rgb(222, 238, 243);
        let muted = egui::Color32::from_rgb(139, 174, 187);

        egui::CentralPanel::default()
            .frame(egui::Frame::NONE.fill(panel).inner_margin(36.0))
            .show(ctx, |ui| {
                ui.vertical_centered(|ui| {
                    ui.add_space(10.0);
                    ui.label(egui::RichText::new("CYCLOTHONE").size(30.0).strong().color(text));
                    ui.label(egui::RichText::new("SECURITY WORKSTATION").size(12.0).color(muted));
                });

                ui.add_space(30.0);

                let available = ui.available_width();
                ui.columns(2, |columns| {
                    columns[0].group(|ui| {
                        ui.set_min_height(270.0);
                        ui.label(egui::RichText::new("DEVICE").size(13.0).color(muted));
                        ui.add_space(12.0);

                        let (state, detail) = match &self.status {
                            Some(s) => (
                                if s.protection == "protected" { "PROTECTED" } else { "ATTENTION" },
                                format!(
                                    "Enrollment: {}\nSecure channel: {}\nBackend telemetry: {}",
                                    if s.enrolled { "confirmed" } else { "required" },
                                    if s.mtls_ready { "ready" } else { "not ready" },
                                    if s.telemetry_healthy { "confirmed" } else { "not confirmed" }
                                ),
                            ),
                            _ => ("NOT CONNECTED", "Cyclothone Agent is not reachable.".into()),
                        };

                        ui.label(egui::RichText::new(state).size(34.0).strong().color(text));
                        ui.add_space(12.0);
                        ui.label(egui::RichText::new(detail).size(15.0).color(muted));

                        if let Some(s) = &self.status {
                            ui.add_space(18.0);
                            ui.label(egui::RichText::new(format!(
                                "Tenant: {}",
                                s.tenant_id.as_deref().unwrap_or("not assigned")
                            )).size(13.0).color(muted));
                        }
                    });

                    columns[1].group(|ui| {
                        ui.set_min_height(270.0);
                        ui.label(egui::RichText::new("SYSTEM").size(13.0).color(muted));
                        ui.add_space(12.0);
                        ui.label(egui::RichText::new("Live agent connection").size(22.0).strong().color(text));
                        ui.add_space(8.0);
                        ui.label(egui::RichText::new(&self.message).size(14.0).color(muted));
                        ui.add_space(20.0);

                        if let Some(s) = &self.status {
                            ui.label(egui::RichText::new(if s.api_configured {
                                "Backend endpoint configured"
                            } else {
                                "Backend endpoint not configured"
                            }).size(15.0).color(text));
                        }

                        ui.add_space(30.0);
                        ui.label(egui::RichText::new("No security metrics are shown until they are supplied by the live agent or Cyclothone API.").size(13.0).color(muted));
                    });
                });

                ui.add_space(available.min(36.0) * 0.25);
                ui.label(egui::RichText::new("AI reasons/plans. Trust verifies. Control authorizes. Execution acts. Evidence proves.").size(12.0).color(muted));
            });

        ctx.request_repaint_after(Duration::from_millis(250));
    }
}
