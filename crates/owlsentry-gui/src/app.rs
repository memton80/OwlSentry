//! Interface egui : liste d'alertes filtrable, panneau de détails
//! (quoi / pourquoi / comment) et tableau de bord.

use crate::client::GuiEvent;
use chrono::{DateTime, Duration as ChronoDuration, Local, Timelike, Utc};
use eframe::egui;
use owlsentry_common::i18n::{self, tr};
use owlsentry_common::{Alert, Category, Lang, Severity};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Receiver;
use std::sync::Arc;

const MAX_ALERTS_IN_MEMORY: usize = 5000;

fn severity_color(sev: Severity) -> egui::Color32 {
    match sev {
        Severity::Info => egui::Color32::from_rgb(140, 140, 140),
        Severity::Low => egui::Color32::from_rgb(90, 140, 220),
        Severity::Medium => egui::Color32::from_rgb(220, 180, 60),
        Severity::High => egui::Color32::from_rgb(235, 130, 50),
        Severity::Critical => egui::Color32::from_rgb(220, 60, 60),
    }
}

#[derive(PartialEq, Clone, Copy)]
enum Tab {
    Alerts,
    Dashboard,
}

pub struct OwlSentryApp {
    rx: Receiver<GuiEvent>,
    notify_enabled: Arc<AtomicBool>,
    alerts: Vec<Alert>,
    connected: bool,
    lang: Lang,
    tab: Tab,
    min_severity: Severity,
    category_filter: Option<Category>,
    search: String,
    selected: Option<u64>,
    notify_checkbox: bool,
}

impl OwlSentryApp {
    pub fn new(rx: Receiver<GuiEvent>, notify_enabled: Arc<AtomicBool>, lang: Lang) -> Self {
        OwlSentryApp {
            rx,
            notify_enabled,
            alerts: Vec::new(),
            connected: false,
            lang,
            tab: Tab::Alerts,
            min_severity: Severity::Info,
            category_filter: None,
            search: String::new(),
            selected: None,
            notify_checkbox: true,
        }
    }

    fn drain_events(&mut self) {
        while let Ok(event) = self.rx.try_recv() {
            match event {
                GuiEvent::Connected { language } => {
                    self.connected = true;
                    // La langue du démon fait foi au premier contact.
                    self.lang = Lang::from_code(&language);
                }
                GuiEvent::Disconnected => self.connected = false,
                GuiEvent::Alert(alert) => {
                    self.alerts.push(alert);
                    if self.alerts.len() > MAX_ALERTS_IN_MEMORY {
                        let excess = self.alerts.len() - MAX_ALERTS_IN_MEMORY;
                        self.alerts.drain(..excess);
                    }
                }
                GuiEvent::Recent(mut alerts) => {
                    // Remplace l'historique (reconnexion comprise).
                    let known: std::collections::HashSet<u64> =
                        alerts.iter().map(|a| a.id).collect();
                    self.alerts.retain(|a| !known.contains(&a.id));
                    self.alerts.append(&mut alerts);
                    self.alerts.sort_by_key(|a| a.timestamp);
                }
            }
        }
    }

    fn matches_filters(&self, alert: &Alert) -> bool {
        if alert.severity < self.min_severity {
            return false;
        }
        if let Some(cat) = self.category_filter {
            if alert.category != cat {
                return false;
            }
        }
        if !self.search.is_empty() {
            let needle = self.search.to_lowercase();
            let hay = format!("{} {} {}", alert.title, alert.what, alert.why).to_lowercase();
            if !hay.contains(&needle) {
                return false;
            }
        }
        true
    }

    fn top_bar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.selectable_value(&mut self.tab, Tab::Alerts, tr(self.lang, "alerts"));
            ui.selectable_value(&mut self.tab, Tab::Dashboard, tr(self.lang, "dashboard"));
            ui.separator();
            let (dot, label) = if self.connected {
                (
                    egui::Color32::from_rgb(80, 200, 100),
                    tr(self.lang, "connected"),
                )
            } else {
                (
                    egui::Color32::from_rgb(220, 60, 60),
                    tr(self.lang, "disconnected"),
                )
            };
            ui.colored_label(dot, "●");
            ui.label(label);
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let lang_label = match self.lang {
                    Lang::Fr => "FR",
                    Lang::En => "EN",
                };
                if ui
                    .button(lang_label)
                    .on_hover_text(tr(self.lang, "language"))
                    .clicked()
                {
                    self.lang = match self.lang {
                        Lang::Fr => Lang::En,
                        Lang::En => Lang::Fr,
                    };
                }
                if ui
                    .checkbox(&mut self.notify_checkbox, tr(self.lang, "notifications"))
                    .changed()
                {
                    self.notify_enabled
                        .store(self.notify_checkbox, Ordering::Relaxed);
                }
            });
        });
    }

    fn filter_bar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label(tr(self.lang, "min_severity"));
            egui::ComboBox::from_id_salt("min_severity")
                .selected_text(i18n::severity_label(self.lang, self.min_severity))
                .show_ui(ui, |ui| {
                    for sev in Severity::ALL {
                        ui.selectable_value(
                            &mut self.min_severity,
                            sev,
                            i18n::severity_label(self.lang, sev),
                        );
                    }
                });
            ui.label(tr(self.lang, "category"));
            egui::ComboBox::from_id_salt("category")
                .selected_text(
                    self.category_filter
                        .map(|c| i18n::category_label(self.lang, c))
                        .unwrap_or(tr(self.lang, "all")),
                )
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.category_filter, None, tr(self.lang, "all"));
                    for cat in Category::ALL {
                        ui.selectable_value(
                            &mut self.category_filter,
                            Some(cat),
                            i18n::category_label(self.lang, cat),
                        );
                    }
                });
            ui.label(tr(self.lang, "search"));
            ui.text_edit_singleline(&mut self.search);
            if ui.button(tr(self.lang, "clear")).clicked() {
                self.search.clear();
                self.category_filter = None;
                self.min_severity = Severity::Info;
            }
        });
    }

    fn alerts_view(&mut self, ui: &mut egui::Ui) {
        self.filter_bar(ui);
        ui.separator();

        let filtered: Vec<Alert> = self
            .alerts
            .iter()
            .rev() // plus récentes en premier
            .filter(|a| self.matches_filters(a))
            .cloned()
            .collect();

        let selected_alert = self
            .selected
            .and_then(|id| self.alerts.iter().find(|a| a.id == id).cloned());

        egui::SidePanel::right("details")
            .resizable(true)
            .default_width(380.0)
            .show_inside(ui, |ui| {
                ui.heading(tr(self.lang, "details"));
                ui.separator();
                match &selected_alert {
                    None => {
                        ui.label(tr(self.lang, "no_alert_selected"));
                    }
                    Some(alert) => {
                        egui::ScrollArea::vertical().show(ui, |ui| {
                            ui.colored_label(
                                severity_color(alert.severity),
                                format!(
                                    "{} — {}",
                                    i18n::severity_label(self.lang, alert.severity),
                                    i18n::category_label(self.lang, alert.category)
                                ),
                            );
                            ui.label(
                                alert
                                    .timestamp
                                    .with_timezone(&Local)
                                    .format("%Y-%m-%d %H:%M:%S")
                                    .to_string(),
                            );
                            ui.separator();
                            ui.strong(tr(self.lang, "what"));
                            ui.label(&alert.what);
                            ui.add_space(6.0);
                            ui.strong(tr(self.lang, "why"));
                            ui.label(&alert.why);
                            ui.add_space(6.0);
                            ui.strong(tr(self.lang, "how"));
                            ui.label(&alert.how);
                            if !alert.metadata.is_empty() {
                                ui.add_space(6.0);
                                ui.strong(tr(self.lang, "metadata"));
                                for (k, v) in &alert.metadata {
                                    ui.monospace(format!("{k} = {v}"));
                                }
                            }
                        });
                    }
                }
            });

        egui::CentralPanel::default().show_inside(ui, |ui| {
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    egui::Grid::new("alerts_grid")
                        .num_columns(4)
                        .striped(true)
                        .min_col_width(60.0)
                        .show(ui, |ui| {
                            ui.strong(tr(self.lang, "time"));
                            ui.strong(tr(self.lang, "severity"));
                            ui.strong(tr(self.lang, "category"));
                            ui.strong(tr(self.lang, "title"));
                            ui.end_row();
                            for alert in &filtered {
                                ui.label(
                                    alert
                                        .timestamp
                                        .with_timezone(&Local)
                                        .format("%H:%M:%S")
                                        .to_string(),
                                );
                                ui.colored_label(
                                    severity_color(alert.severity),
                                    i18n::severity_label(self.lang, alert.severity),
                                );
                                ui.label(i18n::category_label(self.lang, alert.category));
                                let response = ui.selectable_label(
                                    self.selected == Some(alert.id),
                                    &alert.title,
                                );
                                if response.clicked() {
                                    self.selected = Some(alert.id);
                                }
                                ui.end_row();
                            }
                        });
                });
        });
    }

    fn dashboard_view(&mut self, ui: &mut egui::Ui) {
        ui.heading(format!(
            "{}: {}",
            tr(self.lang, "total_alerts"),
            self.alerts.len()
        ));
        ui.add_space(8.0);

        ui.columns(2, |cols| {
            cols[0].group(|ui| {
                ui.strong(tr(self.lang, "by_severity"));
                for sev in Severity::ALL.iter().rev() {
                    let count = self.alerts.iter().filter(|a| a.severity == *sev).count();
                    ui.colored_label(
                        severity_color(*sev),
                        format!("{}: {}", i18n::severity_label(self.lang, *sev), count),
                    );
                }
            });
            cols[1].group(|ui| {
                ui.strong(tr(self.lang, "by_category"));
                for cat in Category::ALL {
                    let count = self.alerts.iter().filter(|a| a.category == cat).count();
                    ui.label(format!(
                        "{}: {}",
                        i18n::category_label(self.lang, cat),
                        count
                    ));
                }
            });
        });

        ui.add_space(12.0);
        ui.strong(tr(self.lang, "alerts_last_24h"));
        self.hourly_histogram(ui);
    }

    /// Histogramme « alertes par heure » sur 24 h, dessiné à la main.
    fn hourly_histogram(&self, ui: &mut egui::Ui) {
        let now = Utc::now();
        let mut buckets = [0u64; 24];
        for alert in &self.alerts {
            let age = now.signed_duration_since(alert.timestamp);
            if age < ChronoDuration::hours(24) && age >= ChronoDuration::zero() {
                let idx = 23 - (age.num_hours().clamp(0, 23) as usize);
                buckets[idx] += 1;
            }
        }
        let max = buckets.iter().copied().max().unwrap_or(0).max(1);

        let desired = egui::vec2(ui.available_width(), 140.0);
        let (rect, _) = ui.allocate_exact_size(desired, egui::Sense::hover());
        let painter = ui.painter_at(rect);
        painter.rect_filled(rect, 4.0, ui.visuals().extreme_bg_color);

        let bar_w = rect.width() / 24.0;
        for (i, count) in buckets.iter().enumerate() {
            if *count == 0 {
                continue;
            }
            let h = (rect.height() - 20.0) * (*count as f32) / (max as f32);
            let x0 = rect.left() + i as f32 * bar_w + 2.0;
            let bar = egui::Rect::from_min_max(
                egui::pos2(x0, rect.bottom() - 4.0 - h),
                egui::pos2(x0 + bar_w - 4.0, rect.bottom() - 4.0),
            );
            painter.rect_filled(bar, 2.0, egui::Color32::from_rgb(90, 140, 220));
            painter.text(
                egui::pos2(x0 + (bar_w - 4.0) / 2.0, bar.top() - 2.0),
                egui::Align2::CENTER_BOTTOM,
                count.to_string(),
                egui::FontId::proportional(10.0),
                ui.visuals().text_color(),
            );
        }
        // Étiquettes d'heures (une sur quatre).
        for i in (0..24).step_by(4) {
            let hour_dt: DateTime<Local> =
                (now - ChronoDuration::hours((23 - i) as i64)).with_timezone(&Local);
            let x = rect.left() + i as f32 * bar_w + bar_w / 2.0;
            painter.text(
                egui::pos2(x, rect.bottom() + 2.0),
                egui::Align2::CENTER_TOP,
                format!("{:02}h", hour_dt.hour()),
                egui::FontId::proportional(10.0),
                ui.visuals().weak_text_color(),
            );
        }
        ui.add_space(16.0);
    }
}

impl eframe::App for OwlSentryApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.drain_events();

        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            self.top_bar(ui);
        });

        egui::CentralPanel::default().show(ctx, |ui| match self.tab {
            Tab::Alerts => self.alerts_view(ui),
            Tab::Dashboard => self.dashboard_view(ui),
        });

        // Rafraîchissement périodique doux (l'IPC demande aussi des repaints).
        ctx.request_repaint_after(std::time::Duration::from_secs(1));
    }
}
