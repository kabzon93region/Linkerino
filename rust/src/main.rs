#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;

use eframe::egui;
use linkerino::engine;

const ACCENT: egui::Color32 = egui::Color32::from_rgb(47, 111, 237);
const SURFACE: egui::Color32 = egui::Color32::from_rgb(255, 255, 255);
const BACKGROUND: egui::Color32 = egui::Color32::from_rgb(244, 246, 250);
const TEXT: egui::Color32 = egui::Color32::from_rgb(24, 28, 36);
const MUTED: egui::Color32 = egui::Color32::from_rgb(108, 115, 127);
const DANGER: egui::Color32 = egui::Color32::from_rgb(200, 52, 52);

enum Msg {
    Progress(engine::Progress),
    Done(engine::Outcome),
}

struct ChannelSink {
    tx: Sender<Msg>,
    cancel: Arc<AtomicBool>,
}

impl engine::Sink for ChannelSink {
    fn progress(&self, progress: &engine::Progress) {
        let _ = self.tx.send(Msg::Progress(progress.clone()));
    }
    fn cancelled(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }
}

struct App {
    source: String,
    dest: String,
    preview: String,
    preview_error: String,
    status: String,
    phase: engine::Phase,
    percent: f32,
    running: bool,
    cancel: Arc<AtomicBool>,
    rx: Option<Receiver<Msg>>,
    confirm: Option<engine::Plan>,
    result: Option<engine::Outcome>,
    journals: Vec<String>,
    screenshot: Option<PathBuf>,
    screenshot_requested: bool,
    frames: u32,
    scroll_to_result: bool,
}

/// Keeps both the beginning and the end of a long path visible.
fn shorten_path(path: &str, max: usize) -> String {
    let chars: Vec<char> = path.chars().collect();
    if chars.len() <= max || max < 8 {
        return path.to_string();
    }
    let head = max / 2 - 2;
    let tail = max - head - 1;
    let start: String = chars[..head].iter().collect();
    let end: String = chars[chars.len() - tail..].iter().collect();
    format!("{}…{}", start, end)
}

fn save_screenshot(image: &egui::ColorImage, path: &std::path::Path) {
    let width = image.width() as u32;
    let height = image.height() as u32;
    let mut pixels = Vec::with_capacity((width * height * 4) as usize);
    for color in &image.pixels {
        pixels.push(color.r());
        pixels.push(color.g());
        pixels.push(color.b());
        pixels.push(color.a());
    }
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Some(buffer) = image::RgbaImage::from_raw(width, height, pixels) {
        if let Err(error) = buffer.save(path) {
            eprintln!("Не удалось сохранить снимок окна {}: {}", path.display(), error);
        }
    }
}

impl App {
    fn new(
        cc: &eframe::CreationContext<'_>,
        screenshot: Option<PathBuf>,
        demo: bool,
        demo_result: bool,
        demo_journals: bool,
    ) -> Self {
        let mut fonts = egui::FontDefinitions::default();
        if let Ok(bytes) = std::fs::read("C:\\Windows\\Fonts\\segoeui.ttf") {
            fonts.font_data.insert("segoe".to_owned(), egui::FontData::from_owned(bytes));
            if let Some(family) = fonts.families.get_mut(&egui::FontFamily::Proportional) {
                family.insert(0, "segoe".to_owned());
            }
        }
        cc.egui_ctx.set_fonts(fonts);

        let mut visuals = egui::Visuals::light();
        visuals.override_text_color = Some(TEXT);
        visuals.panel_fill = BACKGROUND;
        visuals.window_fill = SURFACE;
        visuals.extreme_bg_color = SURFACE;
        visuals.widgets.inactive.bg_fill = SURFACE;
        visuals.widgets.inactive.weak_bg_fill = SURFACE;
        visuals.widgets.inactive.bg_stroke = egui::Stroke::new(1.0_f32, egui::Color32::from_rgb(214, 219, 228));
        visuals.widgets.hovered.bg_stroke = egui::Stroke::new(1.0_f32, ACCENT);
        visuals.selection.bg_fill = ACCENT.linear_multiply(0.25);
        cc.egui_ctx.set_visuals(visuals);

        let mut style = (*cc.egui_ctx.style()).clone();
        style.spacing.item_spacing = egui::vec2(8.0, 6.0);
        style.spacing.button_padding = egui::vec2(12.0, 7.0);
        style.visuals.widgets.inactive.rounding = egui::Rounding::same(8.0);
        style.visuals.widgets.hovered.rounding = egui::Rounding::same(8.0);
        style.visuals.widgets.active.rounding = egui::Rounding::same(8.0);
        cc.egui_ctx.set_style(style);

        let journals: Vec<String> =
            engine::unfinished_journals().iter().map(|p| p.to_string_lossy().to_string()).collect();
        let mut app = App {
            source: String::new(),
            dest: String::new(),
            preview: String::new(),
            preview_error: String::new(),
            status: "Выберите папку и новое место".to_string(),
            phase: engine::Phase::Validate,
            percent: 0.0,
            running: false,
            cancel: Arc::new(AtomicBool::new(false)),
            rx: None,
            confirm: None,
            result: None,
            journals: if screenshot.is_some() { Vec::new() } else { journals },
            screenshot,
            screenshot_requested: false,
            frames: 0,
            scroll_to_result: false,
        };
        if demo || demo_result {
            app.source = "D:\\Games\\Example".to_string();
            app.dest = "E:\\Backup".to_string();
            app.preview = "E:\\Backup\\Example".to_string();
            app.status = "Выберите папку и новое место".to_string();
        }
        if demo_result {
            app.percent = 1.0;
            let message = "Перенос выполнен, ссылка работает. Старый экземпляр удалён не полностью: не удалось удалить файл D:\\Games\\Example\\nested\\folder-with-a-long-name\\another-folder\\file-with-a-long-name.bin";
            app.status = message.to_string();
            app.result = Some(engine::Outcome {
                ok: true,
                message: message.to_string(),
                leftover: "D:\\Games\\.linkerino-backup-example".to_string(),
                ..Default::default()
            });
            app.scroll_to_result = true;
        }
        if demo_journals {
            app.source = "D:\\Games\\Example".to_string();
            app.dest = "E:\\Backup".to_string();
            app.preview = "E:\\Backup\\Example".to_string();
            app.journals = (1..=140)
                .map(|index| format!("D:\\Backup\\Linkerino\\journal-example-{:08x}.txt", index))
                .collect();
        }
        app
    }

    fn refresh_preview(&mut self) {
        if self.source.trim().is_empty() || self.dest.trim().is_empty() {
            self.preview.clear();
            self.preview_error.clear();
            return;
        }
        let plan = engine::build_plan(&self.source, &self.dest);
        if plan.valid {
            self.preview = plan.dest_final.clone();
            self.preview_error.clear();
        } else {
            self.preview.clear();
            self.preview_error = plan.error.clone();
        }
    }

    fn browse(title: &str) -> Option<String> {
        rfd::FileDialog::new().set_title(title).pick_folder().map(|p: PathBuf| p.to_string_lossy().to_string())
    }

    fn start(&mut self, plan: engine::Plan) {
        let (tx, rx) = channel();
        let sink = ChannelSink { tx: tx.clone(), cancel: self.cancel.clone() };
        self.cancel.store(false, Ordering::Relaxed);
        self.running = true;
        self.percent = 0.0;
        self.phase = engine::Phase::Validate;
        self.status = "Начинаю перенос…".to_string();
        self.result = None;
        self.rx = Some(rx);
        let plan_for_thread = plan.clone();
        std::thread::spawn(move || {
            let outcome = engine::execute(&plan_for_thread, Some(&sink), &engine::Faults::default());
            let _ = tx.send(Msg::Done(outcome));
        });
    }

    fn pump(&mut self) {
        let mut done = None;
        if let Some(rx) = &self.rx {
            while let Ok(message) = rx.try_recv() {
                match message {
                    Msg::Progress(progress) => {
                        self.phase = progress.phase;
                        let percent = if progress.bytes_total > 0 {
                            progress.bytes_done as f32 / progress.bytes_total as f32
                        } else if progress.files_total > 0 {
                            progress.files_done as f32 / progress.files_total as f32
                        } else {
                            0.0
                        };
                        self.percent = percent.clamp(0.0, 1.0);
                        self.status = if progress.item.is_empty() {
                            progress.phase.text().to_string()
                        } else {
                            format!("{}: {}", progress.phase.text(), progress.item)
                        };
                    }
                    Msg::Done(outcome) => done = Some(outcome),
                }
            }
        }
        if let Some(outcome) = done {
            self.running = false;
            self.rx = None;
            if outcome.ok {
                self.percent = 1.0;
            }
            self.status = outcome.message.clone();
            self.result = Some(outcome);
            self.scroll_to_result = true;
        }
    }

    fn card(ui: &mut egui::Ui, title: &str, value: &mut String, browse: bool) -> bool {
        let mut changed = false;
        egui::Frame::none()
            .fill(SURFACE)
            .rounding(egui::Rounding::same(10.0))
            .inner_margin(egui::Margin::symmetric(12.0, 8.0))
            .stroke(egui::Stroke::new(1.0_f32, egui::Color32::from_rgb(228, 232, 238)))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.label(egui::RichText::new(title).size(10.5).color(MUTED));
                ui.add_space(2.0);
                ui.horizontal(|ui| {
                    let button_width = 74.0;
                    let spacing = ui.spacing().item_spacing.x;
                    let edit_width = (ui.available_width() - if browse { button_width + spacing } else { 0.0 }).max(60.0);
                    let response = ui.add(
                        egui::TextEdit::singleline(value)
                            .desired_width(edit_width)
                            .hint_text("путь к папке")
                            .frame(false),
                    );
                    changed = response.changed();
                    if browse && ui.button("Обзор…").clicked() {
                        if let Some(picked) = App::browse("Выберите папку") {
                            *value = picked;
                            changed = true;
                        }
                    }
                });
            });
        changed
    }

    fn footer(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            let can_start = !self.running && !self.preview.is_empty();
            let start = ui.add_enabled(
                can_start,
                egui::Button::new(egui::RichText::new("Перенести").color(egui::Color32::WHITE).strong())
                    .fill(if can_start { ACCENT } else { egui::Color32::from_rgb(170, 178, 190) })
                    .rounding(egui::Rounding::same(8.0))
                    .min_size(egui::vec2(150.0, 34.0)),
            );
            if start.clicked() {
                let plan = engine::build_plan(&self.source, &self.dest);
                if plan.valid {
                    self.confirm = Some(plan);
                } else {
                    self.preview_error = plan.error.clone();
                }
            }
            if self.running {
                let cancel_enabled = self.phase != engine::Phase::Publish
                    && self.phase != engine::Phase::Link
                    && self.phase != engine::Phase::Cleanup;
                if ui
                    .add_enabled(cancel_enabled, egui::Button::new("Отмена").min_size(egui::vec2(100.0, 34.0)))
                    .clicked()
                {
                    self.cancel.store(true, Ordering::Relaxed);
                    self.status = "Останавливаюсь после безопасного шага…".to_string();
                }
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if let Some(result) = &self.result {
                    if !result.leftover.is_empty() {
                        let path = result.leftover.clone();
                        if ui.button("Показать остаток").clicked() {
                            // The leftover can be a file (partial cleanup) or a folder: /select works for both.
                            let _ = std::process::Command::new("explorer.exe")
                                .arg(format!("/select,\"{}\"", path))
                                .spawn();
                        }
                    }
                }
            });
        });
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.pump();
        if self.running {
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }
        if self.screenshot.is_some() {
            self.frames += 1;
            if self.frames == 3 && !self.screenshot_requested {
                ctx.send_viewport_cmd(egui::ViewportCommand::Screenshot);
                self.screenshot_requested = true;
            }
            let image = ctx.input(|input| {
                input.events.iter().find_map(|event| match event {
                    egui::Event::Screenshot { image, .. } => Some(image.clone()),
                    _ => None,
                })
            });
            if let Some(image) = image {
                if let Some(path) = self.screenshot.clone() {
                    save_screenshot(&image, &path);
                }
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            } else {
                ctx.request_repaint();
            }
        }

        egui::CentralPanel::default().frame(egui::Frame::none().fill(BACKGROUND)).show(ctx, |ui| {
            ui.add_space(14.0);
            ui.horizontal(|ui| {
                ui.add_space(16.0);
                ui.vertical(|ui| {
                    ui.label(egui::RichText::new("Linkerino").size(22.0).strong().color(TEXT));
                    ui.label(
                        egui::RichText::new("Перенести папку и оставить на старом месте ссылку")
                            .size(12.0)
                            .color(MUTED),
                    );
                });
            });
            ui.add_space(12.0);

            egui::Frame::none().inner_margin(egui::Margin::symmetric(16.0, 0.0)).show(ui, |ui| {
                let has_leftover = self.result.as_ref().map(|r| !r.leftover.is_empty()).unwrap_or(false);
                let footer_height = 52.0;
                let leftover_height = if has_leftover { 22.0 } else { 0.0 };
                let scroll_height = (ui.available_height() - footer_height - leftover_height).max(150.0);
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .max_height(scroll_height)
                    .show(ui, |ui| {
                        let mut changed = App::card(ui, "ОТКУДА", &mut self.source, true);
                        ui.add_space(6.0);
                        changed |= App::card(ui, "КУДА", &mut self.dest, true);
                        if changed {
                            self.refresh_preview();
                        }

                        ui.add_space(10.0);
                        if !self.preview.is_empty() {
                            egui::Frame::none()
                                .fill(egui::Color32::from_rgb(233, 239, 253))
                                .rounding(egui::Rounding::same(8.0))
                                .inner_margin(egui::Margin::symmetric(10.0, 6.0))
                                .show(ui, |ui| {
                                    ui.set_width(ui.available_width());
                                    ui.horizontal(|ui| {
                                        ui.label(egui::RichText::new("Станет").size(11.0).color(MUTED));
                                        ui.add(
                                            egui::Label::new(
                                                egui::RichText::new(&self.preview)
                                                    .monospace()
                                                    .size(12.0)
                                                    .color(ACCENT),
                                            )
                                            .truncate(),
                                        );
                                    });
                                });
                        } else if !self.preview_error.is_empty() {
                            ui.add(
                                egui::Label::new(egui::RichText::new(&self.preview_error).size(11.5).color(DANGER))
                                    .wrap(),
                            );
                        } else {
                            ui.label(egui::RichText::new("Выберите обе папки").size(11.5).color(MUTED));
                        }

                        ui.add_space(8.0);
                        ui.horizontal(|ui| {
                            let percent_width = 40.0;
                            ui.visuals_mut().extreme_bg_color = egui::Color32::from_rgb(226, 231, 239);
                            let bar = egui::ProgressBar::new(self.percent)
                                .desired_width((ui.available_width() - percent_width).max(80.0))
                                .desired_height(6.0)
                                .fill(ACCENT)
                                .rounding(egui::Rounding::same(3.0));
                            ui.add(bar);
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                let percent = (self.percent * 100.0).round() as i32;
                                ui.label(egui::RichText::new(format!("{}%", percent)).size(11.5).color(MUTED));
                            });
                        });
                        ui.add_space(4.0);
                        if self.result.is_none() {
                            ui.add(
                                egui::Label::new(egui::RichText::new(&self.status).size(12.0).color(MUTED)).wrap(),
                            );
                        }

                        if let Some(result) = &self.result {
                            ui.add_space(6.0);
                            let color = if result.ok { MUTED } else { DANGER };
                            ui.add(
                                egui::Label::new(egui::RichText::new(&result.message).size(11.5).color(color))
                                    .wrap(),
                            );
                            if !result.notes.is_empty() {
                                ui.add(
                                    egui::Label::new(egui::RichText::new(&result.notes).size(11.5).color(color))
                                        .wrap(),
                                );
                            }
                            if !result.detail.is_empty() && !result.ok {
                                ui.add(
                                    egui::Label::new(egui::RichText::new(&result.detail).size(11.0).color(MUTED))
                                        .wrap(),
                                );
                            }
                            if self.scroll_to_result {
                                ui.scroll_to_rect(ui.min_rect(), Some(egui::Align::BOTTOM));
                                self.scroll_to_result = false;
                            }
                        }
                        ui.add_space(4.0);
                    });
                if has_leftover {
                    let path = self.result.as_ref().map(|r| r.leftover.clone()).unwrap_or_default();
                    ui.add(
                        egui::Label::new(
                            egui::RichText::new(format!("Остаток сохранён: {}", shorten_path(&path, 64)))
                                .size(10.5)
                                .color(MUTED),
                        )
                        .truncate(),
                    );
                }
                self.footer(ui);
            });
        });

        if let Some(plan) = self.confirm.clone() {
            let mut close = false;
            let mut accept = false;
            egui::Window::new("Подтверждение")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
                .show(ctx, |ui| {
                    ui.label("Перенести папку?");
                    ui.add_space(6.0);
                    ui.label(egui::RichText::new("Откуда").size(10.5).color(MUTED));
                    ui.add(egui::Label::new(egui::RichText::new(&plan.source).monospace().size(12.0)).truncate());
                    ui.add_space(4.0);
                    ui.label(egui::RichText::new("Куда").size(10.5).color(MUTED));
                    ui.add(
                        egui::Label::new(egui::RichText::new(&plan.dest_final).monospace().size(12.0)).truncate(),
                    );
                    ui.add_space(6.0);
                    ui.label(
                        egui::RichText::new("Сначала копия будет сверена, и только потом старый путь станет ссылкой.")
                            .size(11.5)
                            .color(MUTED),
                    );
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui
                            .add(egui::Button::new(egui::RichText::new("Перенести").color(egui::Color32::WHITE))
                                .fill(ACCENT)
                                .min_size(egui::vec2(120.0, 30.0)))
                            .clicked()
                        {
                            accept = true;
                        }
                        if ui.button("Отмена").clicked() {
                            close = true;
                        }
                    });
                });
            if accept {
                self.confirm = None;
                self.start(plan);
            } else if close {
                self.confirm = None;
            }
        }

        if !self.journals.is_empty() {
            let mut close = ctx.input(|input| input.key_pressed(egui::Key::Escape));
            let count = self.journals.len();
            let title = if count == 1 {
                "Незавершённый перенос".to_string()
            } else {
                format!("Незавершённые переносы: {}", count)
            };
            egui::Window::new(title)
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
                .show(ctx, |ui| {
                    ui.label("Проверьте эти папки вручную — перенос мог остановиться на середине:");
                    ui.add_space(4.0);
                    egui::ScrollArea::vertical().max_height(150.0).auto_shrink([false, false]).show(ui, |ui| {
                        for path in self.journals.iter().take(100) {
                            ui.add(
                                egui::Label::new(
                                    egui::RichText::new(shorten_path(path, 74)).monospace().size(10.5),
                                )
                                .truncate(),
                            );
                        }
                    });
                    if count > 100 {
                        ui.add(
                            egui::Label::new(
                                egui::RichText::new(format!("Показаны первые 100, всего {}", count))
                                    .size(10.5)
                                    .color(MUTED),
                            )
                            .truncate(),
                        );
                    }
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui.button("Понятно").clicked() {
                            close = true;
                        }
                        if ui.button("Открыть папку журналов").clicked() {
                            let folder = self
                                .journals
                                .first()
                                .and_then(|path| std::path::Path::new(path).parent().map(|p| p.to_path_buf()));
                            if let Some(folder) = folder {
                                let _ = std::process::Command::new("explorer.exe").arg(folder).spawn();
                            }
                        }
                    });
                });
            if close {
                self.journals.clear();
            }
        }
    }
}

fn attach_console() {
    // The release binary is a GUI subsystem app; a console is attached only for the CLI mode.
    const ATTACH_PARENT_PROCESS: u32 = 0xFFFF_FFFF;
    unsafe {
        windows_sys::Win32::System::Console::AttachConsole(ATTACH_PARENT_PROCESS);
    }
}

fn run_cli(args: &[String]) -> i32 {
    if args.len() < 3 {
        eprintln!("usage: Linkerino --transfer <source-folder> <destination-parent>");
        return 2;
    }
    let plan = engine::build_plan(&args[1], &args[2]);
    if !plan.valid {
        eprintln!("{}", plan.error);
        return 1;
    }
    let outcome = engine::execute(&plan, None, &engine::Faults::default());
    let code = if outcome.ok {
        println!("{}", outcome.message);
        if !outcome.leftover.is_empty() {
            println!("Сохранено: {}", outcome.leftover);
        }
        0
    } else {
        eprintln!("{}", outcome.message);
        if !outcome.detail.is_empty() {
            eprintln!("{}", outcome.detail);
        }
        1
    };
    if !outcome.notes.is_empty() {
        println!("{}", outcome.notes.trim_end());
    }
    code
}

fn window_icon() -> Option<egui::IconData> {
    let image = image::load_from_memory(include_bytes!("../assets/linkerino-256.png")).ok()?.to_rgba8();
    Some(egui::IconData { rgba: image.as_raw().clone(), width: image.width(), height: image.height() })
}

fn main() -> eframe::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut screenshot: Option<PathBuf> = None;
    let mut demo = false;
    let mut demo_result = false;
    let mut demo_journals = false;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--transfer" | "/transfer" => {
                attach_console();
                let code = run_cli(&args[index..]);
                std::process::exit(code);
            }
            "--help" | "/?" | "-h" => {
                attach_console();
                println!("Linkerino: переносит папку и оставляет на её месте символьную ссылку.");
                println!("  Linkerino.exe                             — графический интерфейс");
                println!("  Linkerino.exe --transfer <папка> <куда>   — перенос без интерфейса");
                println!("  Linkerino.exe --screenshot <файл> [--demo] — сохранить снимок окна и выйти");
                std::process::exit(0);
            }
            "--screenshot" => {
                if index + 1 < args.len() {
                    screenshot = Some(PathBuf::from(&args[index + 1]));
                    index += 1;
                }
            }
            "--demo" => demo = true,
            "--demo-result" => demo_result = true,
            "--demo-journals" => demo_journals = true,
            _ => {}
        }
        index += 1;
    }
    let mut viewport = egui::ViewportBuilder::default()
        .with_inner_size([560.0, 412.0])
        .with_min_inner_size([560.0, 412.0])
        .with_resizable(false)
        .with_title("Linkerino");
    if let Some(icon) = window_icon() {
        viewport = viewport.with_icon(icon);
    }
    let options = eframe::NativeOptions { viewport, ..Default::default() };
    eframe::run_native(
        "Linkerino",
        options,
        Box::new(move |cc| Ok(Box::new(App::new(cc, screenshot, demo, demo_result, demo_journals)))),
    )
}
