#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;

use eframe::egui;
use linkerino::engine;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Theme {
    Light,
    Dark,
}

impl Theme {
    fn key(self) -> &'static str {
        match self {
            Theme::Light => "light",
            Theme::Dark => "dark",
        }
    }
}

fn theme_from_key(value: &str) -> Theme {
    if value.trim().eq_ignore_ascii_case("dark") {
        Theme::Dark
    } else {
        Theme::Light
    }
}

fn parse_theme(text: &str) -> Theme {
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(value) = line.strip_prefix("theme=") {
            return theme_from_key(value);
        }
        if !line.contains('=') {
            return theme_from_key(line);
        }
    }
    Theme::Light
}

fn settings_path() -> Option<PathBuf> {
    let base = std::env::var("LOCALAPPDATA").ok()?;
    Some(std::path::Path::new(&base).join("Linkerino").join("settings.txt"))
}

fn load_theme() -> Theme {
    let Some(path) = settings_path() else { return Theme::Light };
    match std::fs::read_to_string(path) {
        Ok(text) => parse_theme(&text),
        Err(_) => Theme::Light,
    }
}

fn save_theme(theme: Theme) {
    let Some(path) = settings_path() else { return };
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(path, format!("theme={}\n", theme.key()));
}

struct Palette {
    accent: egui::Color32,
    surface: egui::Color32,
    background: egui::Color32,
    text: egui::Color32,
    muted: egui::Color32,
    danger: egui::Color32,
    edge: egui::Color32,
    preview: egui::Color32,
    track: egui::Color32,
    disabled: egui::Color32,
    on_accent: egui::Color32,
    on_disabled: egui::Color32,
}

impl Palette {
    fn light() -> Self {
        Palette {
            accent: egui::Color32::from_rgb(47, 111, 237),
            surface: egui::Color32::from_rgb(255, 255, 255),
            background: egui::Color32::from_rgb(244, 246, 250),
            text: egui::Color32::from_rgb(24, 28, 36),
            muted: egui::Color32::from_rgb(108, 115, 127),
            danger: egui::Color32::from_rgb(200, 52, 52),
            edge: egui::Color32::from_rgb(228, 232, 238),
            preview: egui::Color32::from_rgb(233, 239, 253),
            track: egui::Color32::from_rgb(226, 231, 239),
            disabled: egui::Color32::from_rgb(227, 231, 237),
            on_accent: egui::Color32::WHITE,
            on_disabled: egui::Color32::from_rgb(108, 115, 127),
        }
    }

    fn dark() -> Self {
        Palette {
            accent: egui::Color32::from_rgb(107, 156, 255),
            surface: egui::Color32::from_rgb(29, 35, 44),
            background: egui::Color32::from_rgb(18, 22, 28),
            text: egui::Color32::from_rgb(232, 237, 244),
            muted: egui::Color32::from_rgb(150, 160, 175),
            danger: egui::Color32::from_rgb(240, 115, 110),
            edge: egui::Color32::from_rgb(48, 57, 70),
            preview: egui::Color32::from_rgb(30, 44, 72),
            track: egui::Color32::from_rgb(45, 54, 67),
            disabled: egui::Color32::from_rgb(51, 60, 72),
            on_accent: egui::Color32::from_rgb(15, 23, 37),
            on_disabled: egui::Color32::from_rgb(168, 178, 192),
        }
    }

    fn of(theme: Theme) -> Self {
        match theme {
            Theme::Light => Palette::light(),
            Theme::Dark => Palette::dark(),
        }
    }
}

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
    preview_gen: u64,
    preview_rx: Option<std::sync::mpsc::Receiver<(u64, String, String)>>,
    journals_rx: Option<std::sync::mpsc::Receiver<Vec<engine::JournalSummary>>>,
    confirm_rx: Option<std::sync::mpsc::Receiver<engine::Plan>>,
    journals_dismissed: bool,
    status: String,
    phase: engine::Phase,
    percent: f32,
    running: bool,
    cancel: Arc<AtomicBool>,
    rx: Option<Receiver<Msg>>,
    confirm: Option<engine::Plan>,
    result: Option<engine::Outcome>,
    journals: Vec<engine::JournalSummary>,
    screenshot: Option<PathBuf>,
    screenshot_requested: bool,
    frames: u32,
    scroll_to_result: bool,
    /// Set when the window was asked to close during a transfer: it closes once the engine stops.
    close_when_idle: bool,
    theme: Theme,
    palette: Palette,
    theme_locked: bool,
}

fn draw_sun(painter: &egui::Painter, center: egui::Pos2, color: egui::Color32) {
    painter.circle_stroke(center, 2.6, egui::Stroke::new(1.2_f32, color));
    for index in 0..8 {
        let angle = std::f32::consts::TAU * index as f32 / 8.0;
        let direction = egui::vec2(angle.cos(), angle.sin());
        painter.line_segment(
            [center + direction * 4.4, center + direction * 6.6],
            egui::Stroke::new(1.2_f32, color),
        );
    }
}

fn draw_moon(painter: &egui::Painter, center: egui::Pos2, color: egui::Color32, background: egui::Color32) {
    painter.circle_filled(center, 5.2, color);
    painter.circle_filled(center + egui::vec2(2.6, -1.4), 4.6, background);
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
        theme_override: Option<Theme>,
    ) -> Self {
        let mut fonts = egui::FontDefinitions::default();
        if let Ok(bytes) = std::fs::read("C:\\Windows\\Fonts\\segoeui.ttf") {
            fonts.font_data.insert("segoe".to_owned(), egui::FontData::from_owned(bytes));
            if let Some(family) = fonts.families.get_mut(&egui::FontFamily::Proportional) {
                family.insert(0, "segoe".to_owned());
            }
        }
        cc.egui_ctx.set_fonts(fonts);

        let mut style = (*cc.egui_ctx.style()).clone();
        style.spacing.item_spacing = egui::vec2(8.0, 4.0);
        style.spacing.button_padding = egui::vec2(9.0, 3.0);
        style.visuals.widgets.inactive.rounding = egui::Rounding::same(8.0);
        style.visuals.widgets.hovered.rounding = egui::Rounding::same(8.0);
        style.visuals.widgets.active.rounding = egui::Rounding::same(8.0);
        cc.egui_ctx.set_style(style);

        let theme = theme_override.unwrap_or_else(load_theme);
        let palette = Palette::of(theme);

        // Reading journals touches the disk, so it starts in the background and the dialog appears
        // when the answer arrives.
        let journals_rx = if screenshot.is_some() {
            None
        } else {
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let _ = tx.send(engine::unfinished_journals());
            });
            Some(rx)
        };
        let mut app = App {
            source: String::new(),
            dest: String::new(),
            preview: String::new(),
            preview_error: String::new(),
            preview_gen: 0,
            preview_rx: None,
            journals_rx,
            confirm_rx: None,
            journals_dismissed: false,
            status: "Выберите папку и новое место".to_string(),
            phase: engine::Phase::Validate,
            percent: 0.0,
            running: false,
            cancel: Arc::new(AtomicBool::new(false)),
            rx: None,
            confirm: None,
            result: None,
            journals: Vec::new(),
            screenshot,
            screenshot_requested: false,
            frames: 0,
            scroll_to_result: false,
            close_when_idle: false,
            theme,
            palette,
            theme_locked: theme_override.is_some(),
        };
        app.apply_theme(&cc.egui_ctx);
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
                .map(|index| engine::JournalSummary {
                    path: std::path::PathBuf::from(format!(
                        "D:\\Backup\\Linkerino\\journal-example-{:08x}.txt",
                        index
                    )),
                    state: "linked".to_string(),
                    source: format!("D:\\Games\\Example{}", index),
                    dest: format!("E:\\Backup\\Example{}", index),
                    backup: format!("D:\\Games\\.linkerino-backup-{:08x}", index),
                })
                .collect();
        }
        app
    }

    fn apply_theme(&self, ctx: &egui::Context) {
        let palette = &self.palette;
        let mut visuals = match self.theme {
            Theme::Light => egui::Visuals::light(),
            Theme::Dark => egui::Visuals::dark(),
        };
        visuals.override_text_color = Some(palette.text);
        visuals.panel_fill = palette.background;
        visuals.window_fill = palette.surface;
        visuals.extreme_bg_color = palette.surface;
        visuals.window_stroke = egui::Stroke::new(1.0_f32, palette.edge);
        visuals.widgets.inactive.bg_fill = palette.surface;
        visuals.widgets.inactive.weak_bg_fill = palette.surface;
        visuals.widgets.inactive.bg_stroke = egui::Stroke::new(1.0_f32, palette.edge);
        visuals.widgets.inactive.fg_stroke = egui::Stroke::new(1.0_f32, palette.text);
        visuals.widgets.hovered.bg_stroke = egui::Stroke::new(1.0_f32, palette.accent);
        visuals.widgets.hovered.fg_stroke = egui::Stroke::new(1.0_f32, palette.text);
        visuals.widgets.active.bg_stroke = egui::Stroke::new(1.0_f32, palette.accent);
        visuals.widgets.active.fg_stroke = egui::Stroke::new(1.0_f32, palette.text);
        let open = &mut visuals.widgets.open;
        open.bg_fill = palette.surface;
        open.weak_bg_fill = palette.surface;
        open.bg_stroke = egui::Stroke::new(1.0_f32, palette.edge);
        open.fg_stroke = egui::Stroke::new(1.0_f32, palette.text);
        visuals.selection.bg_fill = palette.accent.linear_multiply(0.3);
        visuals.selection.stroke = egui::Stroke::new(1.0_f32, palette.text);
        ctx.set_visuals(visuals);
    }

    fn set_theme(&mut self, theme: Theme, ctx: &egui::Context) {
        if self.theme == theme {
            return;
        }
        self.theme = theme;
        self.palette = Palette::of(theme);
        self.apply_theme(ctx);
        if !self.theme_locked {
            save_theme(theme);
        }
    }

    fn theme_switch(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let palette = &self.palette;
        let dark = self.theme == Theme::Dark;
        let (rect, response) = ui.allocate_exact_size(egui::vec2(52.0, 24.0), egui::Sense::click());
        let rounding = egui::Rounding::same(12.0);
        let painter = ui.painter();
        painter.rect_filled(rect, rounding, palette.track);
        painter.rect_stroke(rect, rounding, egui::Stroke::new(1.0_f32, palette.edge));

        let sun = egui::pos2(rect.left() + 13.0, rect.center().y);
        let moon = egui::pos2(rect.right() - 13.0, rect.center().y);
        let knob = if dark { moon } else { sun };
        painter.circle_filled(knob, 9.0, palette.text);

        if dark {
            draw_sun(painter, sun, palette.muted);
            draw_moon(painter, moon, palette.surface, palette.text);
        } else {
            draw_moon(painter, moon, palette.muted, palette.track);
            draw_sun(painter, sun, palette.surface);
        }

        let hint = if dark { "Тёмная тема — нажмите, чтобы включить светлую" } else { "Светлая тема — нажмите, чтобы включить тёмную" };
        if response.on_hover_text(hint).clicked() {
            self.set_theme(if dark { Theme::Light } else { Theme::Dark }, ctx);
        }
    }

    fn refresh_preview(&mut self) {
        if self.source.trim().is_empty() || self.dest.trim().is_empty() {
            self.preview.clear();
            self.preview_error.clear();
            self.preview_rx = None;
            self.confirm = None;
            self.confirm_rx = None;
            return;
        }
        // The check touches the disk (a network path can take seconds), so it runs in the
        // background and only the answer for the latest request is shown.
        // A pending confirmation belongs to the old paths and must not be used any more.
        self.confirm = None;
        self.confirm_rx = None;
        self.preview_gen += 1;
        let generation = self.preview_gen;
        let source = self.source.clone();
        let dest = self.dest.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let plan = engine::build_plan(&source, &dest);
            let answer = if plan.valid {
                (generation, plan.dest_final.clone(), String::new())
            } else {
                (generation, String::new(), plan.error.clone())
            };
            let _ = tx.send(answer);
        });
        self.preview_rx = Some(rx);
    }

    fn pump_preview(&mut self) {
        let mut answer = None;
        if let Some(rx) = &self.preview_rx {
            if let Ok(value) = rx.try_recv() {
                answer = Some(value);
            }
        }
        if let Some((generation, dest_final, error)) = answer {
            self.preview_rx = None;
            if generation != self.preview_gen {
                return;
            }
            if error.is_empty() {
                self.preview = dest_final;
                self.preview_error.clear();
            } else {
                self.preview.clear();
                self.preview_error = error;
            }
        }
    }

    fn pump_journals(&mut self) {
        let mut loaded = None;
        if let Some(rx) = &self.journals_rx {
            if let Ok(value) = rx.try_recv() {
                loaded = Some(value);
            }
        }
        if let Some(loaded) = loaded {
            self.journals_rx = None;
            // A list the person already dismissed must not come back.
            if !self.journals_dismissed {
                self.journals = loaded;
            }
        }
    }

    /// `None` — the dialog was cancelled; `Some(Err(..))` — the chosen name cannot be read as
    /// Unicode, so it must not be silently replaced by a similar-looking path.
    fn browse(title: &str) -> Option<Result<String, String>> {
        rfd::FileDialog::new().set_title(title).pick_folder().map(|picked: PathBuf| match picked.to_str() {
            Some(value) => Ok(value.to_string()),
            None => Err("В имени выбранной папки есть символы, которые нельзя прочитать как Unicode.".to_string()),
        })
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
        // The confirmation of a transfer is computed off the UI thread as well.
        let mut plan = None;
        if let Some(rx) = &self.confirm_rx {
            if let Ok(value) = rx.try_recv() {
                plan = Some(value);
            }
        }
        if let Some(plan) = plan {
            self.confirm_rx = None;
            if plan.valid {
                self.confirm = Some(plan);
            } else {
                self.preview_error = plan.error.clone();
                self.status = plan.error.clone();
            }
        }
    }

    fn card(ui: &mut egui::Ui, palette: &Palette, title: &str, value: &mut String, browse: bool, message: &mut Option<String>) -> bool {
        let mut changed = false;
        egui::Frame::none()
            .fill(palette.surface)
            .rounding(egui::Rounding::same(8.0))
            .inner_margin(egui::Margin::symmetric(10.0, 4.0))
            .stroke(egui::Stroke::new(1.0_f32, palette.edge))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    ui.add_sized(
                        egui::vec2(52.0, 20.0),
                        egui::Label::new(egui::RichText::new(title).size(9.5).color(palette.muted)),
                    );
                    let button_width = 66.0;
                    let spacing = ui.spacing().item_spacing.x;
                    let edit_width = (ui.available_width() - if browse { button_width + spacing } else { 0.0 }).max(60.0);
                    let response = ui.add(
                        egui::TextEdit::singleline(value)
                            .desired_width(edit_width)
                            .hint_text("путь к папке")
                            .frame(false),
                    );
                    changed = response.changed();
                    if browse {
                        let button = ui.add_sized(
                            egui::vec2(button_width, 20.0),
                            egui::Button::new(egui::RichText::new("Обзор…").size(11.0)),
                        );
                        if button.clicked() {
                            match App::browse("Выберите папку") {
                                Some(Ok(picked)) => {
                                    *value = picked;
                                    changed = true;
                                }
                                Some(Err(error)) => {
                                    *message = Some(error);
                                }
                                None => {}
                            }
                        }
                    }
                });
            });
        changed
    }

    fn footer(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            let can_start = !self.running && self.confirm_rx.is_none() && !self.preview.is_empty();
            let start_text = if can_start { self.palette.on_accent } else { self.palette.on_disabled };
            let start = ui.add_enabled(
                can_start,
                egui::Button::new(egui::RichText::new("Перенести").color(start_text).strong().size(12.5))
                    .fill(if can_start { self.palette.accent } else { self.palette.disabled })
                    .rounding(egui::Rounding::same(7.0))
                    .min_size(egui::vec2(132.0, 28.0)),
            );
            if start.clicked() {
                // The final check touches the disk: run it in the background so a slow or
                // unreachable path cannot freeze the window.
                let source = self.source.clone();
                let dest = self.dest.clone();
                let (tx, rx) = std::sync::mpsc::channel();
                std::thread::spawn(move || {
                    let _ = tx.send(engine::build_plan(&source, &dest));
                });
                self.confirm_rx = Some(rx);
                self.status = "Проверяю пути…".to_string();
            }
            if self.running {
                let cancel_enabled = self.phase != engine::Phase::Publish
                    && self.phase != engine::Phase::Link
                    && self.phase != engine::Phase::Cleanup;
                if ui
                    .add_enabled(cancel_enabled, egui::Button::new("Отмена").min_size(egui::vec2(84.0, 28.0)))
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
        self.pump_preview();
        self.pump_journals();
        // While a background answer is pending, wake up regularly: there is no event for it.
        if self.preview_rx.is_some() || self.journals_rx.is_some() || self.confirm_rx.is_some() {
            ctx.request_repaint_after(std::time::Duration::from_millis(60));
        }
        if self.running {
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }
        // A running transfer must not be killed by closing the window: the click asks it to stop
        // and the window closes as soon as the engine is back at a safe point.
        if ctx.input(|input| input.viewport().close_requested()) && self.running {
            self.cancel.store(true, Ordering::Relaxed);
            self.status = "Останавливаю перенос… Окно закроется, когда это станет безопасно.".to_string();
            self.close_when_idle = true;
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
        }
        if self.close_when_idle && !self.running {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
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

        egui::CentralPanel::default().frame(egui::Frame::none().fill(self.palette.background)).show(ctx, |ui| {
            ui.add_space(9.0);
            ui.horizontal(|ui| {
                ui.add_space(14.0);
                ui.label(egui::RichText::new("Linkerino").size(20.0).strong().color(self.palette.text));
                ui.add_space(6.0);
                self.theme_switch(ui, ctx);
                ui.add_space(10.0);
                ui.label(
                    egui::RichText::new("Перенести папку и оставить на старом месте ссылку")
                        .size(11.0)
                        .color(self.palette.muted),
                );
            });
            ui.add_space(8.0);

            egui::Frame::none().inner_margin(egui::Margin::symmetric(14.0, 0.0)).show(ui, |ui| {
                let has_leftover = self.result.as_ref().map(|r| !r.leftover.is_empty()).unwrap_or(false);
                let footer_height = 40.0;
                let leftover_height = if has_leftover { 18.0 } else { 0.0 };
                let scroll_height = (ui.available_height() - footer_height - leftover_height).max(120.0);
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .max_height(scroll_height)
                    .show(ui, |ui| {
                        let mut picked_error = None;
                        let mut changed = App::card(ui, &self.palette, "ОТКУДА", &mut self.source, true, &mut picked_error);
                        ui.add_space(4.0);
                        changed |= App::card(ui, &self.palette, "КУДА", &mut self.dest, true, &mut picked_error);
                        if let Some(error) = picked_error {
                            self.preview_error = error;
                            self.preview.clear();
                        }
                        if changed {
                            self.refresh_preview();
                        }

                        ui.add_space(7.0);
                        if !self.preview.is_empty() {
                            egui::Frame::none()
                                .fill(self.palette.preview)
                                .rounding(egui::Rounding::same(7.0))
                                .inner_margin(egui::Margin::symmetric(9.0, 4.0))
                                .show(ui, |ui| {
                                    ui.set_width(ui.available_width());
                                    ui.horizontal(|ui| {
                                        ui.label(egui::RichText::new("Станет").size(10.5).color(self.palette.muted));
                                        ui.add(
                                            egui::Label::new(
                                                egui::RichText::new(&self.preview)
                                                    .monospace()
                                                    .size(11.5)
                                                    .color(self.palette.accent),
                                            )
                                            .truncate(),
                                        );
                                    });
                                });
                        } else if !self.preview_error.is_empty() {
                            ui.add(
                                egui::Label::new(egui::RichText::new(&self.preview_error).size(11.0).color(self.palette.danger))
                                    .wrap(),
                            );
                        } else {
                            ui.label(egui::RichText::new("Выберите обе папки").size(11.0).color(self.palette.muted));
                        }

                        ui.add_space(6.0);
                        ui.horizontal(|ui| {
                            let percent_width = 54.0;
                            ui.visuals_mut().extreme_bg_color = self.palette.track;
                            let bar = egui::ProgressBar::new(self.percent)
                                .desired_width((ui.available_width() - percent_width).max(80.0))
                                .desired_height(5.0)
                                .fill(self.palette.accent)
                                .rounding(egui::Rounding::same(3.0));
                            ui.add(bar);
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                ui.add_space(12.0);
                                let percent = (self.percent * 100.0).round() as i32;
                                ui.label(egui::RichText::new(format!("{}%", percent)).size(10.5).color(self.palette.muted));
                            });
                        });
                        ui.add_space(4.0);
                        if self.result.is_none() {
                            ui.add(
                                egui::Label::new(egui::RichText::new(&self.status).size(11.5).color(self.palette.muted)).wrap(),
                            );
                        }

                        if let Some(result) = &self.result {
                            ui.add_space(6.0);
                            let color = if result.ok { self.palette.muted } else { self.palette.danger };
                            ui.add(
                                egui::Label::new(egui::RichText::new(&result.message).size(11.0).color(color))
                                    .wrap(),
                            );
                            if !result.notes.is_empty() {
                                ui.add(
                                    egui::Label::new(egui::RichText::new(&result.notes).size(10.5).color(color))
                                        .wrap(),
                                );
                            }
                            if !result.detail.is_empty() && !result.ok {
                                ui.add(
                                    egui::Label::new(egui::RichText::new(&result.detail).size(10.5).color(self.palette.muted))
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
                            egui::RichText::new(format!("Остаток сохранён: {}", shorten_path(&path, 70)))
                                .size(10.5)
                                .color(self.palette.muted),
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
                    ui.label(egui::RichText::new("Откуда").size(10.5).color(self.palette.muted));
                    ui.add(egui::Label::new(egui::RichText::new(&plan.source).monospace().size(11.5)).truncate());
                    ui.add_space(4.0);
                    ui.label(egui::RichText::new("Куда").size(10.5).color(self.palette.muted));
                    ui.add(
                        egui::Label::new(egui::RichText::new(&plan.dest_final).monospace().size(11.5)).truncate(),
                    );
                    ui.add_space(6.0);
                    ui.label(
                        egui::RichText::new("Сначала копия будет сверена, и только потом старый путь станет ссылкой.")
                            .size(11.5)
                            .color(self.palette.muted),
                    );
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui
                            .add(egui::Button::new(
                                egui::RichText::new("Перенести").color(self.palette.on_accent),
                            )
                            .fill(self.palette.accent)
                            .min_size(egui::vec2(112.0, 26.0)))
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
                "Требует внимания".to_string()
            } else {
                format!("Требуют внимания: {}", count)
            };
            egui::Window::new(title)
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
                .show(ctx, |ui| {
                    ui.label("Проверьте эти папки: перенос мог остановиться, а старый экземпляр — остаться:");
                    ui.add_space(4.0);
                    egui::ScrollArea::vertical().max_height(146.0).auto_shrink([false, false]).show(ui, |ui| {
                        for journal in self.journals.iter().take(100) {
                            let text = if journal.source.is_empty() {
                                journal.state_text().to_string()
                            } else {
                                format!("{} — {}", journal.state_text(), shorten_path(&journal.source, 58))
                            };
                            ui.add(
                                egui::Label::new(egui::RichText::new(text).monospace().size(10.5)).truncate(),
                            );
                        }
                        if count > 100 {
                            ui.add(
                                egui::Label::new(
                                    egui::RichText::new(format!("Показаны первые 100, всего {}", count))
                                        .size(10.5)
                                        .color(self.palette.muted),
                                )
                                .truncate(),
                            );
                        }
                    });
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui.button("Понятно").clicked() {
                            close = true;
                        }
                        if ui.button("Открыть папку журналов").clicked() {
                            let folder = self
                                .journals
                                .first()
                                .and_then(|journal| journal.path.parent().map(|p| p.to_path_buf()));
                            if let Some(folder) = folder {
                                let _ = std::process::Command::new("explorer.exe").arg(folder).spawn();
                            }
                        }
                    });
                });
            if close {
                self.journals.clear();
                self.journals_dismissed = true;
            }
        }
    }
}

const EXIT_OK: i32 = 0;
const EXIT_FAILED: i32 = 1;
const EXIT_USAGE: i32 = 2;
const EXIT_CANCELLED: i32 = 3;

static CANCEL: AtomicBool = AtomicBool::new(false);
static INTERRUPTS: AtomicU32 = AtomicU32::new(0);

#[derive(Clone, Debug, PartialEq, Eq)]
enum CliCommand {
    Help,
    Version,
    Journals,
    Plan { source: String, dest: String },
    Transfer { source: String, dest: String },
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct CliFlags {
    json: bool,
    quiet: bool,
    dry_run: bool,
}

fn expect_no_paths(positional: &[String]) -> Result<(), String> {
    if positional.is_empty() {
        Ok(())
    } else {
        Err(format!("Лишние параметры: {}", positional.join(" ")))
    }
}

fn parse_cli(args: &[String]) -> Result<(CliCommand, CliFlags), String> {
    let mut flags = CliFlags::default();
    let mut verb: Option<&'static str> = None;
    let mut positional: Vec<String> = Vec::new();
    let mut positional_only = false;
    for arg in args {
        if positional_only {
            positional.push(arg.clone());
            continue;
        }
        match arg.as_str() {
            "--" => positional_only = true,
            "--json" => flags.json = true,
            "--quiet" | "-q" => flags.quiet = true,
            "--dry-run" | "-n" => flags.dry_run = true,
            "--transfer" | "/transfer" => set_verb(&mut verb, "transfer")?,
            "--plan" => set_verb(&mut verb, "plan")?,
            "--journals" => set_verb(&mut verb, "journals")?,
            "--version" | "-V" => set_verb(&mut verb, "version")?,
            "--help" | "-h" | "/?" => set_verb(&mut verb, "help")?,
            other if other.starts_with('-') && other != "-" => {
                return Err(format!("Неизвестный параметр: {}", other));
            }
            other => positional.push(other.to_string()),
        }
    }
    let verb = match verb {
        Some(verb) => Some(verb),
        None if flags.dry_run => Some("plan"),
        None => None,
    };
    let Some(verb) = verb else {
        return Err("Не указана команда. Без параметров открывается окно.".to_string());
    };
    let command = match verb {
        "help" => {
            expect_no_paths(&positional)?;
            CliCommand::Help
        }
        "version" => {
            expect_no_paths(&positional)?;
            CliCommand::Version
        }
        "journals" => {
            expect_no_paths(&positional)?;
            CliCommand::Journals
        }
        _ => {
            if positional.len() != 2 {
                return Err("Нужны два пути: переносимая папка и папка назначения.".to_string());
            }
            let source = positional[0].clone();
            let dest = positional[1].clone();
            if verb == "plan" || flags.dry_run {
                CliCommand::Plan { source, dest }
            } else {
                CliCommand::Transfer { source, dest }
            }
        }
    };
    Ok((command, flags))
}

/// Accepts exactly one command: two different verbs on one line are a usage error, not "the last
/// one wins".
fn set_verb(verb: &mut Option<&'static str>, value: &'static str) -> Result<(), String> {
    match verb {
        Some(existing) if *existing != value => {
            Err(format!("Указано несколько команд: --{} и --{}.", existing, value))
        }
        _ => {
            *verb = Some(value);
            Ok(())
        }
    }
}

fn json_bool(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}

fn json_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 8);
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other if (other as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", other as u32)),
            other => out.push(other),
        }
    }
    out
}

fn handle_is_valid(handle: windows_sys::Win32::Foundation::HANDLE) -> bool {
    !handle.is_null() && handle != windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE
}

/// GUI-subsystem binaries start without usable console handles, so the CLI mode takes the parent
/// console (or allocates one) and points the standard handles at it. Redirected handles are kept.
fn ensure_console() {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::System::Console::{
        AllocConsole, AttachConsole, GetConsoleWindow, GetStdHandle, SetConsoleCP, SetConsoleOutputCP, SetStdHandle,
        STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
    };
    const ATTACH_PARENT_PROCESS: u32 = 0xFFFF_FFFF;
    const CP_UTF8: u32 = 65001;
    unsafe {
        // Attach to the parent console even when stdout is redirected: otherwise stderr would stay
        // dead and the progress or an error message would be lost.
        let mut owned_console = false;
        if GetConsoleWindow().is_null() && AttachConsole(ATTACH_PARENT_PROCESS) == 0 {
            let output_missing = !handle_is_valid(GetStdHandle(STD_OUTPUT_HANDLE));
            let errors_missing = !handle_is_valid(GetStdHandle(STD_ERROR_HANDLE));
            if output_missing || errors_missing {
                owned_console = AllocConsole() != 0;
            }
        }
        // Only our own console may be switched to UTF-8: the parent console belongs to the caller,
        // and its code page must stay as it was.
        if owned_console {
            SetConsoleOutputCP(CP_UTF8);
            SetConsoleCP(CP_UTF8);
        }
        for (std_id, device, read) in [
            (STD_OUTPUT_HANDLE, "CONOUT$", false),
            (STD_ERROR_HANDLE, "CONOUT$", false),
            (STD_INPUT_HANDLE, "CONIN$", true),
        ] {
            if handle_is_valid(GetStdHandle(std_id)) {
                continue;
            }
            let opened = if read {
                std::fs::OpenOptions::new().read(true).open(device)
            } else {
                std::fs::OpenOptions::new().write(true).open(device)
            };
            if let Ok(file) = opened {
                SetStdHandle(std_id, file.as_raw_handle() as _);
                std::mem::forget(file);
            }
        }
    }
}

unsafe extern "system" fn console_ctrl_handler(event: u32) -> i32 {
    const CTRL_C_EVENT: u32 = 0;
    const CTRL_BREAK_EVENT: u32 = 1;
    if event == CTRL_C_EVENT || event == CTRL_BREAK_EVENT {
        // Keep handling every Ctrl+C: returning 0 would restore the default handler and kill the
        // process in the middle of publishing or linking, where the journal is the only safety net.
        INTERRUPTS.fetch_add(1, Ordering::SeqCst);
        CANCEL.store(true, Ordering::SeqCst);
        return 1;
    }
    0
}

fn install_ctrl_c() {
    unsafe {
        windows_sys::Win32::System::Console::SetConsoleCtrlHandler(Some(console_ctrl_handler), 1);
    }
}

struct CliSink {
    quiet: bool,
    last_phase: std::sync::Mutex<engine::Phase>,
    last_bucket: AtomicU32,
}

impl CliSink {
    fn new(quiet: bool) -> Self {
        CliSink { quiet, last_phase: std::sync::Mutex::new(engine::Phase::Validate), last_bucket: AtomicU32::new(u32::MAX) }
    }
}

impl engine::Sink for CliSink {
    fn progress(&self, progress: &engine::Progress) {
        if self.quiet {
            return;
        }
        let percent = if progress.bytes_total > 0 {
            (progress.bytes_done.saturating_mul(100) / progress.bytes_total) as u32
        } else if progress.files_total > 0 {
            (progress.files_done.saturating_mul(100) / progress.files_total) as u32
        } else {
            0
        };
        let bucket = percent / 10 * 10;
        let phase_changed = match self.last_phase.lock() {
            Ok(mut last) => {
                if *last == progress.phase {
                    false
                } else {
                    *last = progress.phase;
                    true
                }
            }
            Err(_) => false,
        };
        if !phase_changed && self.last_bucket.load(Ordering::Relaxed) == bucket {
            return;
        }
        self.last_bucket.store(bucket, Ordering::Relaxed);
        if progress.item.is_empty() {
            cli_err(&format!("[{}] {}%", progress.phase.text(), percent));
        } else {
            cli_err(&format!("[{}] {}% {}", progress.phase.text(), percent, shorten_path(&progress.item, 70)));
        }
    }

    fn cancelled(&self) -> bool {
        CANCEL.load(Ordering::SeqCst)
    }
}

/// Writes a line and ignores errors: a GUI-subsystem process may have no usable stdout.
fn cli_out(line: &str) {
    use windows_sys::Win32::System::Console::STD_OUTPUT_HANDLE;
    write_line(STD_OUTPUT_HANDLE, line);
}

fn cli_err(line: &str) {
    use windows_sys::Win32::System::Console::STD_ERROR_HANDLE;
    write_line(STD_ERROR_HANDLE, line);
}
/// A console receives wide characters through `WriteConsoleW`, so Cyrillic is shown correctly no
/// matter which code page the caller's console uses. A redirected handle gets plain UTF-8 bytes.
fn write_line(std_id: u32, line: &str) {
    use std::io::Write;
    use windows_sys::Win32::System::Console::{
        GetConsoleMode, GetStdHandle, WriteConsoleW, STD_OUTPUT_HANDLE,
    };
    const INVALID_HANDLE: isize = -1;
    unsafe {
        let handle = GetStdHandle(std_id);
        let mut mode: u32 = 0;
        if !handle.is_null()
            && handle as isize != INVALID_HANDLE
            && GetConsoleMode(handle, &mut mode) != 0
        {
            let mut units: Vec<u16> = line.encode_utf16().collect();
            units.push(b'\r' as u16);
            units.push(b'\n' as u16);
            let mut written: u32 = 0;
            WriteConsoleW(handle, units.as_ptr(), units.len() as u32, &mut written, std::ptr::null_mut());
            return;
        }
    }
    let stream: &mut dyn Write = if std_id == STD_OUTPUT_HANDLE {
        &mut std::io::stdout()
    } else {
        &mut std::io::stderr()
    };
    let _ = writeln!(stream, "{}", line);
    let _ = stream.flush();
}

fn help_text() -> String {
    let mut text = String::new();
    text.push_str(&format!(
        "Linkerino {}: переносит папку и оставляет на её месте символьную ссылку.\n",
        env!("CARGO_PKG_VERSION")
    ));
    text.push('\n');
    text.push_str("Без параметров открывается окно программы.\n\n");
    text.push_str("Команды:\n");
    text.push_str("  --transfer <папка> <куда>   перенести папку и оставить на старом месте ссылку\n");
    text.push_str("  --plan <папка> <куда>       только проверить пути и показать итоговый путь\n");
    text.push_str("  --journals                  показать записи, требующие внимания\n");
    text.push_str("  --version                   версия программы\n");
    text.push_str("  --help                      эта справка\n\n");
    text.push_str("Параметры:\n");
    text.push_str("  --dry-run, -n               то же, что --plan; можно и без --transfer\n");
    text.push_str("  --quiet, -q                 без строк прогресса\n");
    text.push_str("  --json                      итог и ошибки одной JSON-строкой в stdout\n");
    text.push_str("  --                          дальше только пути (если путь начинается с «-»)\n\n");
    text.push_str(
        "Коды возврата: 0 — успех, 1 — отказ или ошибка переноса, 2 — ошибка в параметрах,\n3 — отменено по Ctrl+C. Прогресс выводится в stderr.\n\n",
    );
    text.push_str("Служебные режимы для снимков окна: --screenshot <файл> [--demo] [--theme light|dark].\n");
    text
}

fn print_help() {
    cli_out(help_text().trim_end());
}

fn print_help_err() {
    cli_err(help_text().trim_end());
}

/// Usage errors keep stdout machine-readable when `--json` was requested; the help goes to stderr.
fn report_usage_error(args: &[String], message: &str) -> i32 {
    if args.iter().any(|arg| arg == "--json") {
        cli_out(&format!("{{\"ok\":false,\"error\":\"{}\"}}", json_escape(message)));
    }
    cli_err(message);
    print_help_err();
    EXIT_USAGE
}

fn json_outcome(plan: &engine::Plan, outcome: &engine::Outcome) -> String {
    format!(
        "{{\"ok\":{},\"cancelled\":{},\"dest\":\"{}\",\"message\":\"{}\",\"detail\":\"{}\",\"notes\":\"{}\",\"leftover\":\"{}\"}}",
        json_bool(outcome.ok),
        json_bool(outcome.cancelled),
        json_escape(&plan.dest_final),
        json_escape(&outcome.message),
        json_escape(&outcome.detail),
        json_escape(outcome.notes.trim_end()),
        json_escape(&outcome.leftover)
    )
}

fn run_journals(json: bool) -> i32 {
    let journals = engine::unfinished_journals();
    if json {
        let items: Vec<String> = journals
            .iter()
            .map(|journal| {
                format!(
                    "{{\"path\":\"{}\",\"state\":\"{}\",\"source\":\"{}\",\"dest\":\"{}\",\"backup\":\"{}\"}}",
                    json_escape(&journal.path.display().to_string()),
                    json_escape(&journal.state),
                    json_escape(&journal.source),
                    json_escape(&journal.dest),
                    json_escape(&journal.backup)
                )
            })
            .collect();
        cli_out(&format!("{{\"count\":{},\"journals\":[{}]}}", journals.len(), items.join(",")));
        return EXIT_OK;
    }
    if journals.is_empty() {
        cli_out("Нет записей, требующих внимания.");
    } else {
        cli_out(&format!("Требуют внимания: {}", journals.len()));
        for journal in &journals {
            cli_out(&format!("{} [{}]", journal.path.display(), journal.state));
            cli_out(&format!("  {}", journal.state_text()));
            if !journal.source.is_empty() {
                cli_out(&format!("  откуда: {}", journal.source));
            }
            if !journal.dest.is_empty() {
                cli_out(&format!("  куда: {}", journal.dest));
            }
            if !journal.backup.is_empty() {
                cli_out(&format!("  резерв: {}", journal.backup));
            }
        }
    }
    EXIT_OK
}

fn run_plan(source: &str, dest: &str, flags: &CliFlags) -> i32 {
    let plan = engine::build_plan(source, dest);
    if !plan.valid {
        if flags.json {
            cli_out(&format!("{{\"ok\":false,\"error\":\"{}\"}}", json_escape(&plan.error)));
        } else {
            cli_err(&plan.error);
        }
        return EXIT_FAILED;
    }
    if flags.json {
        cli_out(&format!(
            "{{\"ok\":true,\"dry_run\":true,\"source\":\"{}\",\"dest\":\"{}\"}}",
            json_escape(&plan.source),
            json_escape(&plan.dest_final)
        ));
    } else {
        cli_out("Проверка пройдена, перенос не выполнялся.");
        cli_out(&format!("Откуда: {}", plan.source));
        cli_out(&format!("Куда:   {}", plan.dest_final));
    }
    EXIT_OK
}

fn run_transfer(source: &str, dest: &str, flags: &CliFlags) -> i32 {
    let plan = engine::build_plan(source, dest);
    if !plan.valid {
        if flags.json {
            cli_out(&format!("{{\"ok\":false,\"error\":\"{}\"}}", json_escape(&plan.error)));
        } else {
            cli_err(&plan.error);
        }
        return EXIT_FAILED;
    }
    install_ctrl_c();
    // Progress goes to stderr and is off only with --quiet: --json controls stdout, not stderr.
    let sink = CliSink::new(flags.quiet);
    let outcome = engine::execute(&plan, Some(&sink), &engine::Faults::default());
    if flags.json {
        cli_out(&json_outcome(&plan, &outcome));
    } else {
        cli_out(&outcome.message);
        if !outcome.leftover.is_empty() {
            cli_out(&format!("Остаток: {}", outcome.leftover));
        }
        if !outcome.notes.is_empty() {
            cli_out(outcome.notes.trim_end());
        }
        if !outcome.ok && !outcome.detail.is_empty() {
            cli_err(&outcome.detail);
        }
    }
    if outcome.cancelled {
        EXIT_CANCELLED
    } else if outcome.ok {
        EXIT_OK
    } else {
        EXIT_FAILED
    }
}

fn run_cli(args: &[String]) -> i32 {
    ensure_console();
    let (command, flags) = match parse_cli(args) {
        Ok(value) => value,
        Err(error) => {
            return report_usage_error(args, &error);
        }
    };
    match command {
        CliCommand::Help => {
            print_help();
            EXIT_OK
        }
        CliCommand::Version => {
            cli_out(&format!("Linkerino {}", env!("CARGO_PKG_VERSION")));
            EXIT_OK
        }
        CliCommand::Journals => run_journals(flags.json),
        CliCommand::Plan { source, dest } => run_plan(&source, &dest, &flags),
        CliCommand::Transfer { source, dest } => run_transfer(&source, &dest, &flags),
    }
}

fn window_icon() -> Option<egui::IconData> {
    let image = image::load_from_memory(include_bytes!("../assets/linkerino-256.png")).ok()?.to_rgba8();
    Some(egui::IconData { rgba: image.as_raw().clone(), width: image.width(), height: image.height() })
}

/// Converts the raw command line strictly, keeping the arguments that are readable.
/// The flag means "some argument could not be read as Unicode": those must not be silently
/// replaced, but the readable ones still decide how the error is reported (`--json`).
fn collect_args<I: Iterator<Item = std::ffi::OsString>>(values: I) -> (Vec<String>, bool) {
    let mut result = Vec::new();
    let mut unreadable = false;
    for value in values {
        match value.to_str() {
            Some(text) => result.push(text.to_string()),
            None => unreadable = true,
        }
    }
    (result, unreadable)
}

fn main() -> eframe::Result<()> {
    // Non-Unicode arguments must not panic, and must not silently open the window either: they are
    // reported as a usage error with code 2 whatever mode was intended.
    let (args, unreadable) = collect_args(std::env::args_os().skip(1));
    if unreadable {
        ensure_console();
        let code = report_usage_error(
            &args,
            "Аргумент содержит символы, которые нельзя прочитать как Unicode.",
        );
        std::process::exit(code);
    }
    let cli = args.iter().any(|arg| {
        matches!(
            arg.as_str(),
            "--transfer"
                | "/transfer"
                | "--plan"
                | "--journals"
                | "--version"
                | "-V"
                | "--help"
                | "-h"
                | "/?"
                | "--dry-run"
                | "-n"
                | "--json"
                | "--quiet"
                | "-q"
        )
    });
    if cli {
        let code = run_cli(&args);
        std::process::exit(code);
    }

    let mut screenshot: Option<PathBuf> = None;
    let mut demo = false;
    let mut demo_result = false;
    let mut demo_journals = false;
    let mut theme_override: Option<Theme> = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--screenshot" => {
                if index + 1 < args.len() {
                    screenshot = Some(PathBuf::from(&args[index + 1]));
                    index += 1;
                }
            }
            "--demo" => demo = true,
            "--demo-result" => demo_result = true,
            "--demo-journals" => demo_journals = true,
            "--theme" => {
                if index + 1 < args.len() {
                    theme_override = Some(theme_from_key(&args[index + 1]));
                    index += 1;
                }
            }
            _ => {}
        }
        index += 1;
    }
    if screenshot.is_none() && !args.is_empty() {
        ensure_console();
        let message = format!("Неизвестные параметры: {}", args.join(" "));
        std::process::exit(report_usage_error(&args, &message));
    }
    let mut viewport = egui::ViewportBuilder::default()
        .with_inner_size([560.0, 320.0])
        .with_min_inner_size([560.0, 320.0])
        .with_resizable(false)
        .with_title("Linkerino");
    if let Some(icon) = window_icon() {
        viewport = viewport.with_icon(icon);
    }
    let options = eframe::NativeOptions { viewport, ..Default::default() };
    eframe::run_native(
        "Linkerino",
        options,
        Box::new(move |cc| Ok(Box::new(App::new(cc, screenshot, demo, demo_result, demo_journals, theme_override)))),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn theme_parsing() {
        assert_eq!(parse_theme("theme=dark\n"), Theme::Dark);
        assert_eq!(parse_theme("theme=light\n"), Theme::Light);
        assert_eq!(parse_theme("dark"), Theme::Dark);
        assert_eq!(parse_theme("theme=unknown\n"), Theme::Light);
        assert_eq!(parse_theme(""), Theme::Light);
        assert_eq!(parse_theme("something=else\n"), Theme::Light);
    }

    #[test]
    fn theme_keys_roundtrip() {
        assert_eq!(theme_from_key(Theme::Dark.key()), Theme::Dark);
        assert_eq!(theme_from_key(Theme::Light.key()), Theme::Light);
        assert_eq!(theme_from_key("DARK"), Theme::Dark);
    }
}

#[cfg(test)]
mod cli_tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|value| value.to_string()).collect()
    }

    #[test]
    fn transfer_parsing() {
        let (command, flags) = parse_cli(&args(&["--transfer", "C:\\a", "D:\\b"])).unwrap();
        assert_eq!(
            command,
            CliCommand::Transfer { source: "C:\\a".to_string(), dest: "D:\\b".to_string() }
        );
        assert!(!flags.json && !flags.quiet && !flags.dry_run);
    }

    #[test]
    fn plan_and_dry_run_parsing() {
        let (command, _) = parse_cli(&args(&["--plan", "a", "b"])).unwrap();
        assert!(matches!(command, CliCommand::Plan { .. }));
        let (command, flags) = parse_cli(&args(&["--transfer", "a", "b", "--dry-run", "--json", "-q"])).unwrap();
        assert!(matches!(command, CliCommand::Plan { .. }));
        assert!(flags.json && flags.quiet && flags.dry_run);
        let (command, flags) = parse_cli(&args(&["--dry-run", "a", "b"])).unwrap();
        assert!(matches!(command, CliCommand::Plan { .. }));
        assert!(flags.dry_run);
    }

    #[test]
    fn double_dash_keeps_dash_paths() {
        let (command, _) = parse_cli(&args(&["--plan", "--", "-odd", "-dest"])).unwrap();
        assert_eq!(
            command,
            CliCommand::Plan { source: "-odd".to_string(), dest: "-dest".to_string() }
        );
        // After `--` a word that looks like a flag is a path, not a command.
        let (command, flags) = parse_cli(&args(&["--transfer", "--", "--json", "dest"])).unwrap();
        assert_eq!(
            command,
            CliCommand::Transfer { source: "--json".to_string(), dest: "dest".to_string() }
        );
        assert!(!flags.json);
    }

    #[test]
    fn two_commands_on_one_line_are_refused() {
        assert!(parse_cli(&args(&["--transfer", "a", "b", "--journals"])).is_err());
        assert!(parse_cli(&args(&["--version", "--help"])).is_err());
        // Repeating the same command is harmless and still a usage error only if paths disagree.
        assert!(parse_cli(&args(&["--journals", "--journals"])).is_ok());
    }

    #[test]
    fn usage_errors() {
        assert!(parse_cli(&args(&["--transfer", "only-one"])).is_err());
        assert!(parse_cli(&args(&["--nonsense"])).is_err());
        assert!(parse_cli(&args(&["--version", "extra"])).is_err());
        assert!(parse_cli(&args(&[])).is_err());
    }

    #[test]
    fn json_escaping() {
        assert_eq!(json_escape("a\"b\\c\nd\te"), "a\\\"b\\\\c\\nd\\te");
        assert_eq!(json_escape("Готово"), "Готово");
        assert_eq!(json_escape("\u{1}"), "\\u0001");
    }
}

#[cfg(test)]
mod args_tests {
    use super::*;
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;

    #[test]
    fn unreadable_arguments_are_refused_but_keep_the_flags() {
        let (good, bad) = collect_args(vec![OsString::from("--plan"), OsString::from("a")].into_iter());
        assert_eq!(good, vec!["--plan".to_string(), "a".to_string()]);
        assert!(!bad);
        // An unpaired surrogate cannot be converted: silently replacing it would be worse. The
        // readable flags are still kept, so `--json` can shape the error message.
        let (kept, bad) = collect_args(
            vec![OsString::from("--json"), OsString::from_wide(&[0xD800]), OsString::from("--plan")].into_iter(),
        );
        assert!(bad);
        assert_eq!(kept, vec!["--json".to_string(), "--plan".to_string()]);
    }
}
