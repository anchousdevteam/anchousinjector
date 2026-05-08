#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use sysinfo::System;

extern "C" {
    fn run_injection(process_name: *const u16, dll_path: *const u16) -> u8;
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([400.0, 320.0]) // Увеличил высоту до 320
            .with_resizable(false)         // Запретил менять размер окна
            .with_icon(std::sync::Arc::new(load_icon())),
        ..Default::default()
    };
    eframe::run_native("anchous injector", options, Box::new(|cc| {
        egui_extras::install_image_loaders(&cc.egui_ctx);
        Box::new(App::new(cc))
    }))
}

fn load_icon() -> egui::IconData {
    let icon_path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/icon.png");
    let image = image::open(icon_path).expect("icon.png not found in src/").to_rgba8();
    let (width, height) = image.dimensions();
    egui::IconData { rgba: image.into_raw(), width, height }
}

struct App {
    process: String,
    dll: String,
    processes: Vec<String>,
}

impl App {
    fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        let mut app = Self {
            process: "Minecraft.Windows.exe".into(),
            dll: "".into(),
            processes: Vec::new(),
        };
        app.refresh_processes();
        app
    }

    fn refresh_processes(&mut self) {
        let mut sys = System::new_all();
        sys.refresh_all();
        self.processes = sys.processes().values()
            .map(|p| p.name().to_string())
            .collect();
        self.processes.sort();
        self.processes.dedup();
    }
}

fn to_wstring(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(10.0);
                let img = egui::Image::new(egui::include_image!("icon.png"))
                    .rounding(50.0)
                    .fit_to_exact_size(egui::vec2(60.0, 60.0));
                ui.add(img);
                ui.heading("anchous injector");
            });
            ui.add_space(10.0);

            ui.label("process name:");
            ui.horizontal(|ui| {
                egui::ComboBox::from_id_source("proc")
                    .width(ui.available_width() - 40.0)
                    .selected_text(&self.process)
                    .show_ui(ui, |ui| {
                        for p in &self.processes {
                            ui.selectable_value(&mut self.process, p.clone(), p);
                        }
                    });
                if ui.button("🔄").clicked() { self.refresh_processes(); }
            });

            ui.add_space(10.0);
            ui.label("dll path:");
            ui.horizontal(|ui| {
                ui.text_edit_singleline(&mut self.dll);
                if ui.button("browse").clicked() {
                    if let Some(path) = rfd::FileDialog::new().add_filter("DLL", &["dll"]).pick_file() {
                        self.dll = path.display().to_string();
                    }
                }
            });

            ui.add_space(20.0);
            
            let btn_width = ui.available_width();
            if ui.add_sized([btn_width, 30.0], egui::Button::new("🚀 inj")).clicked() {
                let p_w = to_wstring(&self.process);
                let d_w = to_wstring(&self.dll);
                unsafe {
                    run_injection(p_w.as_ptr(), d_w.as_ptr());
                }
            }

            ui.with_layout(egui::Layout::bottom_up(egui::Align::Center), |ui| {
                ui.add_space(5.0);
                ui.hyperlink_to("t.me/anchousdev", "https://t.me/anchousdev");
                ui.separator();
            });
        });
    }
}
