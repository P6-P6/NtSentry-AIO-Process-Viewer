#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

mod app;
mod tray;

use eframe::egui;
use ntsentry::autostart::MINIMIZED_FLAG;
use ntsentry::process_inventory::{self, KnownDirs, ProcessInventory};
use ntsentry::signature::SignatureCache;
use ntsentry::storage::{DataDir, write_new};
use ntsentry::{integrity_monitor, inventory, module_audit, persistence_audit};

const HELP: &str = "NtSentry AIO Process Viewer\n\n\
No arguments: open the dashboard.\n\
--minimized                  open the dashboard minimized (used by the sign-in entry)\n\
--scan NEW.json              run every scan and write the reports to a new file\n\
--capture-baseline NEW.json  capture the ntdll baseline and write the outcome to a new file\n\n\
Data directory: %NTSENTRY_DATA% or %LOCALAPPDATA%\\NtSentry.\n\
Output files are never overwritten.";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let data = match DataDir::default_location() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
    };
    let start_minimized = args.len() == 1 && args[0] == MINIMIZED_FLAG;
    if !args.is_empty() && !start_minimized {
        if let Err(e) = cli(&args, &data) {
            eprintln!("{e}");
            std::process::exit(1);
        }
        return;
    }
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("NtSentry AIO Process Viewer")
            .with_inner_size([1400.0, 880.0])
            .with_min_inner_size([900.0, 560.0])
            .with_icon(std::sync::Arc::new(tray::window_icon())),
        ..Default::default()
    };
    if let Err(e) = eframe::run_native(
        "NtSentry AIO Process Viewer",
        options,
        Box::new(move |cc| Ok(Box::new(app::Dashboard::new(cc, data, start_minimized)))),
    ) {
        eprintln!("{e}");
        std::process::exit(1);
    }
}

fn cli(args: &[String], data: &DataDir) -> Result<(), String> {
    match args {
        [flag] if flag == "--help" => {
            println!("{HELP}");
            Ok(())
        }
        [flag, out] if flag == "--scan" => {
            let mut cache = SignatureCache::new();
            let dirs = KnownDirs::detect();
            let integrity = integrity_monitor::scan(data, true);
            let processes = ProcessInventory::new().scan(&mut cache);
            let list: Vec<(u32, String)> =
                process_inventory::list_processes()?.into_iter().map(|p| (p.pid, p.name)).collect();
            let sweep = integrity_monitor::sweep_processes(&list, &mut cache, &dirs);
            let modules = module_audit::scan(&processes.processes, &mut cache, &dirs);
            let persistence = persistence_audit::scan(&inventory::collect(), &mut cache, &dirs);
            data.append_log("integrity", &integrity.findings)?;
            data.append_log("processes", &processes.findings)?;
            for report in [&sweep, &modules, &persistence] {
                data.append_log(&report.kind, &report.findings)?;
            }
            let body = serde_json::json!({
                "integrity": integrity,
                "processes": processes,
                "ntdll_sweep": sweep,
                "modules": modules,
                "persistence": persistence,
            });
            write_new(std::path::Path::new(out), pretty(&body)?.as_bytes())
        }
        [flag, out] if flag == "--capture-baseline" => {
            let outcome = integrity_monitor::capture_baseline(data)?;
            data.append_log("baseline_capture", &outcome.findings)?;
            write_new(std::path::Path::new(out), pretty(&outcome)?.as_bytes())
        }
        _ => Err(format!("Unrecognised arguments.\n\n{HELP}")),
    }
}

fn pretty<T: serde::Serialize>(value: &T) -> Result<String, String> {
    serde_json::to_string_pretty(value).map_err(|e| e.to_string())
}
