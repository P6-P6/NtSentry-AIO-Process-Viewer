//! The egui dashboard: menu bar, toolbar, an always-visible findings pane, the
//! inventory tabs (processes, services, drivers, startup, connections), and a
//! details pane for whatever row is selected.

use eframe::egui::{self, Color32, Key, KeyboardShortcut, Modifiers, RichText};
use egui_extras::{Column, TableBuilder};
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, TryRecvError, channel};
use std::time::{Duration, Instant};
use ntsentry::findings::{Finding, ScanReport, Severity};
use ntsentry::integrity_monitor::{self, IntegrityReport};
use ntsentry::inventory::{
    ProcessDetails, ProcessIdentity, ProcessInfo, ProcessSnapshot, SystemInventory, image_path_from_command,
};
use ntsentry::process_inventory::{self, ProcessRecord, ProcessReport};
use ntsentry::settings::Settings;
use ntsentry::storage::DataDir;
use ntsentry::winutil::{format_utc, now_unix, windows_directory};
use ntsentry::quarantine::{self, QuarantineEntry};
use ntsentry::worker::{Action, Command, Event, LiveCommand, Worker};
use ntsentry::persistence_audit::{self, EntryKind};
use ntsentry::{autostart, dialogs, eventlog, explain, export, module_audit};

/// Scans that only produce findings: (log kind, finding module).
const EXTRA_SCANS: [(&str, &str); 3] = [
    (integrity_monitor::SWEEP_KIND, integrity_monitor::SWEEP_MODULE),
    (module_audit::KIND, module_audit::MODULE),
    (persistence_audit::KIND, persistence_audit::MODULE),
];

const ROW_HEIGHT: f32 = 20.0;
const INVENTORY_REFRESH: Duration = Duration::from_secs(15);

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
enum Tab {
    Processes,
    Services,
    Drivers,
    Startup,
    Connections,
    Quarantine,
}

impl Tab {
    const ALL: [Tab; 6] = [Tab::Processes, Tab::Services, Tab::Drivers, Tab::Startup, Tab::Connections, Tab::Quarantine];

    fn label(self) -> &'static str {
        match self {
            Tab::Processes => "Processes",
            Tab::Services => "Services",
            Tab::Drivers => "Drivers",
            Tab::Startup => "Startup",
            Tab::Connections => "Connections",
            Tab::Quarantine => "Quarantine",
        }
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
enum Selection {
    Finding(String),
    Process(u32),
    Service(String),
    Driver(String),
    Startup(String),
    Connection(String),
    Quarantined(String),
}

impl Selection {
    /// Spec id of the table that shows this kind of row.
    fn table(&self) -> &'static str {
        match self {
            Selection::Finding(_) => "findings",
            Selection::Process(_) => "processes",
            Selection::Service(_) => "services",
            Selection::Driver(_) => "drivers",
            Selection::Startup(_) => "startup",
            Selection::Connection(_) => "connections",
            Selection::Quarantined(_) => "quarantine",
        }
    }
}

/// Operations on the selected rows that need the table's visible rows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RowsOp {
    SelectAll,
    Copy,
    Export,
}

/// The keys from `a` to `b` inclusive, in table order.
fn range_between(keys: &[&Selection], a: &Selection, b: &Selection) -> Option<Vec<Selection>> {
    let ia = keys.iter().position(|k| *k == a)?;
    let ib = keys.iter().position(|k| *k == b)?;
    let (lo, hi) = (ia.min(ib), ia.max(ib));
    Some(keys[lo..=hi].iter().map(|k| (*k).clone()).collect())
}

/// Indices of the columns to show: all except hidden ones (never none).
fn visible_columns(spec: &Spec, hidden: Option<&Vec<String>>) -> Vec<usize> {
    let cols: Vec<usize> = (0..spec.columns.len())
        .filter(|&i| hidden.is_none_or(|h| !h.iter().any(|t| t == spec.columns[i].0)))
        .collect();
    if cols.is_empty() { (0..spec.columns.len()).collect() } else { cols }
}

/// Headers and cell texts restricted to the shown columns.
fn shown_headers<'a>(spec: &'a Spec, cols: &[usize]) -> Vec<&'a str> {
    cols.iter().map(|&i| spec.columns[i].0).collect()
}

fn shown_texts<'a>(row: &'a Row, cols: &[usize]) -> Vec<&'a str> {
    cols.iter().map(|&i| row.cells.get(i).map_or("", |c| c.text.as_str())).collect()
}

/// Selected rows as tab-separated text with a header line, in table order,
/// using only the shown columns.
fn rows_text(spec: &Spec, cols: &[usize], rows: &[&Row], marked: &HashSet<Selection>) -> (String, usize) {
    let mut text = shown_headers(spec, cols).join("\t");
    text.push('\n');
    let mut count = 0;
    for row in rows.iter().filter(|r| marked.contains(&r.key)) {
        text.push_str(&shown_texts(row, cols).join("\t"));
        text.push('\n');
        count += 1;
    }
    (text, count)
}

/// "Columns" submenu with a checkbox per column.
fn columns_menu(ui: &mut egui::Ui, spec: &Spec, cols: &[usize]) -> Option<RowAction> {
    let mut chosen = None;
    ui.menu_button("Columns", |ui| {
        for (i, (title, _)) in spec.columns.iter().enumerate() {
            let mut shown = cols.contains(&i);
            let last = shown && cols.len() == 1;
            if ui.add_enabled(!last, egui::Checkbox::new(&mut shown, *title)).clicked() {
                chosen = Some(RowAction::ToggleColumn(spec.id, title));
            }
        }
        ui.separator();
        if ui.button("Show all columns").clicked() {
            chosen = Some(RowAction::ShowAllColumns(spec.id));
        }
    });
    chosen
}
/// What a right-click menu item asks for.
#[derive(Clone, Debug)]
enum RowAction {
    Details(Selection),
    Copy(Selection),
    OpenLocation(Selection),
    End(Vec<u32>),
    Suspend(Vec<u32>),
    Resume(Vec<u32>),
    Quarantine(Vec<u32>),
    Restore(String),
    Rows(RowsOp),
    EndTree(Vec<u32>),
    VirusTotal(Selection),
    Properties(Selection),
    ToggleColumn(&'static str, &'static str),
    ShowAllColumns(&'static str),
}

/// A pending action shown in a confirmation dialog.
struct Confirm {
    title: String,
    text: String,
    button: &'static str,
    actions: Vec<Action>,
}

/// Right-click menu for a row. `targets` are the PIDs a process action applies to
/// (all selected processes when the row is part of a multi-selection); `suspended`
/// holds PIDs the dashboard suspended; `selected` is how many rows are selected.
fn row_menu(
    ui: &mut egui::Ui,
    selection: &Selection,
    targets: &[u32],
    suspended: &HashSet<u32>,
    selected: usize,
) -> Option<RowAction> {
    let mut chosen = None;
    if matches!(selection, Selection::Process(_)) && !targets.is_empty() {
        let n = targets.len();
        let label = |text: &str| if n > 1 { format!("{text} ({n} processes)") } else { text.to_string() };
        if ui.button(label("End process…")).clicked() {
            chosen = Some(RowAction::End(targets.to_vec()));
        }
        if ui.button(label("End process tree…")).clicked() {
            chosen = Some(RowAction::EndTree(targets.to_vec()));
        }
        if targets.iter().any(|p| !suspended.contains(p)) && ui.button(label("Suspend")).clicked() {
            chosen = Some(RowAction::Suspend(targets.to_vec()));
        }
        if targets.iter().any(|p| suspended.contains(p)) && ui.button(label("Resume")).clicked() {
            chosen = Some(RowAction::Resume(targets.to_vec()));
        }
        if ui.button(label("End and quarantine file…")).clicked() {
            chosen = Some(RowAction::Quarantine(targets.to_vec()));
        }
        ui.separator();
    }
    if let Selection::Quarantined(id) = selection {
        if ui.button("Restore to original location…").clicked() {
            chosen = Some(RowAction::Restore(id.clone()));
        }
        ui.separator();
    }
    if selected > 1 {
        if ui.button(format!("Copy {selected} selected rows")).clicked() {
            chosen = Some(RowAction::Rows(RowsOp::Copy));
        }
        if ui.button(format!("Export {selected} selected rows as CSV…")).clicked() {
            chosen = Some(RowAction::Rows(RowsOp::Export));
        }
        ui.separator();
    }
    if ui.button("Select all\tCtrl+A").clicked() {
        chosen = Some(RowAction::Rows(RowsOp::SelectAll));
    }
    if ui.button("Show details").clicked() {
        chosen = Some(RowAction::Details(selection.clone()));
    }
    if ui.button("Copy details").clicked() {
        chosen = Some(RowAction::Copy(selection.clone()));
    }
    let has_file = matches!(selection, Selection::Process(_) | Selection::Service(_) | Selection::Driver(_) | Selection::Startup(_));
    if has_file {
        if ui.button("Open file location").clicked() {
            chosen = Some(RowAction::OpenLocation(selection.clone()));
        }
        if ui.button("File properties").clicked() {
            chosen = Some(RowAction::Properties(selection.clone()));
        }
    }
    if (has_file || matches!(selection, Selection::Quarantined(_)))
        && ui
            .button("Look up on VirusTotal")
            .on_hover_text("Opens your browser with the file's SHA-256. Only the hash leaves this PC.")
            .clicked()
    {
        chosen = Some(RowAction::VirusTotal(selection.clone()));
    }
    chosen
}

#[derive(Clone, Debug)]
enum SortKey {
    Num(f64),
    Text(String),
    Empty,
}

struct Cell {
    text: String,
    sort: SortKey,
    color: Option<Color32>,
    mono: bool,
    strong: bool,
}

impl Cell {
    fn text(text: impl Into<String>) -> Self {
        let text = text.into();
        let sort = if text.is_empty() { SortKey::Empty } else { SortKey::Text(text.to_lowercase()) };
        Cell { text, sort, color: None, mono: false, strong: false }
    }

    fn num(text: impl Into<String>, value: f64) -> Self {
        Cell { text: text.into(), sort: SortKey::Num(value), color: None, mono: false, strong: false }
    }

    fn empty() -> Self {
        Cell { text: String::new(), sort: SortKey::Empty, color: None, mono: false, strong: false }
    }

    fn severity(severity: Option<Severity>) -> Self {
        match severity {
            Some(s) => Cell {
                color: Some(severity_color(s)),
                strong: true,
                ..Cell::num(s.label(), s as u8 as f64)
            },
            None => Cell::empty(),
        }
    }

    fn mono(mut self) -> Self {
        self.mono = true;
        self
    }

    fn colored(mut self, color: Color32) -> Self {
        self.color = Some(color);
        self
    }
}

struct Row {
    key: Selection,
    cells: Vec<Cell>,
    /// Processes only: a Windows system process (for "Hide Windows system processes").
    system: bool,
    /// Processes only: highest finding severity.
    severity: Option<Severity>,
}

impl Row {
    fn new(key: Selection, cells: Vec<Cell>) -> Self {
        Row { key, cells, system: false, severity: None }
    }

    fn texts(&self) -> Vec<&str> {
        self.cells.iter().map(|c| c.text.as_str()).collect()
    }
}

struct Spec {
    id: &'static str,
    columns: Vec<(&'static str, Column)>,
}

impl Spec {
    fn headers(&self) -> Vec<&'static str> {
        self.columns.iter().map(|(h, _)| *h).collect()
    }
}

#[derive(Default)]
struct TableOutput {
    /// Row clicked, the modifiers held, and whether it was a right-click.
    clicked: Option<(Selection, Modifiers, bool)>,
    sort_clicked: Option<usize>,
    action: Option<RowAction>,
}

fn severity_color(s: Severity) -> Color32 {
    match s {
        Severity::Critical => Color32::from_rgb(230, 60, 60),
        Severity::High => Color32::from_rgb(240, 120, 40),
        Severity::Medium => Color32::from_rgb(220, 170, 30),
        Severity::Low => Color32::from_rgb(150, 175, 70),
        Severity::Info => Color32::GRAY,
    }
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 { format!("{bytes} B") } else { format!("{value:.1} {}", UNITS[unit]) }
}

/// `20261103-015452` (UTC) for default export file names.
fn compact_stamp() -> String {
    format_utc(now_unix()).replace(" UTC", "").replace(['-', ':'], "").replace(' ', "-")
}

fn compare_keys(a: &SortKey, b: &SortKey, ascending: bool) -> Ordering {
    let ordered = match (a, b) {
        (SortKey::Empty, SortKey::Empty) => return Ordering::Equal,
        (SortKey::Empty, _) => return Ordering::Greater,
        (_, SortKey::Empty) => return Ordering::Less,
        (SortKey::Num(x), SortKey::Num(y)) => x.total_cmp(y),
        (SortKey::Text(x), SortKey::Text(y)) => x.cmp(y),
        (SortKey::Num(_), SortKey::Text(_)) => Ordering::Less,
        (SortKey::Text(_), SortKey::Num(_)) => Ordering::Greater,
    };
    if ascending { ordered } else { ordered.reverse() }
}

fn cell_ui(ui: &mut egui::Ui, cell: &Cell) {
    let mut rich = RichText::new(&cell.text);
    if cell.mono {
        rich = rich.monospace();
    }
    if cell.strong {
        rich = rich.strong();
    }
    if let Some(c) = cell.color {
        rich = rich.color(c);
    }
    ui.add(egui::Label::new(rich).truncate().selectable(false));
}

/// One sortable, selectable table. Rows are drawn lazily, so thousands are fine.
#[allow(clippy::too_many_arguments)]
fn render_table(
    ui: &mut egui::Ui,
    spec: &Spec,
    cols: &[usize],
    rows: &[&Row],
    sort: (usize, bool),
    marked: &HashSet<Selection>,
    scroll_to: Option<usize>,
    menu: &dyn Fn(&mut egui::Ui, &Selection) -> Option<RowAction>,
) -> TableOutput {
    let mut out = TableOutput::default();
    let mut builder = TableBuilder::new(ui)
        .id_salt(spec.id)
        .striped(true)
        .resizable(true)
        .sense(egui::Sense::click())
        .auto_shrink(false)
        .max_scroll_height(f32::INFINITY);
    if let Some(row) = scroll_to {
        builder = builder.scroll_to_row(row, None);
    }
    for &i in cols {
        builder = builder.column(spec.columns[i].1);
    }
    builder
        .header(ROW_HEIGHT + 2.0, |mut header| {
            for &i in cols {
                let title = spec.columns[i].0;
                header.col(|ui| {
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 3.0;
                        let button = egui::Button::new(RichText::new(title).strong()).frame(false);
                        let response = ui.add(button).on_hover_text("Click to sort; right-click to choose columns");
                        if response.clicked() {
                            out.sort_clicked = Some(i);
                        }
                        response.context_menu(|ui| {
                            if let Some(action) = columns_menu(ui, spec, cols) {
                                out.action = Some(action);
                                ui.close();
                            }
                        });
                        // Arrows exist only in the bundled monospace font.
                        if sort.0 == i {
                            ui.label(RichText::new(if sort.1 { "↑" } else { "↓" }).monospace().strong());
                        }
                    });
                });
            }
        })
        .body(|body| {
            body.rows(ROW_HEIGHT, rows.len(), |mut table_row| {
                let row = rows[table_row.index()];
                table_row.set_selected(marked.contains(&row.key));
                for &i in cols {
                    if let Some(cell) = row.cells.get(i) {
                        table_row.col(|ui| cell_ui(ui, cell));
                    }
                }
                let response = table_row.response();
                if response.clicked() || response.secondary_clicked() {
                    let modifiers = response.ctx.input(|i| i.modifiers);
                    out.clicked = Some((row.key.clone(), modifiers, response.secondary_clicked()));
                }
                response.context_menu(|ui| {
                    let chosen = menu(ui, &row.key).or_else(|| {
                        ui.separator();
                        columns_menu(ui, spec, cols)
                    });
                    if let Some(action) = chosen {
                        out.action = Some(action);
                        ui.close();
                    }
                });
            });
        });
    out
}

fn open_location(path: &str) -> Result<(), String> {
    use std::os::windows::process::CommandExt;
    if !std::path::Path::new(path).exists() {
        return Err(format!("{path} does not exist or is not accessible"));
    }
    std::process::Command::new("explorer.exe")
        .raw_arg(format!("/select,\"{path}\""))
        .spawn()
        .map(|_| ())
        .map_err(|e| format!("Cannot start Explorer: {e}"))
}

fn open_folder(path: &std::path::Path) -> Result<(), String> {
    std::fs::create_dir_all(path).map_err(|e| format!("Cannot create {}: {e}", path.display()))?;
    std::process::Command::new("explorer.exe")
        .arg(path)
        .spawn()
        .map(|_| ())
        .map_err(|e| format!("Cannot start Explorer: {e}"))
}

struct SaveJob {
    result: Receiver<Option<PathBuf>>,
    contents: Vec<u8>,
}

pub struct Dashboard {
    ctx: egui::Context,
    worker: Worker,
    data: DataDir,
    settings: Settings,
    saved_settings: Settings,
    windows_dir: String,
    exe: Option<PathBuf>,
    autostart: Option<String>,

    // Data
    integrity: Option<IntegrityReport>,
    process_scan: Option<ProcessReport>,
    /// Persistence, module and ntdll-sweep results by log kind.
    reports: HashMap<&'static str, ScanReport>,
    live: Option<ProcessSnapshot>,
    inventory: Option<SystemInventory>,
    proc_details: Option<ProcessDetails>,
    details_requested: Option<u32>,

    // Scheduling
    pending_scans: usize,
    current: Option<&'static str>,
    live_outstanding: bool,
    inventory_outstanding: bool,
    last_scheduled: Instant,
    last_live: Instant,
    last_inventory: Instant,

    // New-finding tracking
    known: HashMap<&'static str, HashSet<String>>,
    new_keys: HashSet<String>,
    alert: Option<String>,
    request_attention: bool,

    // View state
    tab: Tab,
    /// Row whose details are shown (the last one clicked or moved to).
    selected: Option<Selection>,
    /// All selected rows, for copy, export and bulk actions.
    marked: HashSet<Selection>,
    /// Where a Shift range starts.
    anchor: Option<Selection>,
    /// Row index to scroll into view in the selection's table this frame.
    scroll_to: Option<usize>,
    pending_rows_op: Option<RowsOp>,
    /// Messages from helper threads (hashing for VirusTotal).
    notes_tx: std::sync::mpsc::Sender<String>,
    notes_rx: Receiver<String>,
    filter: String,
    min_severity: Severity,
    flagged_only: bool,
    sorts: HashMap<&'static str, (usize, bool)>,
    activity: Vec<(u64, String)>,
    show_about: bool,
    show_help: bool,
    confirm_archive: bool,
    confirm: Option<Confirm>,
    quarantine: Vec<QuarantineEntry>,
    has_baseline: bool,
    save_job: Option<SaveJob>,
    start_minimized: bool,
    last_ctx_zoom: f32,
    tray: Option<crate::tray::Tray>,
    /// Hidden to the notification area.
    hidden: bool,
}

impl Dashboard {
    pub fn new(cc: &eframe::CreationContext<'_>, data: DataDir, start_minimized: bool) -> Self {
        let ctx = cc.egui_ctx.clone();
        let (settings, warning) = Settings::load(&data);
        ctx.set_theme(if settings.light_theme { egui::Theme::Light } else { egui::Theme::Dark });
        let last_ctx_zoom = ctx.zoom_factor();
        ctx.set_zoom_factor(settings.zoom);
        let repaint = ctx.clone();
        let worker = Worker::spawn(data.clone(), move || repaint.request_repaint());
        let mut known = HashMap::new();
        for kind in ["integrity", "processes"].into_iter().chain(EXTRA_SCANS.map(|(k, _)| k)) {
            if let Some(findings) = data.last_logged(kind) {
                known.insert(kind, stable_keys(&findings));
            }
        }
        let long_ago = Instant::now().checked_sub(Duration::from_secs(3600)).unwrap_or_else(Instant::now);
        let mut sorts = HashMap::new();
        sorts.insert("findings", (0, false));
        sorts.insert("processes", (0, false));
        for (table, (column, ascending)) in &settings.sorts {
            if let Some(spec) = Self::spec_for(table)
                && let Some(i) = spec.columns.iter().position(|(t, _)| t == column)
            {
                sorts.insert(spec.id, (i, *ascending));
            }
        }
        let tab = Tab::ALL.into_iter().find(|t| t.label() == settings.last_tab).unwrap_or(Tab::Processes);
        let (notes_tx, notes_rx) = channel();
        let quarantined = quarantine::list(&data);
        let mut app = Dashboard {
            ctx,
            worker,
            has_baseline: data.has_baseline(),
            data,
            saved_settings: settings.clone(),
            settings,
            windows_dir: format!("{}\\", windows_directory().unwrap_or_else(|| "C:\\Windows".into()).to_lowercase()),
            exe: std::env::current_exe().ok(),
            autostart: autostart::registered_command().ok().flatten(),
            integrity: None,
            process_scan: None,
            reports: HashMap::new(),
            live: None,
            inventory: None,
            proc_details: None,
            details_requested: None,
            pending_scans: 0,
            current: None,
            live_outstanding: false,
            inventory_outstanding: false,
            last_scheduled: Instant::now(),
            last_live: long_ago,
            last_inventory: long_ago,
            known,
            new_keys: HashSet::new(),
            alert: None,
            request_attention: false,
            tab,
            selected: None,
            marked: HashSet::new(),
            anchor: None,
            scroll_to: None,
            pending_rows_op: None,
            notes_tx,
            notes_rx,
            filter: String::new(),
            min_severity: Severity::Info,
            flagged_only: false,
            sorts,
            activity: Vec::new(),
            show_about: false,
            show_help: false,
            confirm_archive: false,
            confirm: None,
            quarantine: quarantined,
            save_job: None,
            start_minimized,
            last_ctx_zoom,
            tray: None,
            hidden: false,
        };
        match crate::tray::Tray::new(&app.ctx) {
            Ok(tray) => app.tray = Some(tray),
            Err(e) => app.note(format!("Notification-area icon unavailable: {e}")),
        }
        if let Some(w) = warning {
            app.note(w);
        }
        app.note(format!("Data folder: {}", app.data.root.display()));
        if app.settings.scan_on_open {
            app.scan_all();
        }
        app
    }

    fn note(&mut self, message: impl Into<String>) {
        self.activity.push((now_unix(), message.into()));
        if self.activity.len() > 2000 {
            self.activity.drain(..500);
        }
    }

    fn send(&mut self, command: Command) {
        if self.worker.send(command) {
            self.pending_scans += 1;
        } else {
            self.note("The scan thread has stopped; restart the dashboard.");
        }
    }

    fn scan_all(&mut self) {
        self.send(Command::ScanIntegrity { compare_memory: self.settings.compare_memory });
        self.send(Command::ScanProcesses);
        if self.settings.deep_scans {
            self.send(Command::SweepNtdll);
            self.send(Command::ScanModules);
            self.send(Command::ScanPersistence);
        }
        self.last_scheduled = Instant::now();
    }

    fn refresh_now(&mut self) {
        self.last_live = Instant::now().checked_sub(Duration::from_secs(3600)).unwrap_or_else(Instant::now);
        self.last_inventory = self.last_live;
    }

    // ----------------------------------------------------------------- events

    fn drain_events(&mut self) {
        while let Ok(event) = self.worker.events.try_recv() {
            match event {
                Event::Started(what) => self.current = Some(what),
                Event::Finished => {
                    self.pending_scans = self.pending_scans.saturating_sub(1);
                    if self.pending_scans == 0 {
                        self.current = None;
                    }
                }
                Event::Integrity(r) => {
                    self.note(format!(
                        "ntdll scan: {} finding(s), {} at Medium or above, {} ms",
                        r.findings.len(),
                        r.findings.iter().filter(|f| f.severity >= Severity::Medium).count(),
                        r.duration_ms
                    ));
                    self.track_new("integrity", integrity_monitor::MODULE, &r.findings);
                    self.integrity = Some(r);
                }
                Event::Processes(r) => {
                    self.note(format!(
                        "Process scan: {} processes, {} finding(s), {} ms",
                        r.processes.len(),
                        r.findings.len(),
                        r.duration_ms
                    ));
                    self.track_new("processes", process_inventory::MODULE, &r.findings);
                    self.process_scan = Some(r);
                }
                Event::Report(r) => {
                    self.note(format!("{} ({} ms)", r.summary, r.duration_ms));
                    if let Some(&(kind, module)) = EXTRA_SCANS.iter().find(|(k, _)| *k == r.kind) {
                        self.track_new(kind, module, &r.findings);
                        self.reports.insert(kind, r);
                    }
                }
                Event::BaselineCaptured(Ok(o)) => {
                    self.note(format!("Baseline captured in {}", o.directory.display()));
                    for f in &o.findings {
                        self.note(format!("[{}] {}: {}", f.severity.label(), f.title, f.detail));
                    }
                    self.has_baseline = true;
                    self.send(Command::ScanIntegrity { compare_memory: self.settings.compare_memory });
                }
                Event::BaselineCaptured(Err(e)) => self.note(format!("Baseline not captured: {e}")),
                Event::BaselineArchived(Ok(p)) => {
                    self.note(format!("Baseline archived to {p}"));
                    self.has_baseline = self.data.has_baseline();
                }
                Event::BaselineArchived(Err(e)) => self.note(format!("Archive failed: {e}")),
                Event::LogError(e) => self.note(format!("Log write failed: {e}")),
                Event::ActionDone { ok, message } => {
                    self.note(if ok { message } else { format!("Action failed: {message}") });
                    self.quarantine = quarantine::list(&self.data);
                    self.refresh_now();
                }
                Event::Live(result) => {
                    self.live_outstanding = false;
                    match result {
                        Ok(snapshot) => self.live = Some(snapshot),
                        Err(e) => self.note(format!("Live refresh failed: {e}")),
                    }
                }
                Event::Inventory(inv) => {
                    self.inventory_outstanding = false;
                    for e in &inv.errors {
                        self.note(e.clone());
                    }
                    self.inventory = Some(inv);
                }
                Event::ProcessDetails(details) => {
                    if self.details_requested == Some(details.pid) {
                        self.proc_details = Some(details);
                    }
                }
            }
        }
    }

    /// Marks findings that were not in the previous scan of the same kind (the
    /// previous scan may be from an earlier session, read from the log).
    fn track_new(&mut self, kind: &'static str, module: &str, findings: &[Finding]) {
        let current = stable_keys(findings);
        let previous = self.known.insert(kind, current);
        let prefix = format!("{module}|");
        self.new_keys.retain(|k| !k.starts_with(&prefix));
        let Some(previous) = previous else { return };
        let fresh: Vec<&Finding> = findings
            .iter()
            .filter(|f| f.severity >= Severity::Low && !previous.contains(&f.stable_key()))
            .collect();
        if fresh.is_empty() {
            return;
        }
        self.new_keys.extend(fresh.iter().map(|f| f.stable_key()));
        self.note(format!("{} new finding(s) since the previous {kind} scan", fresh.len()));
        let alerting: Vec<&&Finding> = fresh.iter().filter(|f| f.severity >= self.settings.alert_min_severity).collect();
        if self.settings.alert_on_new && !alerting.is_empty() {
            let worst = alerting.iter().map(|f| f.severity).max().unwrap_or(Severity::Info);
            self.alert = Some(format!(
                "{} new finding(s) at {} or above: {}",
                alerting.len(),
                self.settings.alert_min_severity.label(),
                alerting.iter().take(3).map(|f| format!("[{}] {}", f.severity.label(), f.title)).collect::<Vec<_>>().join("; ")
            ));
            self.note(format!("Alert raised (worst: {})", worst.label()));
            self.request_attention = true;
        }
        if self.settings.event_log {
            let to_log: Vec<&Finding> = fresh.iter().copied().filter(|f| f.severity >= self.settings.event_log_min_severity).collect();
            match eventlog::write(&to_log) {
                Ok(0) => {}
                Ok(n) => self.note(format!("Wrote {n} finding(s) to the Application event log")),
                Err(e) => self.note(e),
            }
        }
    }

    fn poll_save(&mut self) {
        let Some(job) = &self.save_job else { return };
        match job.result.try_recv() {
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => {
                self.save_job = None;
                self.note("The Save dialog closed unexpectedly.");
            }
            Ok(None) => {
                self.save_job = None;
                self.note("Export cancelled.");
            }
            Ok(Some(path)) => {
                let job = self.save_job.take().unwrap();
                match std::fs::write(&path, &job.contents) {
                    Ok(()) => self.note(format!("Exported {} ({} bytes)", path.display(), job.contents.len())),
                    Err(e) => self.note(format!("Cannot write {}: {e}", path.display())),
                }
            }
        }
    }

    // ------------------------------------------------------------------- rows

    fn all_findings(&self) -> Vec<&Finding> {
        let mut all: Vec<&Finding> = self
            .integrity
            .iter()
            .flat_map(|r| &r.findings)
            .chain(self.process_scan.iter().flat_map(|r| &r.findings))
            .chain(EXTRA_SCANS.iter().filter_map(|(k, _)| self.reports.get(k)).flat_map(|r| &r.findings))
            .collect();
        all.sort_by_key(|f| std::cmp::Reverse(f.severity));
        all
    }

    fn findings_spec() -> Spec {
        Spec {
            id: "findings",
            columns: vec![
                ("Severity", Column::exact(66.0)),
                ("New", Column::exact(40.0)),
                ("Module", Column::initial(110.0)),
                ("Subject", Column::initial(170.0)),
                ("Finding", Column::initial(320.0)),
                ("RVA", Column::initial(80.0)),
                ("Expected", Column::initial(130.0)),
                ("Observed", Column::initial(130.0)),
                ("Detail", Column::remainder()),
            ],
        }
    }

    fn finding_rows(&self) -> Vec<Row> {
        self.all_findings()
            .into_iter()
            .filter(|f| f.severity >= self.min_severity)
            .map(|f| {
                let new = self.new_keys.contains(&f.stable_key());
                Row::new(
                    Selection::Finding(f.row_key()),
                    vec![
                        Cell::severity(Some(f.severity)),
                        if new { Cell::num("NEW", 1.0).colored(Color32::from_rgb(90, 170, 255)) } else { Cell::empty() },
                        Cell::text(&f.module),
                        Cell::text(&f.subject),
                        Cell::text(&f.title),
                        f.offset.map_or_else(Cell::empty, |o| Cell::num(format!("0x{o:X}"), o as f64).mono()),
                        Cell::text(f.expected.clone().unwrap_or_default()).mono(),
                        Cell::text(f.observed.clone().unwrap_or_default()).mono(),
                        Cell::text(&f.detail),
                    ],
                )
            })
            .collect()
    }

    fn tab_spec(tab: Tab) -> Spec {
        let service_columns = |first: &'static str| {
            vec![
                ("Flag", Column::exact(66.0)),
                (first, Column::initial(170.0)),
                ("Display name", Column::initial(240.0)),
                ("State", Column::initial(80.0)),
                ("Start", Column::initial(80.0)),
                ("PID", Column::initial(60.0)),
                ("Image path", Column::remainder()),
            ]
        };
        match tab {
            Tab::Processes => Spec {
                id: "processes",
                columns: vec![
                    ("Flag", Column::exact(66.0)),
                    ("PID", Column::initial(60.0)),
                    ("Name", Column::initial(180.0)),
                    ("CPU %", Column::initial(56.0)),
                    ("Memory", Column::initial(80.0)),
                    ("Threads", Column::initial(60.0)),
                    ("Session", Column::initial(60.0)),
                    ("User", Column::initial(150.0)),
                    ("Started", Column::initial(150.0)),
                    ("Location", Column::initial(100.0)),
                    ("Signature", Column::initial(240.0)),
                    ("Command line", Column::initial(320.0)),
                    ("Image path", Column::remainder()),
                ],
            },
            Tab::Services => Spec { id: "services", columns: service_columns("Service") },
            Tab::Drivers => Spec { id: "drivers", columns: service_columns("Driver") },
            Tab::Startup => Spec {
                id: "startup",
                columns: vec![
                    ("Flag", Column::exact(66.0)),
                    ("Location", Column::initial(320.0)),
                    ("Name", Column::initial(200.0)),
                    ("Command", Column::remainder()),
                ],
            },
            Tab::Quarantine => Spec {
                id: "quarantine",
                columns: vec![
                    ("Quarantined", Column::initial(170.0)),
                    ("File", Column::initial(180.0)),
                    ("Original path", Column::initial(360.0)),
                    ("Size", Column::initial(80.0)),
                    ("Process", Column::initial(180.0)),
                    ("SHA-256", Column::remainder()),
                ],
            },
            Tab::Connections => Spec {
                id: "connections",
                columns: vec![
                    ("Protocol", Column::initial(70.0)),
                    ("Local address", Column::initial(200.0)),
                    ("Remote address", Column::initial(200.0)),
                    ("State", Column::initial(110.0)),
                    ("PID", Column::initial(60.0)),
                    ("Process", Column::remainder()),
                ],
            },
        }
    }

    fn records_by_pid(&self) -> HashMap<u32, &ProcessRecord> {
        self.process_scan.iter().flat_map(|r| r.processes.iter().map(|p| (p.pid, p))).collect()
    }

    fn process_name(&self, pid: u32) -> Option<String> {
        if let Some(live) = &self.live {
            return live.processes.iter().find(|p| p.identity.pid == pid).map(|p| p.name.clone());
        }
        self.process_scan.as_ref()?.processes.iter().find(|p| p.pid == pid).map(|p| p.name.clone())
    }

    fn is_system(&self, pid: u32, path: &str) -> bool {
        pid == 0 || pid == 4 || path.is_empty() || path.to_lowercase().starts_with(&self.windows_dir)
    }

    /// Highest finding severity per subject (for the Flag columns).
    fn subject_flags(&self) -> HashMap<String, Severity> {
        let mut flags: HashMap<String, Severity> = HashMap::new();
        for f in self.all_findings() {
            let entry = flags.entry(f.subject.clone()).or_insert(f.severity);
            *entry = (*entry).max(f.severity);
        }
        flags
    }

    fn pid_flags(&self) -> HashMap<u32, Severity> {
        let mut flags: HashMap<u32, Severity> = HashMap::new();
        for f in self.all_findings().into_iter().filter(|f| f.severity >= Severity::Low) {
            if let Some(pid) = f.pid() {
                let entry = flags.entry(pid).or_insert(f.severity);
                *entry = (*entry).max(f.severity);
            }
        }
        flags
    }

    fn process_row(&self, pid: u32, live: Option<&ProcessInfo>, record: Option<&ProcessRecord>, pid_flags: &HashMap<u32, Severity>) -> Row {
        let name = live.map(|p| p.name.clone()).or_else(|| record.map(|r| r.name.clone())).unwrap_or_default();
        let path = live
            .map(|p| p.path.clone())
            .filter(|p| !p.is_empty())
            .or_else(|| record.and_then(|r| r.path.clone()))
            .unwrap_or_default();
        let path_shown = if path.is_empty() {
            record.and_then(|r| r.path_error.clone()).map(|e| format!("({e})")).unwrap_or_default()
        } else {
            path.clone()
        };
        let severity = record.and_then(|r| r.max_severity).max(pid_flags.get(&pid).copied());
        let accessible = live.is_some_and(|p| p.accessible);
        let signature = match record {
            Some(r) => r.signature.as_ref().map(|s| s.summary()).unwrap_or_default(),
            None if !path.is_empty() => "pending next process scan".into(),
            None => String::new(),
        };
        let cells = vec![
            Cell::severity(severity),
            Cell::num(pid.to_string(), f64::from(pid)),
            Cell::text(&name),
            if accessible { live.map_or_else(Cell::empty, |p| Cell::num(format!("{:.1}", p.cpu_percent), p.cpu_percent)) } else { Cell::empty() },
            if accessible { live.map_or_else(Cell::empty, |p| Cell::num(format_bytes(p.memory_bytes), p.memory_bytes as f64)) } else { Cell::empty() },
            live.map_or_else(Cell::empty, |p| Cell::num(p.thread_count.to_string(), f64::from(p.thread_count))),
            live.filter(|p| p.session_id != u32::MAX)
                .map_or_else(Cell::empty, |p| Cell::num(p.session_id.to_string(), f64::from(p.session_id))),
            Cell::text(live.map(|p| p.user.clone()).unwrap_or_default()),
            live.and_then(|p| ntsentry::system::filetime_to_unix(p.identity.creation_time))
                .map_or_else(Cell::empty, |t| Cell::num(format_utc(t), t as f64)),
            Cell::text(record.and_then(|r| r.path_class).map_or("", |c| c.label())),
            Cell::text(signature),
            Cell::text(live.map(|p| p.command_line.clone()).unwrap_or_default()),
            Cell::text(path_shown),
        ];
        Row { key: Selection::Process(pid), cells, system: self.is_system(pid, &path), severity }
    }

    fn tab_rows(&self, tab: Tab) -> Vec<Row> {
        match tab {
            Tab::Processes => {
                let records = self.records_by_pid();
                let flags = self.pid_flags();
                // (row, parent pid, creation time) for the optional tree layout.
                let mut entries: Vec<(Row, u32, u64)> = match (&self.live, &self.process_scan) {
                    (Some(live), _) => live
                        .processes
                        .iter()
                        .map(|p| {
                            let row = self.process_row(p.identity.pid, Some(p), records.get(&p.identity.pid).copied(), &flags);
                            (row, p.parent_pid, p.identity.creation_time)
                        })
                        .collect(),
                    (None, Some(scan)) => scan
                        .processes
                        .iter()
                        .map(|r| (self.process_row(r.pid, None, Some(r), &flags), r.parent_pid, r.created_filetime.unwrap_or(0)))
                        .collect(),
                    (None, None) => Vec::new(),
                };
                entries.sort_by(|a, b| a.0.cells[2].text.to_lowercase().cmp(&b.0.cells[2].text.to_lowercase()));
                if self.settings.process_tree { tree_order(entries) } else { entries.into_iter().map(|e| e.0).collect() }
            }
            Tab::Services | Tab::Drivers => {
                let Some(inv) = &self.inventory else { return Vec::new() };
                let flags = self.subject_flags();
                let list = if tab == Tab::Services { &inv.services } else { &inv.drivers };
                list.iter()
                    .map(|s| {
                        let (key, kind) = if tab == Tab::Services {
                            (Selection::Service(s.name.clone()), EntryKind::Service)
                        } else {
                            (Selection::Driver(s.name.clone()), EntryKind::Driver)
                        };
                        let severity = flags.get(&persistence_audit::subject(kind, &s.name, "")).copied();
                        let mut row = Row::new(
                            key,
                            vec![
                                Cell::severity(severity),
                                Cell::text(&s.name),
                                Cell::text(&s.display_name),
                                Cell::text(&s.state),
                                Cell::text(&s.start_type),
                                if s.pid == 0 { Cell::empty() } else { Cell::num(s.pid.to_string(), f64::from(s.pid)) },
                                Cell::text(&s.binary_path),
                            ],
                        );
                        row.severity = severity;
                        row
                    })
                    .collect()
            }
            Tab::Startup => {
                let Some(inv) = &self.inventory else { return Vec::new() };
                let flags = self.subject_flags();
                inv.startup
                    .iter()
                    .map(|a| {
                        let severity = flags.get(&persistence_audit::subject(EntryKind::Startup, &a.name, &a.location)).copied();
                        let mut row = Row::new(
                            Selection::Startup(format!("{}|{}|{}", a.location, a.name, a.command)),
                            vec![Cell::severity(severity), Cell::text(&a.location), Cell::text(&a.name), Cell::text(&a.command)],
                        );
                        row.severity = severity;
                        row
                    })
                    .collect()
            }
            Tab::Quarantine => self
                .quarantine
                .iter()
                .map(|q| {
                    let file = q.original_path.rsplit('\\').next().unwrap_or(&q.original_path).to_string();
                    Row::new(
                        Selection::Quarantined(q.id.clone()),
                        vec![
                            Cell::num(format_utc(q.quarantined_unix), q.quarantined_unix as f64),
                            Cell::text(file),
                            Cell::text(&q.original_path),
                            Cell::num(format_bytes(q.size), q.size as f64),
                            Cell::text(&q.process),
                            Cell::text(&q.sha256).mono(),
                        ],
                    )
                })
                .collect(),
            Tab::Connections => {
                let Some(inv) = &self.inventory else { return Vec::new() };
                let names: HashMap<u32, String> = match &self.live {
                    Some(l) => l.processes.iter().map(|p| (p.identity.pid, p.name.clone())).collect(),
                    None => self.records_by_pid().into_iter().map(|(pid, r)| (pid, r.name.clone())).collect(),
                };
                inv.connections
                    .iter()
                    .map(|c| {
                        Row::new(
                            Selection::Connection(connection_key(c)),
                            vec![
                                Cell::text(&c.protocol),
                                Cell::text(&c.local_address).mono(),
                                Cell::text(&c.remote_address).mono(),
                                Cell::text(&c.state),
                                Cell::num(c.pid.to_string(), f64::from(c.pid)),
                                Cell::text(names.get(&c.pid).cloned().unwrap_or_default()),
                            ],
                        )
                    })
                    .collect()
            }
        }
    }

    fn tab_count(&self, tab: Tab) -> usize {
        match tab {
            Tab::Processes => self
                .live
                .as_ref()
                .map(|l| l.processes.len())
                .or_else(|| self.process_scan.as_ref().map(|r| r.processes.len()))
                .unwrap_or(0),
            Tab::Services => self.inventory.as_ref().map_or(0, |i| i.services.len()),
            Tab::Drivers => self.inventory.as_ref().map_or(0, |i| i.drivers.len()),
            Tab::Startup => self.inventory.as_ref().map_or(0, |i| i.startup.len()),
            Tab::Connections => self.inventory.as_ref().map_or(0, |i| i.connections.len()),
            Tab::Quarantine => self.quarantine.len(),
        }
    }

    /// Applies Find text and the system/flagged filters, then sorts (except in tree view).
    fn visible<'a>(&self, spec_id: &'static str, rows: &'a [Row], tab: Option<Tab>) -> Vec<&'a Row> {
        let needle = self.filter.trim().to_lowercase();
        let processes = tab == Some(Tab::Processes);
        let flaggable = matches!(tab, Some(Tab::Processes | Tab::Services | Tab::Drivers | Tab::Startup));
        let mut visible: Vec<&Row> = rows
            .iter()
            .filter(|r| !processes || !self.settings.hide_system_processes || !r.system)
            .filter(|r| !flaggable || !self.flagged_only || r.severity.is_some_and(|s| s >= self.min_severity))
            .filter(|r| needle.is_empty() || r.cells.iter().any(|c| c.text.to_lowercase().contains(&needle)))
            .collect();
        if processes && self.settings.process_tree {
            return visible;
        }
        if let Some(&(column, ascending)) = self.sorts.get(spec_id) {
            visible.sort_by(|a, b| match (a.cells.get(column), b.cells.get(column)) {
                (Some(x), Some(y)) => compare_keys(&x.sort, &y.sort, ascending),
                _ => Ordering::Equal,
            });
        }
        visible
    }

    /// Identity, name, path and signature summary of a running process.
    fn process_target(&self, pid: u32) -> Option<(ProcessIdentity, String, String, String)> {
        let records = self.records_by_pid();
        let record = records.get(&pid);
        let signature = record.and_then(|r| r.signature.as_ref()).map(|s| s.summary()).unwrap_or_else(|| "not checked".into());
        if let Some(p) = self.live.as_ref().and_then(|l| l.processes.iter().find(|p| p.identity.pid == pid)) {
            let path = if p.path.is_empty() { record.and_then(|r| r.path.clone()).unwrap_or_default() } else { p.path.clone() };
            return Some((p.identity, p.name.clone(), path, signature));
        }
        let r = record?;
        let identity = ProcessIdentity { pid, creation_time: r.created_filetime? };
        Some((identity, r.name.clone(), r.path.clone().unwrap_or_default(), signature))
    }

    /// Running targets for the PIDs; notes any that are gone.
    fn process_targets_for(&mut self, pids: &[u32]) -> Vec<(ProcessIdentity, String, String, String)> {
        let mut targets = Vec::new();
        for &pid in pids {
            match self.process_target(pid) {
                Some(t) => targets.push(t),
                None => self.note(format!("Process {pid} is no longer in the list; skipped.")),
            }
        }
        targets
    }

    /// PIDs a process action on `selection` applies to: every selected process
    /// when the row is part of a multi-selection, else just that one.
    fn action_pids(&self, selection: &Selection) -> Vec<u32> {
        let Selection::Process(pid) = selection else { return Vec::new() };
        let mut marked: Vec<u32> = self
            .marked
            .iter()
            .filter_map(|s| if let Selection::Process(p) = s { Some(*p) } else { None })
            .collect();
        if marked.len() > 1 && self.marked.contains(selection) {
            marked.sort_unstable();
            marked
        } else {
            vec![*pid]
        }
    }

    fn apply_row_action(&mut self, action: RowAction) {
        let action_kind = match action {
            RowAction::Suspend(_) => ActionKind::Suspend,
            _ => ActionKind::Other,
        };
        match action {
            RowAction::Rows(op) => self.pending_rows_op = Some(op),
            RowAction::ToggleColumn(table, column) => {
                let hidden = self.settings.hidden_columns.entry(table.to_string()).or_default();
                match hidden.iter().position(|c| c == column) {
                    Some(i) => {
                        hidden.remove(i);
                    }
                    None => hidden.push(column.to_string()),
                }
            }
            RowAction::ShowAllColumns(table) => {
                self.settings.hidden_columns.insert(table.to_string(), Vec::new());
            }
            RowAction::Properties(selection) => match self.selection_path(&selection) {
                Some(path) => {
                    if let Err(e) = ntsentry::system::open_file_properties(&path) {
                        self.note(e);
                    }
                }
                None => self.note("The selected item has no file to show properties for."),
            },
            RowAction::VirusTotal(selection) => self.virustotal(&selection),
            RowAction::EndTree(pids) => {
                let order = self.tree_end_order(&pids);
                let targets = self.process_targets_for(&order);
                if targets.is_empty() {
                    return;
                }
                let list = describe_targets(&targets, false);
                self.confirm = Some(Confirm {
                    title: format!("End {} process(es) in this tree?", targets.len()),
                    text: format!(
                        "{list}\n\nThe selected process and everything it started are stopped immediately, children first. \
                         Unsaved work in them is lost."
                    ),
                    button: "End tree",
                    actions: targets.into_iter().map(|(identity, name, _, _)| Action::End { identity, name }).collect(),
                });
            }
            RowAction::Details(selection) => self.select(selection),
            RowAction::Copy(selection) => {
                self.select(selection);
                self.copy_selection();
            }
            RowAction::OpenLocation(selection) => {
                self.select(selection);
                self.open_selection_location();
            }
            RowAction::End(pids) => {
                let targets = self.process_targets_for(&pids);
                if targets.is_empty() {
                    return;
                }
                let list = describe_targets(&targets, false);
                let title = match targets.as_slice() {
                    [(_, name, _, _)] => format!("End {name}?"),
                    _ => format!("End {} processes?", targets.len()),
                };
                self.confirm = Some(Confirm {
                    title,
                    text: format!("{list}\n\nStopped immediately. Unsaved work in them is lost."),
                    button: "End",
                    actions: targets.into_iter().map(|(identity, name, _, _)| Action::End { identity, name }).collect(),
                });
            }
            RowAction::Suspend(pids) | RowAction::Resume(pids) => {
                let suspend = matches!(action_kind, ActionKind::Suspend);
                let suspended: HashSet<u32> = ntsentry::system::suspended_processes().iter().map(|i| i.pid).collect();
                let wanted: Vec<u32> = pids.into_iter().filter(|p| suspended.contains(p) != suspend).collect();
                for (identity, name, _, _) in self.process_targets_for(&wanted) {
                    let act = if suspend { Action::Suspend { identity, name } } else { Action::Resume { identity, name } };
                    self.worker.send_live(LiveCommand::Act(act));
                }
            }
            RowAction::Quarantine(pids) => {
                let windows = windows_directory().unwrap_or_else(|| "C:\\Windows".into());
                let mut targets = Vec::new();
                for (identity, name, path, signature) in self.process_targets_for(&pids) {
                    if path.is_empty() {
                        self.note(format!("{name} (pid {}) has no accessible file path to quarantine; skipped.", identity.pid));
                    } else if let Some(reason) = quarantine::refusal(&path, &windows) {
                        self.note(format!("{name}: {reason}; skipped."));
                    } else {
                        targets.push((identity, name, path, signature));
                    }
                }
                if targets.is_empty() {
                    return;
                }
                let list = describe_targets(&targets, true);
                let title = match targets.as_slice() {
                    [(_, name, _, _)] => format!("End {name} and quarantine its file?"),
                    _ => format!("End {} processes and quarantine their files?", targets.len()),
                };
                self.confirm = Some(Confirm {
                    title,
                    text: format!(
                        "{list}\n\nEach process is ended and its file moved into quarantine (verified copy, original deleted). \
                         Restore from the Quarantine tab."
                    ),
                    button: "End and quarantine",
                    actions: targets
                        .into_iter()
                        .map(|(identity, name, path, signature)| Action::Quarantine { identity, name, path, signature })
                        .collect(),
                });
            }
            RowAction::Restore(id) => {
                let path = self.quarantine.iter().find(|q| q.id == id).map(|q| q.original_path.clone()).unwrap_or_default();
                self.confirm = Some(Confirm {
                    title: "Restore from quarantine?".into(),
                    text: format!("{path}\n\nThe file is written back to its original location. Nothing existing is overwritten."),
                    button: "Restore",
                    actions: vec![Action::Restore { id }],
                });
            }
        }
    }

    fn apply_table_output(&mut self, spec_id: &'static str, out: TableOutput, keys: &[&Selection]) {
        if let Some(column) = out.sort_clicked {
            let entry = self.sorts.entry(spec_id).or_insert((column, true));
            *entry = if entry.0 == column { (column, !entry.1) } else { (column, true) };
            let (column, ascending) = *entry;
            if let Some(spec) = Self::spec_for(spec_id) {
                self.settings.sorts.insert(spec_id.to_string(), (spec.columns[column].0.to_string(), ascending));
            }
        }
        if let Some((key, modifiers, secondary)) = out.clicked {
            self.click_row(key, modifiers, secondary, keys);
        }
        if let Some(action) = out.action {
            self.apply_row_action(action);
        }
    }

    /// Click: select one row. Ctrl+click: add or remove a row. Shift+click: select
    /// the range from the anchor. Right-click keeps a multi-selection that includes
    /// the row, so its menu acts on all of them.
    fn click_row(&mut self, key: Selection, modifiers: Modifiers, secondary: bool, keys: &[&Selection]) {
        let same_table = self.anchor.as_ref().is_some_and(|a| a.table() == key.table());
        if secondary {
            if self.marked.contains(&key) {
                self.focus(key);
            } else {
                self.select(key);
            }
        } else if modifiers.shift && same_table {
            let anchor = self.anchor.clone().unwrap();
            match range_between(keys, &anchor, &key) {
                Some(range) => {
                    self.marked = range.into_iter().collect();
                    self.focus(key);
                }
                None => self.select(key),
            }
        } else if modifiers.command && same_table {
            if !self.marked.remove(&key) {
                self.marked.insert(key.clone());
            }
            self.anchor = Some(key.clone());
            self.focus(key);
        } else {
            self.select(key);
        }
    }

    /// Selects exactly this row.
    fn select(&mut self, selection: Selection) {
        self.marked = HashSet::from([selection.clone()]);
        self.anchor = Some(selection.clone());
        self.focus(selection);
    }

    /// Shows this row's details without changing the multi-selection.
    fn focus(&mut self, selection: Selection) {
        if let Selection::Process(pid) = &selection {
            self.request_process_details(*pid);
        }
        self.selected = Some(selection);
    }

    fn clear_selection(&mut self) {
        self.selected = None;
        self.marked.clear();
        self.anchor = None;
    }

    /// Arrow keys, Home/End, PageUp/PageDown move the selection (Shift extends it),
    /// Ctrl+A selects every visible row, Ctrl+C copies. Returns a row to scroll to.
    fn keyboard_selection(&mut self, ui: &mut egui::Ui, rows: &[&Row]) -> Option<usize> {
        if ui.memory(|m| m.focused().is_some()) || self.confirm.is_some() {
            return None;
        }
        let (step, select_all, shift, copy) = ui.input_mut(|i| {
            let step = if i.key_pressed(Key::ArrowUp) {
                Some(-1)
            } else if i.key_pressed(Key::ArrowDown) {
                Some(1)
            } else if i.key_pressed(Key::PageUp) {
                Some(-20)
            } else if i.key_pressed(Key::PageDown) {
                Some(20)
            } else if i.key_pressed(Key::Home) {
                Some(isize::MIN)
            } else if i.key_pressed(Key::End) {
                Some(isize::MAX)
            } else {
                None
            };
            let all = i.consume_shortcut(&KeyboardShortcut::new(Modifiers::COMMAND, Key::A));
            (step, all, i.modifiers.shift, i.events.iter().any(|e| matches!(e, egui::Event::Copy)))
        });
        if select_all {
            self.pending_rows_op = Some(RowsOp::SelectAll);
        }
        if copy {
            self.pending_rows_op = Some(RowsOp::Copy);
        }
        let step = step?;
        let keys: Vec<&Selection> = rows.iter().map(|r| &r.key).collect();
        if keys.is_empty() {
            return None;
        }
        let last = keys.len() - 1;
        let current = self.selected.as_ref().and_then(|s| keys.iter().position(|k| *k == s));
        let next = match (current, step) {
            (_, isize::MIN) => 0,
            (_, isize::MAX) => last,
            (None, _) => 0,
            (Some(c), s) => (c as isize + s).clamp(0, last as isize) as usize,
        };
        let key = keys[next].clone();
        if shift {
            let anchor = self
                .anchor
                .clone()
                .filter(|a| keys.contains(&a))
                .unwrap_or_else(|| keys[current.unwrap_or(next)].clone());
            if let Some(range) = range_between(&keys, &anchor, &key) {
                self.marked = range.into_iter().collect();
            }
            self.anchor = Some(anchor);
            self.focus(key);
        } else {
            self.select(key);
        }
        Some(next)
    }

    /// The PIDs and all their descendants, children before parents. A "parent"
    /// that started after its child is a reused PID and is not followed.
    fn tree_end_order(&self, roots: &[u32]) -> Vec<u32> {
        let Some(live) = &self.live else { return roots.to_vec() };
        let created: HashMap<u32, u64> = live.processes.iter().map(|p| (p.identity.pid, p.identity.creation_time)).collect();
        let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
        for p in &live.processes {
            let (pid, parent) = (p.identity.pid, p.parent_pid);
            let genuine = created.get(&parent).is_some_and(|&pc| pc == 0 || p.identity.creation_time == 0 || pc <= p.identity.creation_time);
            if pid != parent && pid != 0 && genuine {
                children.entry(parent).or_default().push(pid);
            }
        }
        let mut order = Vec::new();
        let mut seen = HashSet::new();
        fn visit(pid: u32, children: &HashMap<u32, Vec<u32>>, seen: &mut HashSet<u32>, order: &mut Vec<u32>) {
            if !seen.insert(pid) {
                return;
            }
            for &child in children.get(&pid).map(Vec::as_slice).unwrap_or(&[]) {
                visit(child, children, seen, order);
            }
            order.push(pid);
        }
        for &root in roots {
            visit(root, &children, &mut seen, &mut order);
        }
        order
    }

    /// Opens VirusTotal in the browser for the selection's file. The file is hashed
    /// on a helper thread; only the SHA-256 leaves the PC, inside the URL.
    fn virustotal(&mut self, selection: &Selection) {
        let open = |sha256: &str| {
            std::process::Command::new("explorer.exe")
                .arg(format!("https://www.virustotal.com/gui/file/{sha256}"))
                .spawn()
                .map(|_| ())
                .map_err(|e| format!("Cannot open the browser: {e}"))
        };
        if let Selection::Quarantined(id) = selection {
            if let Some(q) = self.quarantine.iter().find(|q| &q.id == id) {
                let sha = q.sha256.clone();
                match open(&sha) {
                    Ok(()) => self.note(format!("Opened VirusTotal for {} (SHA-256 {sha})", q.original_path)),
                    Err(e) => self.note(e),
                }
            }
            return;
        }
        let Some(path) = self.selection_path(selection) else {
            self.note("The selected item has no file to look up.");
            return;
        };
        self.note(format!("Hashing {path} for VirusTotal…"));
        let tx = self.notes_tx.clone();
        let ctx = self.ctx.clone();
        std::thread::spawn(move || {
            let message = match ntsentry::winutil::sha256_file(&path) {
                Ok(sha) => match open(&sha) {
                    Ok(()) => format!("Opened VirusTotal for {path} (SHA-256 {sha})"),
                    Err(e) => e,
                },
                Err(e) => e,
            };
            let _ = tx.send(message);
            ctx.request_repaint();
        });
    }

    /// Spec for a table id (findings or an inventory tab).
    fn spec_for(id: &str) -> Option<Spec> {
        if id == "findings" {
            return Some(Self::findings_spec());
        }
        Tab::ALL.into_iter().map(Self::tab_spec).find(|s| s.id == id)
    }

    fn cols_for(&self, spec: &Spec) -> Vec<usize> {
        visible_columns(spec, self.settings.hidden_columns.get(spec.id))
    }

    /// Select all / copy / export on the visible rows of the selection's table.
    fn run_rows_op(&mut self, op: RowsOp, spec: &Spec, rows: &[&Row]) {
        match op {
            RowsOp::SelectAll => {
                self.marked = rows.iter().map(|r| r.key.clone()).collect();
                self.anchor = rows.first().map(|r| r.key.clone());
                if self.selected.as_ref().is_none_or(|s| !self.marked.contains(s))
                    && let Some(first) = rows.first()
                {
                    self.focus(first.key.clone());
                }
                self.note(format!("Selected all {} rows", rows.len()));
            }
            RowsOp::Copy if self.marked.len() > 1 => {
                let cols = self.cols_for(spec);
                let (text, count) = rows_text(spec, &cols, rows, &self.marked);
                self.ctx.copy_text(text);
                self.note(format!("Copied {count} rows"));
            }
            RowsOp::Copy => self.copy_selection(),
            RowsOp::Export => {
                let cols = self.cols_for(spec);
                let selected: Vec<&Row> = rows.iter().copied().filter(|r| self.marked.contains(&r.key)).collect();
                let csv = export::csv(&shown_headers(spec, &cols), selected.iter().map(|r| shown_texts(r, &cols)));
                self.save_as("Export selected rows (CSV)", spec.id, ("CSV files", "*.csv"), "csv", csv.into_bytes());
            }
        }
    }

    fn request_process_details(&mut self, pid: u32) {
        if self.details_requested == Some(pid) {
            return;
        }
        let live = self.live.as_ref().and_then(|l| l.processes.iter().find(|p| p.identity.pid == pid));
        let identity = live.map_or(ProcessIdentity { pid, creation_time: 0 }, |p| p.identity);
        let path = live
            .map(|p| p.path.clone())
            .filter(|p| !p.is_empty())
            .or_else(|| self.records_by_pid().get(&pid).and_then(|r| r.path.clone()))
            .unwrap_or_default();
        self.details_requested = Some(pid);
        self.proc_details = None;
        self.worker.send_live(LiveCommand::ProcessDetails { identity, path });
    }

    // ---------------------------------------------------------------- details

    /// Title and label/value pairs describing the selection, or `None` if it vanished.
    fn selection_fields(&self, selection: &Selection) -> Option<(String, Vec<(&'static str, String)>)> {
        match selection {
            Selection::Finding(key) => {
                let f = self.all_findings().into_iter().find(|f| &f.row_key() == key)?;
                Some((
                    format!("{} finding", f.severity.label()),
                    vec![
                        ("Finding", f.title.clone()),
                        ("Severity", f.severity.label().into()),
                        ("New since previous scan", yes_no(self.new_keys.contains(&f.stable_key()))),
                        ("Module", f.module.clone()),
                        ("Subject", f.subject.clone()),
                        ("RVA", f.offset.map(|o| format!("0x{o:X}")).unwrap_or_default()),
                        ("Expected bytes", f.expected.clone().unwrap_or_default()),
                        ("Observed bytes", f.observed.clone().unwrap_or_default()),
                        ("Observed at", format_utc(f.observed_unix)),
                        ("Detail", f.detail.clone()),
                    ],
                ))
            }
            Selection::Process(pid) => {
                let live = self.live.as_ref().and_then(|l| l.processes.iter().find(|p| p.identity.pid == *pid));
                let records = self.records_by_pid();
                let record = records.get(pid).copied();
                if live.is_none() && record.is_none() {
                    return None;
                }
                let name = live.map(|p| p.name.clone()).or_else(|| record.map(|r| r.name.clone())).unwrap_or_default();
                let parent = live.map(|p| p.parent_pid).or_else(|| record.map(|r| r.parent_pid)).unwrap_or(0);
                let path = live
                    .map(|p| p.path.clone())
                    .filter(|p| !p.is_empty())
                    .or_else(|| record.and_then(|r| r.path.clone()))
                    .unwrap_or_default();
                let mut fields = vec![
                    ("Name", name.clone()),
                    ("PID", pid.to_string()),
                    ("Parent", format!("{parent} ({})", self.process_name(parent).unwrap_or_else(|| "not running".into()))),
                    ("Image path", if path.is_empty() { record.and_then(|r| r.path_error.clone()).unwrap_or_default() } else { path }),
                    ("Location", record.and_then(|r| r.path_class).map_or("", |c| c.label()).into()),
                    ("Signature", record.and_then(|r| r.signature.as_ref()).map(|s| s.summary()).unwrap_or_else(|| "not checked yet".into())),
                    ("Highest finding", record.and_then(|r| r.max_severity).map_or("none", |s| s.label()).into()),
                ];
                if let Some(p) = live.filter(|p| p.accessible) {
                    fields.push(("CPU", format!("{:.1} %", p.cpu_percent)));
                    fields.push(("Memory (working set)", format_bytes(p.memory_bytes)));
                }
                if let Some(p) = live {
                    fields.push(("Threads", p.thread_count.to_string()));
                    if p.session_id != u32::MAX {
                        fields.push(("Session", p.session_id.to_string()));
                    }
                    fields.push(("Critical process", yes_no(p.is_critical)));
                    fields.push(("User", p.user.clone()));
                    if let Some(t) = ntsentry::system::filetime_to_unix(p.identity.creation_time) {
                        fields.push(("Started", format_utc(t)));
                    }
                    fields.push(("Command line", p.command_line.clone()));
                }
                if let Some(d) = self.proc_details.as_ref().filter(|d| d.pid == *pid) {
                    match &d.file {
                        Ok(file) => {
                            fields.push(("Description", file.description.clone()));
                            fields.push(("Company", file.company.clone()));
                            fields.push(("Product", file.product_name.clone()));
                            fields.push(("File version", file.file_version.clone()));
                            fields.push(("File size", format_bytes(file.size_bytes)));
                            if let Some(m) = file.modified_unix_seconds {
                                fields.push(("Modified", format_utc(m)));
                            }
                        }
                        Err(e) => fields.push(("File details", e.clone())),
                    }
                }
                Some((format!("Process {name}"), fields))
            }
            Selection::Service(name) | Selection::Driver(name) => {
                let inv = self.inventory.as_ref()?;
                let driver = matches!(selection, Selection::Driver(_));
                let list = if driver { &inv.drivers } else { &inv.services };
                let s = list.iter().find(|s| &s.name == name)?;
                let mut fields = vec![
                    ("Name", s.name.clone()),
                    ("Display name", s.display_name.clone()),
                    ("State", s.state.clone()),
                    ("Start type", s.start_type.clone()),
                    ("Image path (as registered)", s.binary_path.clone()),
                    ("Resolved file", image_path_from_command(&s.binary_path).unwrap_or_default()),
                ];
                if s.pid != 0 {
                    fields.push(("PID", format!("{} ({})", s.pid, self.process_name(s.pid).unwrap_or_default())));
                }
                Some((format!("{} {}", if driver { "Driver" } else { "Service" }, s.name), fields))
            }
            Selection::Startup(key) => {
                let a = self
                    .inventory
                    .as_ref()?
                    .startup
                    .iter()
                    .find(|a| &format!("{}|{}|{}", a.location, a.name, a.command) == key)?;
                Some((
                    format!("Startup entry {}", a.name),
                    vec![
                        ("Name", a.name.clone()),
                        ("Location", a.location.clone()),
                        ("Command", a.command.clone()),
                        ("Resolved file", image_path_from_command(&a.command).unwrap_or_default()),
                    ],
                ))
            }
            Selection::Quarantined(id) => {
                let q = self.quarantine.iter().find(|q| &q.id == id)?;
                Some((
                    "Quarantined file".into(),
                    vec![
                        ("Original path", q.original_path.clone()),
                        ("Quarantined", format_utc(q.quarantined_unix)),
                        ("Size", format_bytes(q.size)),
                        ("SHA-256", q.sha256.clone()),
                        ("Process", q.process.clone()),
                        ("Signature", q.signature.clone()),
                        ("Stored in", quarantine::quarantine_dir(&self.data).join(&q.id).display().to_string()),
                    ],
                ))
            }
            Selection::Connection(key) => {
                let c = self.inventory.as_ref()?.connections.iter().find(|c| &connection_key(c) == key)?;
                Some((
                    format!("{} connection", c.protocol),
                    vec![
                        ("Protocol", c.protocol.clone()),
                        ("Local address", c.local_address.clone()),
                        ("Remote address", c.remote_address.clone()),
                        ("State", c.state.clone()),
                        ("PID", c.pid.to_string()),
                        ("Process", self.process_name(c.pid).unwrap_or_default()),
                    ],
                ))
            }
        }
    }

    /// A file on disk that "Open file location" can reveal for the selection.
    fn selection_path(&self, selection: &Selection) -> Option<String> {
        let path = match selection {
            Selection::Process(pid) => self
                .live
                .as_ref()
                .and_then(|l| l.processes.iter().find(|p| p.identity.pid == *pid))
                .map(|p| p.path.clone())
                .filter(|p| !p.is_empty())
                .or_else(|| self.records_by_pid().get(pid).and_then(|r| r.path.clone())),
            Selection::Finding(_) => self.selection_pid(selection).and_then(|pid| self.selection_path(&Selection::Process(pid))),
            Selection::Service(name) | Selection::Driver(name) => {
                let inv = self.inventory.as_ref()?;
                let list = if matches!(selection, Selection::Driver(_)) { &inv.drivers } else { &inv.services };
                list.iter().find(|s| &s.name == name).and_then(|s| image_path_from_command(&s.binary_path))
            }
            Selection::Startup(key) => key.splitn(3, '|').nth(2).and_then(image_path_from_command),
            Selection::Connection(_) => self.selection_pid(selection).and_then(|pid| self.selection_path(&Selection::Process(pid))),
            Selection::Quarantined(_) => None,
        };
        path.filter(|p| !p.is_empty())
    }

    /// A process related to the selection, for "Show process".
    fn selection_pid(&self, selection: &Selection) -> Option<u32> {
        match selection {
            Selection::Finding(key) => self.all_findings().into_iter().find(|f| &f.row_key() == key)?.pid(),
            Selection::Service(name) => self.inventory.as_ref()?.services.iter().find(|s| &s.name == name).map(|s| s.pid).filter(|p| *p != 0),
            Selection::Connection(key) => key.rsplit('|').next()?.parse().ok().filter(|p| *p != 0),
            _ => None,
        }
    }

    fn copy_selection(&mut self) {
        let Some(selection) = self.selected.clone() else { return };
        if let Some((title, fields)) = self.selection_fields(&selection) {
            let mut text = format!("{title}\n");
            for (k, v) in fields.iter().filter(|(_, v)| !v.is_empty()) {
                text.push_str(&format!("{k}: {v}\n"));
            }
            self.ctx.copy_text(text);
            self.note(format!("Copied: {title}"));
        }
    }

    fn open_selection_location(&mut self) {
        let Some(selection) = self.selected.clone() else { return };
        match self.selection_path(&selection) {
            Some(path) => {
                if let Err(e) = open_location(&path) {
                    self.note(e);
                }
            }
            None => self.note("The selected item has no file to show."),
        }
    }

    fn details_pane(&mut self, ui: &mut egui::Ui) {
        let Some(selection) = self.selected.clone() else { return };
        let fields = self.selection_fields(&selection);
        ui.horizontal(|ui| {
            ui.heading(fields.as_ref().map_or("Selection", |(t, _)| t.as_str()));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("×").on_hover_text("Close (Esc)").clicked() {
                    self.clear_selection();
                }
            });
        });
        let Some((_, fields)) = fields else {
            ui.label("The selected item is no longer present.");
            return;
        };
        ui.horizontal_wrapped(|ui| {
            if ui.button("Copy").on_hover_text("Copy these details (Ctrl+C)").clicked() {
                self.copy_selection();
            }
            let has_path = self.selection_path(&selection).is_some();
            if has_path && ui.button("Open file location").clicked() {
                self.open_selection_location();
            }
            if has_path && ui.button("File properties").clicked() {
                self.apply_row_action(RowAction::Properties(selection.clone()));
            }
            if (has_path || matches!(selection, Selection::Quarantined(_)))
                && ui.button("VirusTotal").on_hover_text("Opens your browser with the file's SHA-256").clicked()
            {
                self.apply_row_action(RowAction::VirusTotal(selection.clone()));
            }
            if let Some(pid) = self.selection_pid(&selection)
                && ui.button(format!("Show process {pid}")).clicked()
            {
                self.tab = Tab::Processes;
                self.select(Selection::Process(pid));
            }
        });
        if self.marked.len() > 1 {
            ui.label(RichText::new(format!("{} rows selected; right-click one for actions on all of them", self.marked.len())).small().weak());
        }
        let pids = self.action_pids(&selection);
        if !pids.is_empty() {
            let suspended: HashSet<u32> = ntsentry::system::suspended_processes().iter().map(|i| i.pid).collect();
            let n = pids.len();
            let label = |text: &str| if n > 1 { format!("{text} ({n})") } else { text.to_string() };
            ui.horizontal_wrapped(|ui| {
                if ui.button(label("End process…")).clicked() {
                    self.apply_row_action(RowAction::End(pids.clone()));
                }
                if pids.iter().any(|p| !suspended.contains(p)) && ui.button(label("Suspend")).clicked() {
                    self.apply_row_action(RowAction::Suspend(pids.clone()));
                }
                if pids.iter().any(|p| suspended.contains(p)) && ui.button(label("Resume")).clicked() {
                    self.apply_row_action(RowAction::Resume(pids.clone()));
                }
                if ui.button(label("End and quarantine…")).clicked() {
                    self.apply_row_action(RowAction::Quarantine(pids.clone()));
                }
                if ui.button(label("End tree…")).on_hover_text("End these and everything they started").clicked() {
                    self.apply_row_action(RowAction::EndTree(pids.clone()));
                }
            });
        }
        if let Selection::Quarantined(id) = &selection
            && ui.button("Restore to original location…").clicked()
        {
            self.apply_row_action(RowAction::Restore(id.clone()));
        }
        ui.separator();
        let mut navigate = None;
        let help = match &selection {
            Selection::Finding(key) => self.all_findings().into_iter().find(|f| &f.row_key() == key).map(explain::explain),
            _ => None,
        };
        egui::ScrollArea::vertical().auto_shrink(false).show(ui, |ui| {
            if let Some(help) = &help {
                egui::Frame::new().fill(ui.visuals().faint_bg_color).inner_margin(8.0).corner_radius(4.0).show(ui, |ui| {
                    ui.strong("What this means");
                    ui.add(egui::Label::new(help.meaning).wrap());
                    ui.add_space(4.0);
                    ui.strong("What you can do");
                    ui.add(egui::Label::new(help.next_steps).wrap());
                });
                ui.add_space(6.0);
            }
            for (label, value) in fields.iter().filter(|(_, v)| !v.is_empty()) {
                ui.label(RichText::new(*label).small().weak());
                let mono = label.contains("bytes") || label.contains("RVA");
                let text = if mono { RichText::new(value).monospace() } else { RichText::new(value) };
                ui.add(egui::Label::new(text).wrap());
                ui.add_space(4.0);
            }
            if !matches!(selection, Selection::Finding(_)) {
                let related = self.related_findings(&selection);
                ui.separator();
                ui.strong(format!("Findings ({})", related.len()));
                for f in related {
                    let text = RichText::new(format!("[{}] {}", f.severity.label(), f.title)).color(severity_color(f.severity));
                    if ui.link(text).clicked() {
                        navigate = Some(Selection::Finding(f.row_key()));
                    }
                }
            }
            if let Selection::Process(pid) = selection {
                self.process_extras(ui, pid);
            }
        });
        if let Some(selection) = navigate {
            self.select(selection);
        }
    }

    fn related_findings(&self, selection: &Selection) -> Vec<&Finding> {
        let subject = match selection {
            Selection::Process(pid) => {
                return self.all_findings().into_iter().filter(|f| f.pid() == Some(*pid)).collect();
            }
            Selection::Service(name) => persistence_audit::subject(EntryKind::Service, name, ""),
            Selection::Driver(name) => persistence_audit::subject(EntryKind::Driver, name, ""),
            Selection::Startup(key) => {
                let mut parts = key.splitn(3, '|');
                let (location, name) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
                persistence_audit::subject(EntryKind::Startup, name, location)
            }
            Selection::Finding(_) | Selection::Connection(_) | Selection::Quarantined(_) => return Vec::new(),
        };
        self.all_findings().into_iter().filter(|f| f.subject == subject).collect()
    }

    fn process_extras(&self, ui: &mut egui::Ui, pid: u32) {
        if let Some(inv) = &self.inventory {
            let connections: Vec<_> = inv.connections.iter().filter(|c| c.pid == pid).collect();
            ui.separator();
            ui.strong(format!("Network endpoints ({})", connections.len()));
            for c in connections {
                ui.label(RichText::new(format!("{} {} → {} {}", c.protocol, c.local_address, c.remote_address, c.state)).monospace());
            }
        }
        ui.separator();
        match self.proc_details.as_ref().filter(|d| d.pid == pid) {
            None => {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label("Loading modules and file details…");
                });
            }
            Some(d) => match &d.modules {
                Ok(modules) => {
                    egui::CollapsingHeader::new(format!("Loaded modules ({})", modules.len())).show(ui, |ui| {
                        for m in modules {
                            ui.label(RichText::new(&m.name).strong()).on_hover_text(format!(
                                "{}\nbase 0x{:X}, {}",
                                m.path,
                                m.base_address,
                                format_bytes(u64::from(m.size_bytes))
                            ));
                            ui.label(RichText::new(&m.path).small().weak());
                        }
                    });
                }
                Err(e) => {
                    ui.label(format!("Loaded modules: {e}"));
                }
            },
        }
    }

    // ---------------------------------------------------------------- exports

    fn save_as(&mut self, title: &str, stem: &str, filter: (&'static str, &'static str), extension: &'static str, contents: Vec<u8>) {
        if self.save_job.is_some() {
            self.note("A Save dialog is already open.");
            return;
        }
        let (tx, rx) = channel();
        let title = title.to_string();
        let name = format!("{stem}-{}.{extension}", compact_stamp());
        let ctx = self.ctx.clone();
        std::thread::spawn(move || {
            let _ = tx.send(dialogs::save_file(&title, &name, filter, extension));
            ctx.request_repaint();
        });
        self.save_job = Some(SaveJob { result: rx, contents });
    }

    fn export_current_view(&mut self) {
        let spec = Self::tab_spec(self.tab);
        let rows = self.tab_rows(self.tab);
        let visible = self.visible(spec.id, &rows, Some(self.tab));
        let cols = self.cols_for(&spec);
        let csv = export::csv(&shown_headers(&spec, &cols), visible.iter().map(|r| shown_texts(r, &cols)));
        self.save_as(&format!("Export {} (CSV)", self.tab.label()), spec.id, ("CSV files", "*.csv"), "csv", csv.into_bytes());
    }

    fn export_findings(&mut self, json: bool) {
        let findings: Vec<Finding> = self.all_findings().into_iter().cloned().collect();
        if json {
            let text = serde_json::to_string_pretty(&findings).unwrap_or_default();
            self.save_as("Export findings (JSON)", "findings", ("JSON files", "*.json"), "json", text.into_bytes());
        } else {
            let text = export::findings_csv(&findings);
            self.save_as("Export findings (CSV)", "findings", ("CSV files", "*.csv"), "csv", text.into_bytes());
        }
    }

    fn export_report(&mut self) {
        let mut tables = serde_json::Map::new();
        for tab in Tab::ALL {
            let spec = Self::tab_spec(tab);
            let rows = self.tab_rows(tab);
            tables.insert(spec.id.into(), export::table_json(&spec.headers(), rows.iter().map(|r| r.texts())));
        }
        let report = serde_json::json!({
            "generated_utc": format_utc(now_unix()),
            "tool": "ntsentry",
            "integrity": self.integrity,
            "process_scan": self.process_scan,
            "ntdll_sweep": self.reports.get(integrity_monitor::SWEEP_KIND),
            "modules": self.reports.get(module_audit::KIND),
            "persistence": self.reports.get(persistence_audit::KIND),
            "inventories": tables,
        });
        let text = serde_json::to_string_pretty(&report).unwrap_or_default();
        self.save_as("Export full report (JSON)", "ntsentry-report", ("JSON files", "*.json"), "json", text.into_bytes());
    }

    // ------------------------------------------------------------------ menus

    fn menu_bar(&mut self, ui: &mut egui::Ui) {
        egui::MenuBar::new().ui(ui, |ui| {
            ui.menu_button("File", |ui| {
                if ui.button(format!("Export {} view as CSV…\tCtrl+S", self.tab.label())).clicked() {
                    self.export_current_view();
                    ui.close();
                }
                if ui.button("Export findings as CSV…").clicked() {
                    self.export_findings(false);
                    ui.close();
                }
                if ui.button("Export findings as JSON…").clicked() {
                    self.export_findings(true);
                    ui.close();
                }
                if ui.button("Export full report as JSON…").clicked() {
                    self.export_report();
                    ui.close();
                }
                ui.separator();
                if ui.button("Open data folder").clicked() {
                    if let Err(e) = open_folder(&self.data.root) {
                        self.note(e);
                    }
                    ui.close();
                }
                if ui.button("Show findings log").clicked() {
                    let log = self.data.findings_log();
                    if let Err(e) = open_location(&log.display().to_string()) {
                        self.note(e);
                    }
                    ui.close();
                }
                ui.separator();
                if ui.button("Exit").clicked() {
                    self.ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
            });
            ui.menu_button("Edit", |ui| {
                let has = self.selected.is_some();
                if ui.add_enabled(has, egui::Button::new("Copy\tCtrl+C")).clicked() {
                    self.pending_rows_op = Some(RowsOp::Copy);
                    ui.close();
                }
                let path = self.selected.as_ref().and_then(|s| self.selection_path(s));
                if ui.add_enabled(path.is_some(), egui::Button::new("Open file location")).clicked() {
                    self.open_selection_location();
                    ui.close();
                }
                ui.separator();
                if ui.button("Select all\tCtrl+A").clicked() {
                    self.pending_rows_op = Some(RowsOp::SelectAll);
                    ui.close();
                }
                let count = self.marked.len();
                if ui.add_enabled(count > 1, egui::Button::new(format!("Copy {count} selected rows"))).clicked() {
                    self.pending_rows_op = Some(RowsOp::Copy);
                    ui.close();
                }
                if ui.add_enabled(count > 0, egui::Button::new("Export selected rows as CSV…")).clicked() {
                    self.pending_rows_op = Some(RowsOp::Export);
                    ui.close();
                }
                let pids = self.selected.as_ref().map(|s| self.action_pids(s)).unwrap_or_default();
                if !pids.is_empty() {
                    ui.separator();
                    let n = pids.len();
                    let label = |text: &str| if n > 1 { format!("{text} ({n} processes)") } else { text.to_string() };
                    if ui.button(label("End process…")).clicked() {
                        self.apply_row_action(RowAction::End(pids.clone()));
                        ui.close();
                    }
                    if ui.button(label("Suspend")).clicked() {
                        self.apply_row_action(RowAction::Suspend(pids.clone()));
                        ui.close();
                    }
                    if ui.button(label("Resume")).clicked() {
                        self.apply_row_action(RowAction::Resume(pids.clone()));
                        ui.close();
                    }
                    if ui.button(label("End and quarantine…")).clicked() {
                        self.apply_row_action(RowAction::Quarantine(pids.clone()));
                        ui.close();
                    }
                }
                ui.separator();
                if ui.add_enabled(has, egui::Button::new("Clear selection\tEsc")).clicked() {
                    self.clear_selection();
                    ui.close();
                }
            });
            ui.menu_button("View", |ui| {
                if ui.button("Refresh now\tF5").clicked() {
                    self.refresh_now();
                    ui.close();
                }
                let mut paused = !self.settings.live_refresh;
                if ui.checkbox(&mut paused, "Pause automatic refresh").changed() {
                    self.settings.live_refresh = !paused;
                }
                ui.checkbox(&mut self.settings.hide_system_processes, "Hide Windows system processes");
                ui.checkbox(&mut self.flagged_only, "Flagged entries only");
                ui.checkbox(&mut self.settings.process_tree, "Process tree (parent/child)");
                ui.checkbox(&mut self.settings.show_activity, "Show activity log");
                if ui.button("Find…\tCtrl+F").clicked() {
                    ui.memory_mut(|m| m.request_focus(egui::Id::unique("find")));
                    ui.close();
                }
                ui.separator();
                ui.menu_button("Go to tab", |ui| {
                    for tab in Tab::ALL {
                        if ui.selectable_label(self.tab == tab, tab.label()).clicked() {
                            self.tab = tab;
                            ui.close();
                        }
                    }
                });
                ui.separator();
                if ui.button("Zoom in\tCtrl++").clicked() {
                    self.set_zoom(self.settings.zoom + 0.1);
                }
                if ui.button("Zoom out\tCtrl+-").clicked() {
                    self.set_zoom(self.settings.zoom - 0.1);
                }
                if ui.button("Reset zoom\tCtrl+0").clicked() {
                    self.set_zoom(1.0);
                }
                ui.separator();
                let mut light = self.settings.light_theme;
                let dark_clicked = ui.radio_value(&mut light, false, "Dark theme").clicked();
                let light_clicked = ui.radio_value(&mut light, true, "Light theme").clicked();
                if dark_clicked || light_clicked {
                    self.settings.light_theme = light;
                    self.ctx.set_theme(if light { egui::Theme::Light } else { egui::Theme::Dark });
                }
            });
            ui.menu_button("Scan", |ui| {
                let idle = self.pending_scans == 0;
                if ui.add_enabled(idle, egui::Button::new("Scan all")).clicked() {
                    self.scan_all();
                    ui.close();
                }
                if ui.add_enabled(idle, egui::Button::new("Scan ntdll integrity")).clicked() {
                    self.send(Command::ScanIntegrity { compare_memory: self.settings.compare_memory });
                    ui.close();
                }
                if ui.add_enabled(idle, egui::Button::new("Scan processes")).clicked() {
                    self.send(Command::ScanProcesses);
                    ui.close();
                }
                ui.separator();
                if ui.add_enabled(idle, egui::Button::new("Compare ntdll across all processes")).clicked() {
                    self.send(Command::SweepNtdll);
                    ui.close();
                }
                if ui.add_enabled(idle, egui::Button::new("Check loaded modules (DLLs)")).clicked() {
                    self.send(Command::ScanModules);
                    ui.close();
                }
                if ui.add_enabled(idle, egui::Button::new("Check services, drivers and startup")).clicked() {
                    self.send(Command::ScanPersistence);
                    ui.close();
                }
                ui.separator();
                ui.checkbox(&mut self.settings.deep_scans, "Include these three in Scan all and scheduled scans");
                ui.checkbox(&mut self.settings.compare_memory, "Compare in-memory ntdll");
            });
            ui.menu_button("Baseline", |ui| {
                let idle = self.pending_scans == 0;
                if ui.add_enabled(idle && !self.has_baseline, egui::Button::new("Capture baseline"))
                    .on_hover_text("Record the current ntdll as known-good. Only on a machine you trust is clean.")
                    .clicked()
                {
                    self.send(Command::CaptureBaseline);
                    ui.close();
                }
                if ui.add_enabled(idle && self.has_baseline, egui::Button::new("Archive baseline…")).clicked() {
                    self.confirm_archive = true;
                    ui.close();
                }
                if ui.button("Open baseline folder").clicked() {
                    if let Err(e) = open_folder(&self.data.root) {
                        self.note(e);
                    }
                    ui.close();
                }
                ui.separator();
                let info = match self.integrity.as_ref().and_then(|r| r.baseline_captured_unix) {
                    Some(t) => format!("Captured {}", format_utc(t)),
                    None if self.has_baseline => "Present".into(),
                    None => "No baseline captured".into(),
                };
                ui.label(RichText::new(info).weak());
            });
            ui.menu_button("Settings", |ui| self.settings_menu(ui));
            ui.menu_button("Help", |ui| {
                if ui.button("How to use").clicked() {
                    self.show_help = true;
                    ui.close();
                }
                if ui.button("About NtSentry").clicked() {
                    self.show_about = true;
                    ui.close();
                }
            });
        });
    }

    fn settings_menu(&mut self, ui: &mut egui::Ui) {
        let mut run = self.autostart.is_some();
        if ui.checkbox(&mut run, "Run at Windows sign-in (starts minimized)")
            .on_hover_text("Adds a NtSentry value under HKCU\\…\\CurrentVersion\\Run for your account only.")
            .changed()
        {
            self.set_autostart(run);
        }
        if let (Some(registered), Some(exe)) = (&self.autostart, &self.exe)
            && *registered != autostart::command_for(exe)
        {
            ui.label(RichText::new("The sign-in entry points to a different copy. Untick and tick to update it.").small().weak());
        }
        ui.checkbox(&mut self.settings.scan_on_open, "Scan when the dashboard opens");
        ui.horizontal(|ui| {
            ui.checkbox(&mut self.settings.scheduled_scans, "Scan and log every");
            ui.add(egui::DragValue::new(&mut self.settings.scan_interval_minutes).range(5..=1440).suffix(" min"));
        });
        ui.horizontal(|ui| {
            ui.checkbox(&mut self.settings.live_refresh, "Refresh live data every");
            ui.add(egui::DragValue::new(&mut self.settings.live_refresh_seconds).range(1..=300).suffix(" s"));
        });
        ui.separator();
        ui.checkbox(&mut self.settings.alert_on_new, "Alert (flash taskbar) on new findings");
        ui.menu_button(format!("Alert at or above: {}", self.settings.alert_min_severity.label()), |ui| {
            for s in Severity::ALL {
                if ui.radio_value(&mut self.settings.alert_min_severity, s, s.label()).clicked() {
                    ui.close();
                }
            }
        });
        ui.checkbox(&mut self.settings.event_log, "Write new findings to the Windows event log")
            .on_hover_text("Application log, source NtSentry, event ID 1000 + severity (High = 1003).");
        ui.menu_button(format!("Event log at or above: {}", self.settings.event_log_min_severity.label()), |ui| {
            for s in Severity::ALL {
                if ui.radio_value(&mut self.settings.event_log_min_severity, s, s.label()).clicked() {
                    ui.close();
                }
            }
        });
        ui.separator();
        ui.add_enabled(self.tray.is_some(), egui::Checkbox::new(&mut self.settings.minimize_to_tray, "Minimize to the notification area"));
        ui.checkbox(&mut self.settings.deep_scans, "Deep checks in Scan all and scheduled scans");
        ui.checkbox(&mut self.settings.compare_memory, "Compare in-memory ntdll");
        ui.separator();
        ui.label(
            RichText::new("Every scan is appended to findings.jsonl (rotated at 16 MB, old logs kept). Settings save automatically.")
                .small()
                .weak(),
        );
    }

    fn set_autostart(&mut self, enable: bool) {
        let result = match (enable, &self.exe) {
            (true, Some(exe)) => autostart::enable(exe),
            (true, None) => Err("Cannot determine this program's path".into()),
            (false, _) => autostart::disable(),
        };
        match result {
            Ok(()) => self.note(if enable { "Will run at Windows sign-in (minimized)." } else { "Removed from Windows sign-in." }),
            Err(e) => self.note(e),
        }
        self.autostart = autostart::registered_command().ok().flatten();
    }

    fn set_zoom(&mut self, zoom: f32) {
        self.settings.zoom = (zoom * 10.0).round().clamp(5.0, 30.0) / 10.0;
        self.ctx.set_zoom_factor(self.settings.zoom);
    }

    fn toolbar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
            let idle = self.pending_scans == 0;
            if ui.button("Refresh").on_hover_text("Refresh live data and inventories (F5)").clicked() {
                self.refresh_now();
            }
            if ui.add_enabled(idle, egui::Button::new("Scan all")).on_hover_text("ntdll integrity + process scan, logged").clicked() {
                self.scan_all();
            }
            if ui.add_enabled(idle, egui::Button::new("Scan ntdll")).clicked() {
                self.send(Command::ScanIntegrity { compare_memory: self.settings.compare_memory });
            }
            if ui.add_enabled(idle, egui::Button::new("Scan processes")).clicked() {
                self.send(Command::ScanProcesses);
            }
            ui.separator();
            let path = self.selected.as_ref().and_then(|s| self.selection_path(s));
            if ui.add_enabled(path.is_some(), egui::Button::new("Open folder")).clicked() {
                self.open_selection_location();
            }
            if ui.add_enabled(self.selected.is_some(), egui::Button::new("Copy")).on_hover_text("Ctrl+C: selected rows, or the details of one").clicked() {
                self.pending_rows_op = Some(RowsOp::Copy);
            }
            ui.menu_button("Export…", |ui| {
                if ui.button(format!("{} view as CSV…", self.tab.label())).clicked() {
                    self.export_current_view();
                    ui.close();
                }
                if ui.button("Findings as CSV…").clicked() {
                    self.export_findings(false);
                    ui.close();
                }
                if ui.button("Full report as JSON…").clicked() {
                    self.export_report();
                    ui.close();
                }
            });
            let paused = !self.settings.live_refresh;
            if ui.selectable_label(paused, if paused { "Resume" } else { "Pause" }).on_hover_text("Pause automatic refresh").clicked() {
                self.settings.live_refresh = paused;
            }
            ui.separator();
            if ui.add_enabled(idle && !self.has_baseline, egui::Button::new("Capture baseline")).clicked() {
                self.send(Command::CaptureBaseline);
            }
            if self.has_baseline && ui.add_enabled(idle, egui::Button::new("Archive baseline…")).clicked() {
                self.confirm_archive = true;
            }
        });
    }

    fn status_bar(&self, ui: &mut egui::Ui, shown: usize) {
        ui.horizontal(|ui| {
            match self.current {
                Some(what) => {
                    ui.spinner();
                    ui.label(what);
                }
                None => {
                    ui.label("Idle");
                }
            }
            ui.separator();
            if self.marked.len() > 1 {
                ui.label(format!("{shown} entries shown · {} selected", self.marked.len()));
            } else {
                ui.label(format!("{shown} entries shown"));
            }
            ui.separator();
            ui.label(if self.settings.live_refresh {
                format!("Live refresh every {} s", self.settings.live_refresh_seconds)
            } else {
                "Live refresh paused".into()
            });
            ui.separator();
            if self.settings.scheduled_scans {
                let left = self.settings.scan_interval().saturating_sub(self.last_scheduled.elapsed());
                ui.label(format!("Next scheduled scan in {} min", left.as_secs().div_ceil(60)));
            } else {
                ui.label("Scheduled scans off");
            }
            ui.separator();
            ui.label(if self.has_baseline { "Baseline: present" } else { "Baseline: none" });
            ui.separator();
            ui.label(RichText::new("Scans are read-only; actions ask first").weak());
        });
    }

    fn summary(&self, ui: &mut egui::Ui) {
        match &self.integrity {
            Some(r) => {
                let status = r.findings.iter().map(|f| f.severity).max().unwrap_or(Severity::Info);
                ui.horizontal_wrapped(|ui| {
                    ui.label(RichText::new(format!("ntdll: {}", if status >= Severity::Medium { status.label() } else { "OK" }))
                        .color(severity_color(status))
                        .strong());
                    ui.label(format!(
                        "{} · signature {} · disk-vs-memory runs {} · baseline {} · scanned {}",
                        r.ntdll_path,
                        r.signature.as_ref().map_or("not checked".into(), |s| s.summary()),
                        r.disk_vs_memory_runs,
                        r.baseline_captured_unix.map_or("none".into(), |t| format!("{} (deviations {})", format_utc(t), r.baseline_deviation_runs)),
                        format_utc(r.scanned_unix),
                    ));
                });
            }
            None => {
                ui.label("ntdll: not scanned yet");
            }
        }
        ui.horizontal_wrapped(|ui| {
            if let Some(live) = &self.live {
                ui.label(format!(
                    "CPU {:.0} % · memory {} of {} used · {} processes",
                    live.cpu_percent,
                    format_bytes(live.memory_total_bytes.saturating_sub(live.memory_available_bytes)),
                    format_bytes(live.memory_total_bytes),
                    live.processes.len()
                ));
            }
            if let Some(p) = &self.process_scan {
                ui.label(format!(
                    "· last process scan {} ({} without an accessible path)",
                    format_utc(p.scanned_unix),
                    p.inaccessible
                ));
            }
        });
        let extra: Vec<&str> = EXTRA_SCANS.iter().filter_map(|(k, _)| self.reports.get(k)).map(|r| r.summary.as_str()).collect();
        if !extra.is_empty() {
            ui.label(RichText::new(extra.join("  ·  ")).weak());
        }
    }

    fn dialogs(&mut self, ctx: &egui::Context) {
        if let Some(confirm) = &self.confirm {
            let (title, text, button) = (confirm.title.clone(), confirm.text.clone(), confirm.button);
            let mut decision = None;
            let modal = egui::Modal::new(egui::Id::unique("confirm_action")).show(ctx, |ui| {
                ui.set_max_width(520.0);
                ui.heading(title);
                ui.add(egui::Label::new(text).wrap());
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    if ui.button(RichText::new(button).strong().color(Color32::from_rgb(230, 90, 70))).clicked() {
                        decision = Some(true);
                    }
                    if ui.button("Cancel").clicked() {
                        decision = Some(false);
                    }
                });
            });
            if modal.should_close() && decision.is_none() {
                decision = Some(false);
            }
            match decision {
                Some(true) => {
                    let confirm = self.confirm.take().unwrap();
                    for action in confirm.actions {
                        self.worker.send_live(LiveCommand::Act(action));
                    }
                }
                Some(false) => self.confirm = None,
                None => {}
            }
        }
        if self.confirm_archive {
            let modal = egui::Modal::new(egui::Id::unique("archive_modal")).show(ctx, |ui| {
                ui.heading("Archive the baseline?");
                ui.label("The current baseline folder is renamed to baseline-archived-<time>. Nothing is deleted.");
                ui.label("Capture a new baseline afterwards, on a system you trust is clean.");
                ui.horizontal(|ui| {
                    if ui.button("Archive").clicked() {
                        self.send(Command::ArchiveBaseline);
                        self.confirm_archive = false;
                    }
                    if ui.button("Cancel").clicked() {
                        self.confirm_archive = false;
                    }
                });
            });
            if modal.should_close() {
                self.confirm_archive = false;
            }
        }
        egui::Window::new("About NtSentry").open(&mut self.show_about).collapsible(false).show(ctx, |ui| {
            ui.label(format!("Version {}", env!("CARGO_PKG_VERSION")));
            ui.label("Tamper detection, system inventory and confirmed process actions for Windows.");
            ui.label("Scans never write to process memory, change protections, or restore bytes.");
            ui.label("Process actions (end, suspend, quarantine) run only after you confirm them, and are logged.");
            ui.label(format!("Data folder: {}", self.data.root.display()));
        });
        egui::Window::new("How to use").open(&mut self.show_help).default_width(520.0).show(ctx, |ui| {
            ui.label("• Findings (top) lists everything the scans found, most severe first. NEW marks findings that were not in the previous scan.");
            ui.label("• The tabs below show every process, service, driver, startup entry and network endpoint. Click a column header to sort.");
            ui.label("• Click any row to see its full details on the right; Esc clears the selection.");
            ui.label("• Select several rows: Ctrl+click, Shift+click, Shift+arrow keys, or Ctrl+A for all. Ctrl+C copies them; right-click for actions on all of them.");
            ui.label("• Right-click a row or a column header > Columns to show or hide columns. Copies and exports include only the shown columns.");
            ui.label("• Click a finding to read what it means and what you can do about it.");
            ui.label("• Right-click a process to end, suspend/resume, or end it and quarantine its file. Restore from the Quarantine tab.");
            ui.label("• Find (Ctrl+F) filters the findings and the current tab by any text: name, PID, path…");
            ui.label("• Baseline > Capture baseline records ntdll on a known-clean system; later scans report only deviations from it.");
            ui.label("• Scan > ... also compares ntdll across all processes, checks loaded DLLs, and audits services, drivers and startup entries.");
            ui.label("• Settings: run at sign-in, scheduled scans (logged to findings.jsonl), live refresh, alerts, event log, tray.");
            ui.label("• View > Process tree shows parent/child relationships (sorting is off in tree view).");
            ui.label("• File: export the current view, findings, or a full report.");
        });
    }

    fn handle_shortcuts(&mut self, ui: &mut egui::Ui) {
        let (f5, find, save, escape) = ui.input_mut(|i| {
            (
                i.key_pressed(Key::F5),
                i.consume_shortcut(&KeyboardShortcut::new(Modifiers::COMMAND, Key::F)),
                i.consume_shortcut(&KeyboardShortcut::new(Modifiers::COMMAND, Key::S)),
                i.key_pressed(Key::Escape),
            )
        });
        let typing = ui.memory(|m| m.focused().is_some());
        if f5 {
            self.refresh_now();
        }
        if find {
            ui.memory_mut(|m| m.request_focus(egui::Id::unique("find")));
        }
        if save {
            self.export_current_view();
        }
        if escape && !typing {
            self.clear_selection();
        }
    }
}

#[derive(Clone, Copy)]
enum ActionKind {
    Suspend,
    Other,
}

/// "name (pid N)" lines for a confirmation, at most 15, optionally with paths.
fn describe_targets(targets: &[(ProcessIdentity, String, String, String)], paths: bool) -> String {
    let mut lines: Vec<String> = targets
        .iter()
        .take(15)
        .map(|(identity, name, path, signature)| {
            if paths {
                format!("{name} (pid {})\n    {path}\n    {signature}", identity.pid)
            } else {
                format!("{name} (pid {})", identity.pid)
            }
        })
        .collect();
    if targets.len() > 15 {
        lines.push(format!("…and {} more", targets.len() - 15));
    }
    lines.join("\n")
}

fn yes_no(value: bool) -> String {
    if value { "Yes".into() } else { "No".into() }
}

fn stable_keys(findings: &[Finding]) -> HashSet<String> {
    findings.iter().filter(|f| f.severity >= Severity::Low).map(Finding::stable_key).collect()
}

/// Orders process rows as a parent/child tree and indents the Name cell. A parent
/// that started after its child is a reused PID, so the child becomes a root.
fn tree_order(entries: Vec<(Row, u32, u64)>) -> Vec<Row> {
    let pids: Vec<u32> = entries.iter().map(|(r, _, _)| match r.key {
        Selection::Process(pid) => pid,
        _ => u32::MAX,
    }).collect();
    let index: HashMap<u32, usize> = pids.iter().enumerate().map(|(i, p)| (*p, i)).collect();
    let mut children: HashMap<usize, Vec<usize>> = HashMap::new();
    let mut roots = Vec::new();
    for (i, (_, parent, created)) in entries.iter().enumerate() {
        let parent_index = index.get(parent).copied().filter(|&pi| {
            let parent_created = entries[pi].2;
            pi != i && pids[i] != 0 && (parent_created == 0 || *created == 0 || parent_created <= *created)
        });
        match parent_index {
            Some(pi) => children.entry(pi).or_default().push(i),
            None => roots.push(i),
        }
    }
    // Entries arrive sorted by name, so children and roots keep that order.
    let mut order = Vec::with_capacity(entries.len());
    let mut stack: Vec<(usize, usize)> = roots.into_iter().rev().map(|i| (i, 0)).collect();
    let mut visited = vec![false; entries.len()];
    while let Some((i, depth)) = stack.pop() {
        if std::mem::replace(&mut visited[i], true) {
            continue;
        }
        order.push((i, depth));
        if let Some(kids) = children.get(&i) {
            stack.extend(kids.iter().rev().map(|&k| (k, depth + 1)));
        }
    }
    // Anything left (a parent cycle) is appended as roots.
    order.extend((0..entries.len()).filter(|&i| !visited[i]).map(|i| (i, 0)));
    let mut slots: Vec<Option<Row>> = entries.into_iter().map(|(r, _, _)| Some(r)).collect();
    order
        .into_iter()
        .filter_map(|(i, depth)| {
            let mut row = slots[i].take()?;
            if depth > 0 {
                row.cells[2].text = format!("{}› {}", "    ".repeat(depth - 1), row.cells[2].text);
            }
            Some(row)
        })
        .collect()
}

fn connection_key(c: &ntsentry::inventory::NetworkConnection) -> String {
    format!("{}|{}|{}|{}|{}", c.protocol, c.local_address, c.remote_address, c.state, c.pid)
}

impl eframe::App for Dashboard {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.start_minimized {
            self.start_minimized = false;
            ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(true));
        }
        self.drain_events();
        self.poll_save();
        while let Ok(message) = self.notes_rx.try_recv() {
            self.note(message);
        }
        if self.settings.last_tab != self.tab.label() {
            self.settings.last_tab = self.tab.label().to_string();
        }
        if std::mem::take(&mut self.request_attention) && !self.hidden {
            ctx.send_viewport_cmd(egui::ViewportCommand::RequestUserAttention(egui::UserAttentionType::Critical));
        }
        let actions = self.tray.as_ref().map(|t| t.poll()).unwrap_or_default();
        for action in actions {
            match action {
                crate::tray::TrayAction::Show => {
                    self.hidden = false;
                    ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                    ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
                    ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                }
                crate::tray::TrayAction::ScanNow => {
                    if self.pending_scans == 0 {
                        self.scan_all();
                    }
                }
                crate::tray::TrayAction::Exit => ctx.send_viewport_cmd(egui::ViewportCommand::Close),
            }
        }
        let alert = self.alert.clone();
        if let Some(tray) = &mut self.tray {
            tray.set_alert(alert.as_deref());
        }

        // Follow zoom changes made with Ctrl+Plus/Minus as well as the menu.
        let zoom = ctx.zoom_factor();
        if (zoom - self.last_ctx_zoom).abs() > f32::EPSILON {
            self.last_ctx_zoom = zoom;
            self.settings.zoom = zoom;
        }

        let minimized = self.hidden || ctx.input(|i| i.viewport().minimized).unwrap_or(false);
        if self.settings.minimize_to_tray && self.tray.is_some() && minimized && !self.hidden {
            self.hidden = true;
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
            self.note("Hidden to the notification area; click the icon to restore.");
        }
        if self.settings.scheduled_scans && self.pending_scans == 0 && self.last_scheduled.elapsed() >= self.settings.scan_interval() {
            self.note("Scheduled scan");
            self.scan_all();
        }
        if (!minimized && self.settings.live_refresh) || self.live.is_none() {
            if !self.live_outstanding && self.last_live.elapsed() >= self.settings.live_interval() {
                self.live_outstanding = self.worker.send_live(LiveCommand::RefreshProcesses);
                self.last_live = Instant::now();
            }
            if !self.inventory_outstanding && self.last_inventory.elapsed() >= INVENTORY_REFRESH {
                self.inventory_outstanding = self.worker.send_live(LiveCommand::CollectInventory);
                self.last_inventory = Instant::now();
            }
        } else if !self.settings.live_refresh && !minimized && self.inventory.is_none() && !self.inventory_outstanding {
            self.inventory_outstanding = self.worker.send_live(LiveCommand::CollectInventory);
        }

        if self.settings != self.saved_settings {
            self.settings = self.settings.clone().sanitized();
            match self.settings.save(&self.data) {
                Ok(()) => self.saved_settings = self.settings.clone(),
                Err(e) => {
                    self.note(format!("Settings not saved: {e}"));
                    self.saved_settings = self.settings.clone();
                }
            }
        }
        // Keep timers (scheduled scans, live refresh) ticking without input.
        ctx.request_repaint_after(Duration::from_secs(1));
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        // Never leave a process frozen because the dashboard closed.
        ntsentry::system::resume_all_suspended();
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        self.handle_shortcuts(ui);
        self.dialogs(&ctx);

        let finding_rows = self.finding_rows();
        let tab_rows = self.tab_rows(self.tab);
        let findings_spec = Self::findings_spec();
        let tab_spec = Self::tab_spec(self.tab);
        let visible_findings = self.visible(findings_spec.id, &finding_rows, None);
        let visible_tab = self.visible(tab_spec.id, &tab_rows, Some(self.tab));
        let shown = visible_tab.len();

        // Keyboard selection and row operations act on the table holding the selection.
        let active = self.anchor.as_ref().map_or(tab_spec.id, |a| a.table());
        let (active_spec, active_rows) = if active == findings_spec.id {
            (&findings_spec, &visible_findings)
        } else {
            (&tab_spec, &visible_tab)
        };
        self.scroll_to = self.keyboard_selection(ui, active_rows);
        if let Some(op) = self.pending_rows_op.take() {
            self.run_rows_op(op, active_spec, active_rows);
        }
        let scroll_findings = self.scroll_to.filter(|_| active == findings_spec.id);
        let scroll_tab = self.scroll_to.filter(|_| active != findings_spec.id);
        let findings_cols = self.cols_for(&findings_spec);
        let tab_cols = self.cols_for(&tab_spec);
        let findings_keys: Vec<&Selection> = visible_findings.iter().map(|r| &r.key).collect();
        let tab_keys: Vec<&Selection> = visible_tab.iter().map(|r| &r.key).collect();

        egui::Panel::top("menu_bar").show(ui, |ui| self.menu_bar(ui));
        egui::Panel::top("toolbar").show(ui, |ui| self.toolbar(ui));
        egui::Panel::bottom("status").show(ui, |ui| self.status_bar(ui, shown));
        if self.settings.show_activity {
            egui::Panel::bottom("activity").resizable(true).default_size(90.0).min_size(40.0).show(ui, |ui| {
                ui.strong("Activity");
                egui::ScrollArea::vertical().stick_to_bottom(true).auto_shrink(false).show(ui, |ui| {
                    for (t, m) in &self.activity {
                        ui.label(format!("{}  {m}", format_utc(*t)));
                    }
                });
            });
        }
        if self.selected.is_some() {
            egui::Panel::right("details").resizable(true).default_size(400.0).min_size(260.0).show(ui, |ui| self.details_pane(ui));
        }

        let mut outputs = Vec::new();
        let suspended: HashSet<u32> = ntsentry::system::suspended_processes().iter().map(|i| i.pid).collect();
        let marked = self.marked.clone();
        let mut marked_pids: Vec<u32> =
            marked.iter().filter_map(|s| if let Selection::Process(p) = s { Some(*p) } else { None }).collect();
        marked_pids.sort_unstable();
        let menu = |ui: &mut egui::Ui, selection: &Selection| {
            let targets = match selection {
                Selection::Process(_) if marked_pids.len() > 1 && marked.contains(selection) => marked_pids.clone(),
                Selection::Process(pid) => vec![*pid],
                _ => Vec::new(),
            };
            let selected = if marked.contains(selection) { marked.len() } else { 1 };
            row_menu(ui, selection, &targets, &suspended, selected)
        };
        egui::CentralPanel::default().show(ui, |ui| {
            self.summary(ui);
            if let Some(alert) = self.alert.clone() {
                egui::Frame::new().fill(Color32::from_rgb(110, 40, 30)).inner_margin(6.0).corner_radius(4.0).show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(format!("ALERT: {alert}")).color(Color32::WHITE).strong());
                        if ui.button("Dismiss").clicked() {
                            self.alert = None;
                        }
                    });
                });
            }
            ui.horizontal(|ui| {
                ui.label("Find:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.filter)
                        .id(egui::Id::unique("find"))
                        .hint_text("Filter by name, PID, path or any text… (Ctrl+F)")
                        .desired_width(420.0),
                );
                if !self.filter.is_empty() && ui.button("×").on_hover_text("Clear").clicked() {
                    self.filter.clear();
                }
                ui.separator();
                ui.label("Minimum severity");
                egui::ComboBox::from_id_salt("min_severity").selected_text(self.min_severity.label()).show_ui(ui, |ui| {
                    for s in Severity::ALL {
                        ui.selectable_value(&mut self.min_severity, s, s.label());
                    }
                });
                ui.checkbox(&mut self.settings.hide_system_processes, "Hide Windows system processes");
                ui.checkbox(&mut self.flagged_only, "Flagged only");
                if self.tab == Tab::Processes {
                    ui.checkbox(&mut self.settings.process_tree, "Tree");
                }
            });
            ui.separator();
            let findings_height = (ui.available_height() * 0.33).max(110.0);
            egui::Panel::top("findings_pane").resizable(true).default_size(findings_height).min_size(70.0).show(ui, |ui| {
                ui.strong(format!("Findings ({} shown)", visible_findings.len()));
                let sort = self.sorts.get(findings_spec.id).copied().unwrap_or((0, false));
                outputs.push((findings_spec.id, render_table(ui, &findings_spec, &findings_cols, &visible_findings, sort, &marked, scroll_findings, &menu)));
            });
            ui.horizontal(|ui| {
                for tab in Tab::ALL {
                    let label = format!("{} ({})", tab.label(), self.tab_count(tab));
                    if ui.selectable_label(self.tab == tab, label).clicked() {
                        self.tab = tab;
                    }
                }
                if self.tab != Tab::Processes && self.inventory.is_none() {
                    ui.spinner();
                    ui.label("Loading inventories…");
                }
            });
            let sort = self.sorts.get(tab_spec.id).copied().unwrap_or((0, true));
            outputs.push((tab_spec.id, render_table(ui, &tab_spec, &tab_cols, &visible_tab, sort, &marked, scroll_tab, &menu)));
        });
        for (id, out) in outputs {
            let keys = if id == findings_spec.id { &findings_keys } else { &tab_keys };
            self.apply_table_output(id, out, keys);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use egui::{Pos2, Rect, pos2, vec2};

    /// Runs `render_table` headlessly, feeding pointer events, and returns what it reported.
    fn run_frames(
        rows: &[Row],
        spec: &Spec,
        clicks: &[Pos2],
        pointer: egui::PointerButton,
    ) -> (Vec<Selection>, Vec<usize>, Vec<Selection>) {
        let ctx = egui::Context::default();
        let refs: Vec<&Row> = rows.iter().collect();
        let mut selected = Vec::new();
        let mut sorted = Vec::new();
        // Rows whose right-click menu was drawn.
        let menus = std::cell::RefCell::new(Vec::new());
        let menu = |_: &mut egui::Ui, s: &Selection| {
            menus.borrow_mut().push(s.clone());
            None
        };
        let mut frame = |events: Vec<egui::Event>| {
            let input = egui::RawInput {
                screen_rect: Some(Rect::from_min_size(Pos2::ZERO, vec2(900.0, 600.0))),
                events,
                ..Default::default()
            };
            let mut output = ctx.run_ui(input, |ui| {
                let cols: Vec<usize> = (0..spec.columns.len()).collect();
                let out = render_table(ui, spec, &cols, &refs, (0, true), &HashSet::new(), None, &menu);
                selected.extend(out.clicked.map(|c| c.0));
                sorted.extend(out.sort_clicked);
            });
            // No renderer in tests: drop the font texture uploads explicitly.
            output.textures_delta.clear();
        };
        frame(Vec::new());
        frame(Vec::new());
        for &pos in clicks {
            let button = |pressed| egui::Event::PointerButton {
                pos,
                button: pointer,
                pressed,
                modifiers: Modifiers::NONE,
            };
            frame(vec![egui::Event::PointerMoved(pos)]);
            frame(vec![button(true)]);
            frame(vec![button(false)]);
            frame(Vec::new());
        }
        let mut opened = menus.into_inner();
        opened.dedup();
        (selected, sorted, opened)
    }

    fn sample() -> (Vec<Row>, Spec) {
        let rows = (1..=5)
            .map(|pid| {
                Row::new(
                    Selection::Process(pid),
                    vec![Cell::num(pid.to_string(), f64::from(pid)), Cell::text(format!("process-{pid}.exe"))],
                )
            })
            .collect();
        let spec = Spec { id: "test", columns: vec![("PID", Column::initial(120.0)), ("Name", Column::remainder())] };
        (rows, spec)
    }

    #[test]
    fn clicking_a_row_selects_it_even_on_its_text() {
        let (rows, spec) = sample();
        // Header is about ROW_HEIGHT + 2 tall; the third row starts near y = 2.5 rows down.
        let third_row_y = (ROW_HEIGHT + 2.0) + 2.5 * (ROW_HEIGHT + 3.0);
        let (selected, _, menus) =
            run_frames(&rows, &spec, &[pos2(20.0, third_row_y), pos2(300.0, third_row_y)], egui::PointerButton::Primary);
        assert_eq!(selected, vec![Selection::Process(3), Selection::Process(3)], "clicks on the PID text and on the name cell");
        assert!(menus.is_empty(), "a left click opens no menu");
    }

    #[test]
    fn right_clicking_a_row_selects_it_and_opens_its_menu() {
        let (rows, spec) = sample();
        let second_row_y = (ROW_HEIGHT + 2.0) + 1.5 * (ROW_HEIGHT + 3.0);
        let (selected, _, menus) = run_frames(&rows, &spec, &[pos2(200.0, second_row_y)], egui::PointerButton::Secondary);
        assert_eq!(selected, vec![Selection::Process(2)]);
        assert_eq!(menus, vec![Selection::Process(2)], "the menu is built for the row that was right-clicked");
    }

    #[test]
    fn clicking_a_header_requests_sorting() {
        let (rows, spec) = sample();
        let (selected, sorted, _) = run_frames(&rows, &spec, &[pos2(140.0, 8.0)], egui::PointerButton::Primary);
        assert!(selected.is_empty());
        assert_eq!(sorted, vec![1]);
    }

    #[test]
    fn ranges_and_copied_rows_follow_table_order() {
        let (rows, _) = sample();
        let keys: Vec<&Selection> = rows.iter().map(|r| &r.key).collect();
        let range = range_between(&keys, &Selection::Process(4), &Selection::Process(2)).unwrap();
        assert_eq!(range, vec![Selection::Process(2), Selection::Process(3), Selection::Process(4)]);
        assert!(range_between(&keys, &Selection::Process(9), &Selection::Process(2)).is_none());
        let refs: Vec<&Row> = rows.iter().collect();
        let marked: HashSet<Selection> = [Selection::Process(4), Selection::Process(1)].into_iter().collect();
        let spec = Spec { id: "test", columns: vec![("PID", Column::auto()), ("Name", Column::auto())] };
        let (text, count) = rows_text(&spec, &[0, 1], &refs, &marked);
        assert_eq!(count, 2);
        assert_eq!(text, "PID\tName\n1\tprocess-1.exe\n4\tprocess-4.exe\n");
        let (text, _) = rows_text(&spec, &[1], &refs, &marked);
        assert_eq!(text, "Name\nprocess-1.exe\nprocess-4.exe\n", "hidden columns are left out");
        let hidden = vec!["PID".to_string()];
        assert_eq!(visible_columns(&spec, Some(&hidden)), vec![1]);
        let all = vec!["PID".to_string(), "Name".to_string()];
        assert_eq!(visible_columns(&spec, Some(&all)), vec![0, 1], "never hide every column");
    }

    #[test]
    fn sorting_keeps_empty_cells_last() {
        let mut keys = [SortKey::Num(2.0), SortKey::Empty, SortKey::Num(10.0), SortKey::Text("a".into())];
        keys.sort_by(|a, b| compare_keys(a, b, false));
        assert!(matches!(keys[0], SortKey::Text(_)));
        assert!(matches!(keys[1], SortKey::Num(x) if x == 10.0));
        assert!(matches!(keys[3], SortKey::Empty));
    }

    #[test]
    fn byte_and_stamp_formatting() {
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(5 * 1024 * 1024), "5.0 MB");
        let stamp = compact_stamp();
        assert_eq!(stamp.len(), 15, "{stamp}");
        assert!(stamp.chars().all(|c| c.is_ascii_digit() || c == '-'), "{stamp}");
    }
}
