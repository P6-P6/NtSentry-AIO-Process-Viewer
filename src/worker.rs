//! Background threads. The UI sends commands and drains [`Event`]s; nothing slow
//! runs on the render thread.
//!
//! * The scan thread runs the tamper scans (seconds each) and logs them.
//! * The live thread refreshes CPU/memory and the inventories, and loads details
//!   for a selected process, so it never waits behind a scan.
//! * The icon thread reads row icons, which can touch hundreds of files, some on
//!   slow drives, so it never holds up the live refresh.

use crate::file_icon::{IconImage, small_icon};
use crate::findings::{Finding, ScanReport, Severity};
use crate::integrity_monitor::{self, CaptureOutcome, IntegrityReport};
use crate::inventory::{self, AutorunInfo, Monitor, ProcessDetails, ProcessIdentity, ProcessSnapshot, SystemInventory};
use crate::process_inventory::{self, KnownDirs, ProcessInventory, ProcessReport};
use crate::signature::SignatureCache;
use crate::{module_audit, persistence_audit};
use crate::storage::DataDir;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::mpsc::{Receiver, Sender, channel};

#[derive(Clone, Debug)]
pub enum Command {
    ScanIntegrity { compare_memory: bool },
    ScanProcesses,
    /// ntdll in every readable process against this process's copy.
    SweepNtdll,
    /// Unsigned DLLs in signed processes.
    ScanModules,
    /// Services, drivers and startup entries.
    ScanPersistence,
    CaptureBaseline,
    ArchiveBaseline,
}

#[derive(Clone, Debug)]
pub enum LiveCommand {
    RefreshProcesses,
    CollectInventory,
    ProcessDetails { identity: ProcessIdentity, path: String },
    Act(Action),
}

/// A user-confirmed change. Each one re-checks its target first.
#[derive(Clone, Debug)]
pub enum Action {
    End { identity: ProcessIdentity, name: String },
    Suspend { identity: ProcessIdentity, name: String },
    Resume { identity: ProcessIdentity, name: String },
    /// End the process, then move its file into quarantine.
    Quarantine { identity: ProcessIdentity, name: String, path: String, signature: String },
    Restore { id: String },
    /// Turn a startup entry off or on for future sign-ins.
    SetStartup { entry: AutorunInfo, disable: bool },
}

#[derive(Debug)]
pub enum Event {
    Started(&'static str),
    Integrity(IntegrityReport),
    Processes(ProcessReport),
    /// Persistence, module and ntdll-sweep results.
    Report(ScanReport),
    BaselineCaptured(Result<CaptureOutcome, String>),
    BaselineArchived(Result<String, String>),
    /// A log write failed; findings are still shown.
    LogError(String),
    /// A scan command finished.
    Finished,
    Live(Result<ProcessSnapshot, String>),
    Inventory(SystemInventory),
    ProcessDetails(ProcessDetails),
    /// Loaded icons, as (command they were requested for, icon).
    Icons(Vec<(String, Option<IconImage>)>),
    ActionDone { ok: bool, message: String },
}

pub struct Worker {
    scans: Sender<Command>,
    live: Sender<LiveCommand>,
    icons: Sender<Vec<String>>,
    pub events: Receiver<Event>,
}

impl Worker {
    /// `notify` is called after every event, e.g. to wake the UI with `request_repaint`.
    /// The threads end when the `Worker` is dropped (their command channels close).
    pub fn spawn(data: DataDir, notify: impl Fn() + Send + Sync + 'static) -> Self {
        let notify: Arc<dyn Fn() + Send + Sync> = Arc::new(notify);
        let (scans, scan_inbox) = channel::<Command>();
        let (live, live_inbox) = channel::<LiveCommand>();
        let (icons, icon_inbox) = channel::<Vec<String>>();
        let (outbox, events) = channel::<Event>();
        let (scan_out, scan_notify) = (outbox.clone(), notify.clone());
        let (icon_out, icon_notify) = (outbox.clone(), notify.clone());
        let live_data = data.clone();
        std::thread::Builder::new()
            .name("ntsentry-scan".into())
            .spawn(move || run_scans(data, scan_inbox, scan_out, scan_notify))
            .expect("spawn scan thread");
        std::thread::Builder::new()
            .name("ntsentry-live".into())
            .spawn(move || run_live(live_data, live_inbox, outbox, notify))
            .expect("spawn live thread");
        std::thread::Builder::new()
            .name("ntsentry-icons".into())
            .spawn(move || run_icons(icon_inbox, icon_out, icon_notify))
            .expect("spawn icon thread");
        Worker { scans, live, icons, events }
    }

    pub fn send(&self, command: Command) -> bool {
        self.scans.send(command).is_ok()
    }

    pub fn send_live(&self, command: LiveCommand) -> bool {
        self.live.send(command).is_ok()
    }

    /// Requests icons for these commands; each arrives in an [`Event::Icons`].
    pub fn send_icons(&self, commands: Vec<String>) -> bool {
        self.icons.send(commands).is_ok()
    }
}

/// Icons sent per event, so a long list appears progressively.
const ICON_BATCH: usize = 32;

fn run_icons(inbox: Receiver<Vec<String>>, outbox: Sender<Event>, notify: Arc<dyn Fn() + Send + Sync>) {
    // Many commands share a file, such as every service hosted by svchost.exe.
    let mut by_file: HashMap<Option<String>, Option<IconImage>> = HashMap::new();
    while let Ok(commands) = inbox.recv() {
        for batch in commands.chunks(ICON_BATCH) {
            let icons = batch
                .iter()
                .map(|command| {
                    let file = inventory::command_target(command);
                    (command.clone(), by_file.entry(file).or_insert_with_key(|f| small_icon(f.as_deref())).clone())
                })
                .collect();
            if outbox.send(Event::Icons(icons)).is_err() {
                return;
            }
            notify();
        }
    }
}

fn run_scans(data: DataDir, inbox: Receiver<Command>, outbox: Sender<Event>, notify: Arc<dyn Fn() + Send + Sync>) {
    let mut inventory = ProcessInventory::new();
    let mut cache = SignatureCache::new();
    let dirs = KnownDirs::detect();
    let send = |event: Event| {
        let ok = outbox.send(event).is_ok();
        notify();
        ok
    };
    let log = |scan: &str, findings: &[Finding]| {
        if let Err(e) = data.append_log(scan, findings) {
            send(Event::LogError(e));
        }
    };
    while let Ok(command) = inbox.recv() {
        let event = match command {
            Command::ScanIntegrity { compare_memory } => {
                send(Event::Started("Scanning ntdll.dll integrity"));
                let report = integrity_monitor::scan(&data, compare_memory);
                log("integrity", &report.findings);
                Event::Integrity(report)
            }
            Command::ScanProcesses => {
                send(Event::Started("Scanning processes"));
                let report = inventory.scan(&mut cache);
                log("processes", &report.findings);
                Event::Processes(report)
            }
            Command::SweepNtdll => {
                send(Event::Started("Comparing ntdll across processes"));
                let report = match process_inventory::list_processes() {
                    Ok(list) => {
                        let list: Vec<(u32, String)> = list.into_iter().map(|p| (p.pid, p.name)).collect();
                        integrity_monitor::sweep_processes(&list, &mut cache, &dirs)
                    }
                    Err(e) => error_report(integrity_monitor::SWEEP_KIND, integrity_monitor::SWEEP_MODULE, e),
                };
                log(&report.kind, &report.findings);
                Event::Report(report)
            }
            Command::ScanModules => {
                send(Event::Started("Checking loaded modules"));
                let processes = inventory.scan(&mut cache).processes;
                let report = module_audit::scan(&processes, &mut cache, &dirs);
                log(&report.kind, &report.findings);
                Event::Report(report)
            }
            Command::ScanPersistence => {
                send(Event::Started("Checking services, drivers and startup entries"));
                let report = persistence_audit::scan(&inventory::collect(), &mut cache, &dirs);
                log(&report.kind, &report.findings);
                Event::Report(report)
            }
            Command::CaptureBaseline => {
                send(Event::Started("Capturing ntdll baseline"));
                let outcome = integrity_monitor::capture_baseline(&data);
                match &outcome {
                    Ok(o) => log("baseline_capture", &o.findings),
                    Err(e) => log(
                        "baseline_capture",
                        &[Finding::new(integrity_monitor::MODULE, Severity::Info, "baseline", "Baseline capture refused")
                            .detail(e.clone())],
                    ),
                }
                Event::BaselineCaptured(outcome)
            }
            Command::ArchiveBaseline => {
                send(Event::Started("Archiving baseline"));
                Event::BaselineArchived(data.archive_baseline().map(|p| p.display().to_string()))
            }
        };
        if !send(event) || !send(Event::Finished) {
            break;
        }
    }
}

fn error_report(kind: &str, module: &str, error: String) -> ScanReport {
    ScanReport {
        kind: kind.into(),
        scanned_unix: crate::winutil::now_unix(),
        duration_ms: 0,
        summary: format!("{kind}: failed"),
        findings: vec![Finding::new(module, Severity::High, "scan", "Scan could not run").detail(error)],
    }
}

/// Performs one action; returns (succeeded, message, subject for the log).
fn perform(data: &DataDir, action: Action) -> (bool, String, String) {
    use crate::system::{resume_process, suspend_process, terminate_process};
    let subject = |identity: &ProcessIdentity, name: &str| format!("pid {} {name}", identity.pid);
    match action {
        Action::End { identity, name } => match terminate_process(&identity) {
            Ok(()) => (true, format!("Ended {name} (pid {})", identity.pid), subject(&identity, &name)),
            Err(e) => (false, format!("Could not end {name}: {e}"), subject(&identity, &name)),
        },
        Action::Suspend { identity, name } => match suspend_process(&identity) {
            Ok(n) => (true, format!("Suspended {name} (pid {}, {n} threads)", identity.pid), subject(&identity, &name)),
            Err(e) => (false, format!("Could not suspend {name}: {e}"), subject(&identity, &name)),
        },
        Action::Resume { identity, name } => match resume_process(&identity) {
            Ok(n) => (true, format!("Resumed {name} (pid {}, {n} threads)", identity.pid), subject(&identity, &name)),
            Err(e) => (false, format!("Could not resume {name}: {e}"), subject(&identity, &name)),
        },
        Action::Quarantine { identity, name, path, signature } => {
            let who = subject(&identity, &name);
            if let Err(e) = terminate_process(&identity) {
                return (false, format!("Not quarantined: could not end {name} first: {e}"), who);
            }
            match crate::quarantine::quarantine_file(data, &path, &who, &signature) {
                Ok(entry) => (true, format!("Ended {name} and quarantined {path} (entry {})", entry.id), who),
                Err(e) => (false, format!("Ended {name}, but quarantine failed: {e}"), who),
            }
        }
        Action::Restore { id } => match crate::quarantine::restore(data, &id) {
            Ok(path) => (true, format!("Restored {path} from quarantine"), format!("quarantine {id}")),
            Err(e) => (false, format!("Could not restore quarantine entry {id}: {e}"), format!("quarantine {id}")),
        },
        Action::SetStartup { entry, disable } => {
            let who = persistence_audit::subject(persistence_audit::EntryKind::Startup, &entry.name, &entry.location);
            let (done, verb) = if disable { ("Disabled", "disable") } else { ("Enabled", "enable") };
            match crate::startup_control::set_disabled(&entry, disable) {
                Ok(()) => (true, format!("{done} {} at startup; this applies from the next sign-in", entry.name), who),
                Err(e) => (false, format!("Could not {verb} {}: {e}", entry.name), who),
            }
        }
    }
}

fn run_live(data: DataDir, inbox: Receiver<LiveCommand>, outbox: Sender<Event>, notify: Arc<dyn Fn() + Send + Sync>) {
    let mut monitor = Monitor::new();
    // The first sample only establishes CPU baselines.
    let _ = monitor.refresh();
    while let Ok(command) = inbox.recv() {
        let event = match command {
            LiveCommand::RefreshProcesses => Event::Live(monitor.refresh()),
            LiveCommand::CollectInventory => Event::Inventory(inventory::collect()),
            LiveCommand::ProcessDetails { identity, path } => {
                Event::ProcessDetails(inventory::process_details(identity, &path))
            }
            LiveCommand::Act(action) => {
                let (ok, message, subject) = perform(&data, action);
                let severity = if ok { Severity::Info } else { Severity::Low };
                let entry = Finding::new("actions", severity, subject, message.clone());
                if let Err(e) = data.append_log("action", &[entry]) {
                    let _ = outbox.send(Event::LogError(e));
                }
                Event::ActionDone { ok, message }
            }
        };
        if outbox.send(event).is_err() {
            break;
        }
        notify();
    }
}
