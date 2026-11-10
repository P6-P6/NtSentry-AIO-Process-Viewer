//! Read-only checks against the real system: the installed ntdll.dll and the live
//! process list. Baselines are written only into a fresh temporary directory.

use ntsentry::findings::Severity;
use ntsentry::integrity_monitor::{capture_baseline, load_baseline, ntdll_path, scan};
use ntsentry::integrity_monitor::{SWEEP_MODULE, sweep_processes};
use ntsentry::process_inventory::{KnownDirs, ProcessInventory};
use ntsentry::signature::{SignatureCache, SignatureState, signature_info};
use ntsentry::{file_icon, inventory, module_audit, persistence_audit, quarantine, service_control};
use ntsentry::inventory::ServiceInfo;
use ntsentry::service_control::ServiceOp;
use ntsentry::storage::DataDir;

struct Scratch(std::path::PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        Scratch(std::env::temp_dir().join(format!("ntsentry-live-{tag}-{}-{nanos}", std::process::id())))
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A throwaway service that is never started, removed when dropped.
struct TestService(String);

impl TestService {
    fn create(tag: &str, binary: &str) -> Self {
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let name = format!("NtSentryTest{tag}{}{nanos}", std::process::id());
        let status = std::process::Command::new("sc.exe")
            .args(["create", &name, "binPath=", binary, "start=", "demand"])
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "sc create failed");
        TestService(name)
    }

    fn info(&self) -> ServiceInfo {
        ntsentry::system::list_services(false).unwrap().into_iter().find(|s| s.name == self.0).expect("test service listed")
    }
}

impl Drop for TestService {
    fn drop(&mut self) {
        let _ = std::process::Command::new("sc.exe").args(["delete", &self.0]).stdout(std::process::Stdio::null()).status();
    }
}

#[test]
fn service_start_changes_and_quarantine_work_on_a_real_service() {
    if !ntsentry::system::is_elevated() {
        eprintln!("skipped: changing services needs elevation");
        return;
    }
    let scratch = Scratch::new("service");
    std::fs::create_dir_all(&scratch.0).unwrap();
    let data = DataDir::at(scratch.0.join("data"));
    let file = scratch.0.join("payload.exe");
    std::fs::write(&file, b"MZ harmless test payload").unwrap();
    let service = TestService::create("Q", &file.to_string_lossy());

    assert_eq!(service.info().start_type, "Manual");
    for (op, expected) in [(ServiceOp::Disable, "Disabled"), (ServiceOp::EnableAutomatic, "Automatic"), (ServiceOp::EnableManual, "Manual")] {
        service_control::apply(&data, &service.info(), op).unwrap();
        assert_eq!(service.info().start_type, expected);
    }
    service_control::apply(&data, &service.info(), ServiceOp::Stop).expect("stopping a stopped service is fine");

    let mut stale = service.info();
    stale.binary_path = r"C:\somewhere\else.exe".into();
    assert!(service_control::apply(&data, &stale, ServiceOp::Disable).unwrap_err().contains("changed"));
    assert_eq!(service.info().start_type, "Manual", "a stale target changes nothing");

    let message = service_control::apply(&data, &service.info(), ServiceOp::Quarantine).unwrap();
    assert!(message.contains("quarantined"), "{message}");
    assert!(!file.exists(), "the file moved out");
    assert_eq!(service.info().start_type, "Disabled");
    let entries = quarantine::list(&data);
    assert_eq!(entries.len(), 1);
    quarantine::restore(&data, &entries[0].id).unwrap();
    assert_eq!(std::fs::read(&file).unwrap(), b"MZ harmless test payload");
}

#[test]
fn microsofts_own_files_are_never_quarantined() {
    if !ntsentry::system::is_elevated() {
        eprintln!("skipped: changing services needs elevation");
        return;
    }
    let scratch = Scratch::new("servicems");
    std::fs::create_dir_all(&scratch.0).unwrap();
    let data = DataDir::at(scratch.0.join("data"));
    let cmd = format!(r"{}\System32\cmd.exe", ntsentry::winutil::windows_directory().unwrap());
    let service = TestService::create("M", &cmd);

    let error = service_control::apply(&data, &service.info(), ServiceOp::Quarantine).unwrap_err();
    assert!(error.contains("Microsoft"), "{error}");
    assert!(std::path::Path::new(&cmd).exists());
    assert_eq!(service.info().start_type, "Manual", "refused before anything changed");
    assert!(quarantine::list(&data).is_empty());
}

#[test]
fn installed_ntdll_has_a_valid_microsoft_signature() {
    // Embedded on current Windows 11 builds; the catalog path covers other builds.
    let sig = signature_info(&ntdll_path().unwrap()).unwrap();
    assert_eq!(sig.state, SignatureState::Valid, "{}", sig.summary());
    assert!(sig.signer.starts_with("Microsoft"), "{}", sig.summary());
}

#[test]
fn scan_without_baseline_completes() {
    let scratch = Scratch::new("nobaseline");
    let report = scan(&DataDir::at(&scratch.0), true);
    assert!(!report.file_sha256.is_empty());
    assert!(report.loaded_base.is_some());
    assert!(report.sections_checked.iter().any(|s| s.starts_with(".text")), "{:?}", report.sections_checked);
    assert!(
        !report.findings.iter().any(|f| f.title.contains("could not")),
        "{:#?}",
        report.findings
    );
    assert!(report.findings.iter().any(|f| f.title == "No baseline captured"));
}

#[test]
fn fresh_baseline_matches_immediately_and_is_not_overwritten() {
    let scratch = Scratch::new("baseline");
    let data = DataDir::at(&scratch.0);
    let outcome = capture_baseline(&data).expect("capture on this machine");
    assert!(!outcome.baseline.sections.is_empty());
    let loaded = load_baseline(&data).unwrap().unwrap();
    assert!(loaded.problems.is_empty(), "{:#?}", loaded.problems);
    assert!(loaded.sections.iter().all(Option::is_some));

    let report = scan(&data, true);
    assert_eq!(report.baseline_deviation_runs, 0, "{:#?}", report.findings);
    assert!(
        report.findings.iter().all(|f| f.severity < Severity::Medium),
        "{:#?}",
        report.findings.iter().filter(|f| f.severity >= Severity::Medium).collect::<Vec<_>>()
    );
    assert!(capture_baseline(&data).unwrap_err().contains("already exists"));
}

#[test]
fn tampered_baseline_file_is_detected() {
    let scratch = Scratch::new("tampered");
    let data = DataDir::at(&scratch.0);
    let outcome = capture_baseline(&data).unwrap();
    // Alter the *stored snapshot* (our own scratch file), never real memory.
    let file = data.baseline_dir().join(&outcome.baseline.sections[0].file);
    let mut bytes = std::fs::read(&file).unwrap();
    bytes[0] ^= 0xFF;
    std::fs::write(&file, bytes).unwrap();
    let report = scan(&data, true);
    assert!(
        report.findings.iter().any(|f| f.severity == Severity::Critical && f.title.contains("does not match its recorded hash")),
        "{:#?}",
        report.findings
    );
}

#[test]
fn process_inventory_sees_this_test_process() {
    let mut inventory = ProcessInventory::new();
    let mut cache = SignatureCache::new();
    let report = inventory.scan(&mut cache);
    let me = report.processes.iter().find(|p| p.pid == std::process::id()).expect("own pid");
    let exe = std::env::current_exe().unwrap();
    assert!(me.path.as_deref().unwrap().eq_ignore_ascii_case(&exe.to_string_lossy()), "{me:?}");
    assert!(me.created_filetime.is_some());
    assert!(report.processes.len() > 10);
    // A second scan reuses cached signature results.
    assert!(inventory.scan(&mut cache).signature_cache_hits > 0);
}

/// A freshly started, untouched process must match the dashboard's ntdll exactly.
#[test]
fn ntdll_sweep_finds_a_fresh_child_identical() {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let mut child = std::process::Command::new("cmd.exe")
        .args(["/c", "ping -n 6 127.0.0.1 >nul"])
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
        .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(500));
    let report = sweep_processes(&[(child.id(), "cmd.exe".into())], &mut SignatureCache::new(), &KnownDirs::detect());
    let _ = child.kill();
    let _ = child.wait();
    assert!(report.summary.contains("1 processes compared"), "{}", report.summary);
    assert!(report.summary.contains("0 modified"), "{:#?}", report.findings);
    assert!(report.findings.iter().all(|f| f.module == SWEEP_MODULE && f.severity == Severity::Info));
}

#[test]
fn every_inventory_entry_gets_an_icon() {
    let inv = inventory::collect();
    let services = inv.services.iter().chain(&inv.drivers).map(|s| s.binary_path.as_str());
    let commands: Vec<&str> = services.chain(inv.startup.iter().map(|a| a.command.as_str())).collect();
    assert!(!commands.is_empty());
    let started = std::time::Instant::now();
    let missing: Vec<&str> =
        commands.iter().copied().filter(|c| file_icon::small_icon(inventory::command_target(c).as_deref()).is_none()).collect();
    println!("{} icons in {:?}", commands.len(), started.elapsed());
    assert!(missing.is_empty(), "{missing:?}");
}

#[test]
fn persistence_and_module_audits_complete() {
    let mut cache = SignatureCache::new();
    let dirs = KnownDirs::detect();
    let inv = inventory::collect();
    assert!(!inv.services.is_empty() && !inv.drivers.is_empty(), "{:?}", inv.errors);
    let persistence = persistence_audit::scan(&inv, &mut cache, &dirs);
    assert!(persistence.summary.starts_with("Persistence:"), "{}", persistence.summary);
    let processes = ProcessInventory::new().scan(&mut cache).processes;
    let modules = module_audit::scan(&processes, &mut cache, &dirs);
    assert!(modules.summary.contains("signed processes"), "{}", modules.summary);
    assert!(!modules.summary.starts_with("Modules: 0 modules"), "{}", modules.summary);
}
