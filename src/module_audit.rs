//! Loaded-module audit: unsigned DLLs inside signed processes. Detection only.
//!
//! A signed program that has loaded an unsigned DLL from a temp or user-writable
//! folder is a common sign of DLL side-loading or injection. Modules elsewhere are
//! not reported (unsigned plugins under Program Files are ordinary), and only
//! modules in risky folders are signature-checked, which keeps the scan fast.

use crate::findings::{Finding, ScanReport, Severity, sort_findings};
use crate::inventory::ProcessIdentity;
use crate::process_inventory::{KnownDirs, PathClass, ProcessRecord, classify_path};
use crate::signature::{SignatureCache, SignatureInfo, SignatureState};
use crate::winutil::now_unix;
use std::time::Instant;

pub const MODULE: &str = "module_audit";
pub const KIND: &str = "modules";

/// Pure rule for one module in one signed process.
pub fn assess(
    process: &ProcessRecord,
    host_class: Option<PathClass>,
    module_path: &str,
    module_class: PathClass,
    signature: Option<&SignatureInfo>,
) -> Option<Finding> {
    let state = signature.map(|s| s.state)?;
    if state == SignatureState::Valid {
        return None;
    }
    let risky = matches!(module_class, PathClass::TempOrDownloads | PathClass::UserWritable);
    if !risky && state != SignatureState::Invalid {
        return None;
    }
    let windows_host = host_class == Some(PathClass::Windows);
    let severity = match (state, module_class) {
        (SignatureState::Invalid, _) | (_, PathClass::TempOrDownloads) => Severity::High,
        _ if windows_host => Severity::High,
        _ => Severity::Medium,
    };
    let what = match state {
        SignatureState::Invalid => "DLL with an invalid signature",
        SignatureState::Untrusted => "DLL with an untrusted signature",
        _ => "unsigned DLL",
    };
    let place = match module_class {
        PathClass::TempOrDownloads => " from a temp/download folder",
        PathClass::UserWritable => " from a user-writable folder",
        _ => "",
    };
    Some(
        Finding::new(MODULE, severity, format!("pid {} {}", process.pid, process.name), format!("Signed process loaded an {what}{place}"))
            .detail(format!(
                "Module {module_path} in {} ({}).",
                process.path.as_deref().unwrap_or("?"),
                process.signature.as_ref().map_or("signature unknown".into(), |s| s.summary())
            )),
    )
}

pub fn scan(processes: &[ProcessRecord], cache: &mut SignatureCache, dirs: &KnownDirs) -> ScanReport {
    let started = Instant::now();
    let mut findings = Vec::new();
    let (mut inspected, mut unreadable, mut modules_seen) = (0, 0, 0);
    let own = std::process::id();
    for p in processes {
        let signed = p.signature.as_ref().is_some_and(|s| s.state == SignatureState::Valid);
        if !signed || p.pid == own {
            continue;
        }
        let Some(created) = p.created_filetime else { continue };
        let identity = ProcessIdentity { pid: p.pid, creation_time: created };
        let modules = match crate::system::process_modules(&identity) {
            Ok(m) => m,
            Err(_) => {
                unreadable += 1;
                continue;
            }
        };
        inspected += 1;
        for m in &modules {
            modules_seen += 1;
            let class = classify_path(&m.path, dirs);
            if !matches!(class, PathClass::TempOrDownloads | PathClass::UserWritable) {
                continue;
            }
            let signature = cache.get(&m.path);
            findings.extend(assess(p, p.path_class, &m.path, class, signature.as_ref()));
        }
    }
    let summary = format!(
        "Modules: {modules_seen} modules in {inspected} signed processes ({unreadable} not readable), {} finding(s)",
        findings.len()
    );
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

    fn process() -> ProcessRecord {
        ProcessRecord {
            pid: 42,
            parent_pid: 1,
            name: "notepad.exe".into(),
            path: Some(r"C:\Windows\System32\notepad.exe".into()),
            path_error: None,
            path_class: Some(PathClass::Windows),
            signature: Some(SignatureInfo { state: SignatureState::Valid, signer: "Microsoft Windows".into(), via_catalog: false, status_code: 0 }),
            created_filetime: Some(1),
            max_severity: None,
        }
    }

    fn sig(state: SignatureState) -> SignatureInfo {
        SignatureInfo { state, signer: String::new(), via_catalog: false, status_code: 0 }
    }

    #[test]
    fn only_unsigned_modules_in_risky_folders_are_reported() {
        let p = process();
        let unsigned = sig(SignatureState::Unsigned);
        let valid = sig(SignatureState::Valid);
        let user = r"C:\Users\a\AppData\Roaming\x\hook.dll";
        let f = assess(&p, p.path_class, user, PathClass::UserWritable, Some(&unsigned)).unwrap();
        assert_eq!(f.severity, Severity::High, "unsigned user-folder DLL inside a Windows process");
        assert!(assess(&p, p.path_class, user, PathClass::UserWritable, Some(&valid)).is_none());
        assert!(assess(&p, p.path_class, r"C:\Program Files\App\plugin.dll", PathClass::ProgramFiles, Some(&unsigned)).is_none());
        let f = assess(&p, Some(PathClass::ProgramFiles), user, PathClass::UserWritable, Some(&unsigned)).unwrap();
        assert_eq!(f.severity, Severity::Medium);
        let f = assess(&p, Some(PathClass::ProgramFiles), r"C:\Program Files\App\x.dll", PathClass::ProgramFiles, Some(&sig(SignatureState::Invalid))).unwrap();
        assert_eq!(f.severity, Severity::High);
        assert!(assess(&p, p.path_class, user, PathClass::UserWritable, None).is_none(), "unknown signature is not a finding");
    }
}
