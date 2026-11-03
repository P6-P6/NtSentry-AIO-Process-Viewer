//! Module B: process inventory. Detection only.
//!
//! Processes come from `CreateToolhelp32Snapshot`; image paths from
//! `QueryFullProcessImageNameW` on a `PROCESS_QUERY_LIMITED_INFORMATION` handle,
//! which grants no read, write, or control rights. Each image is checked for an
//! Authenticode signature, a temp or user-writable location, and a name that does
//! not match its path (including Windows system process names running from
//! somewhere other than where Windows keeps them).

use crate::findings::{Finding, Severity, sort_findings};
use crate::signature::{SignatureCache, SignatureInfo, SignatureState};
use crate::winutil::{OwnedHandle, from_wide, now_unix, system_directory, windows_directory};
use serde::Serialize;
use std::collections::HashMap;
use std::mem::{size_of, zeroed};
use std::time::Instant;
use windows_sys::Win32::Foundation::{FILETIME, GetLastError, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
};

pub const MODULE: &str = "process_inventory";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum PathClass {
    /// Under the Windows directory, but not its Temp folder.
    Windows,
    /// Under Program Files.
    ProgramFiles,
    /// A temp, Downloads, or recycle-bin folder.
    TempOrDownloads,
    /// Elsewhere in a user profile, Public, or ProgramData.
    UserWritable,
    Other,
}

impl PathClass {
    pub fn label(self) -> &'static str {
        match self {
            PathClass::Windows => "Windows",
            PathClass::ProgramFiles => "Program Files",
            PathClass::TempOrDownloads => "Temp/Downloads",
            PathClass::UserWritable => "User-writable",
            PathClass::Other => "Other",
        }
    }
}

/// Lower-cased, backslash-terminated reference directories.
#[derive(Clone, Debug)]
pub struct KnownDirs {
    pub windows: String,
    pub system32: String,
    pub syswow64: String,
    pub program_files: Vec<String>,
    pub users: Vec<String>,
    /// %TEMP% and %TMP%, wherever they point.
    pub temp: Vec<String>,
    pub program_data: Option<String>,
}

fn dir_key(path: &str) -> String {
    let mut s = path.replace('/', "\\").to_lowercase();
    if !s.ends_with('\\') {
        s.push('\\');
    }
    s
}

impl KnownDirs {
    pub fn detect() -> Self {
        let windows = windows_directory().unwrap_or_else(|| "C:\\Windows".into());
        let system32 = system_directory().unwrap_or_else(|| format!("{windows}\\System32"));
        let env = |name: &str| std::env::var(name).ok().filter(|v| !v.is_empty());
        let mut program_files: Vec<String> = ["ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"]
            .iter()
            .filter_map(|n| env(n))
            .map(|p| dir_key(&p))
            .collect();
        program_files.dedup();
        // The parent of the current profile covers every user's profile; Public sits there too.
        let mut users: Vec<String> = env("USERPROFILE")
            .and_then(|p| std::path::Path::new(&p).parent().map(|d| dir_key(&d.to_string_lossy())))
            .into_iter()
            .collect();
        users.extend(env("PUBLIC").map(|p| dir_key(&p)));
        let mut temp: Vec<String> = ["TEMP", "TMP"].iter().filter_map(|n| env(n)).map(|p| dir_key(&p)).collect();
        temp.dedup();
        KnownDirs {
            syswow64: dir_key(&format!("{windows}\\SysWOW64")),
            windows: dir_key(&windows),
            system32: dir_key(&system32),
            program_files,
            users,
            temp,
            program_data: env("ProgramData").map(|p| dir_key(&p)),
        }
    }
}

pub fn classify_path(path: &str, dirs: &KnownDirs) -> PathClass {
    let p = path.replace('/', "\\").to_lowercase();
    let in_users = dirs.users.iter().any(|u| p.starts_with(u.as_str()));
    let temp_segment = ["\\temp\\", "\\tmp\\", "\\downloads\\", "\\$recycle.bin\\", "\\inetcache\\"]
        .iter()
        .any(|seg| p.contains(seg));
    if p.starts_with(&format!("{}temp\\", dirs.windows))
        || dirs.temp.iter().any(|t| p.starts_with(t.as_str()))
        || (in_users && temp_segment)
        || p.contains("\\$recycle.bin\\")
    {
        return PathClass::TempOrDownloads;
    }
    if p.starts_with(&dirs.windows) {
        return PathClass::Windows;
    }
    if dirs.program_files.iter().any(|d| p.starts_with(d.as_str())) {
        return PathClass::ProgramFiles;
    }
    if in_users || dirs.program_data.as_deref().is_some_and(|d| p.starts_with(d)) {
        return PathClass::UserWritable;
    }
    PathClass::Other
}

/// Windows binaries whose names are commonly borrowed by malware, and where they live.
fn expected_system_location(name: &str, dirs: &KnownDirs) -> Option<Vec<String>> {
    const SYSTEM32: &[&str] = &[
        "csrss.exe", "smss.exe", "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe", "lsaiso.exe",
        "svchost.exe", "spoolsv.exe", "taskhostw.exe", "dllhost.exe", "conhost.exe", "sihost.exe",
        "fontdrvhost.exe", "dwm.exe", "ctfmon.exe", "runtimebroker.exe", "wmiprvse.exe", "searchindexer.exe",
        "rundll32.exe", "regsvr32.exe", "userinit.exe", "taskmgr.exe", "audiodg.exe", "werfault.exe",
    ];
    let lower = name.to_lowercase();
    if lower == "explorer.exe" {
        return Some(vec![format!("{}explorer.exe", dirs.windows), format!("{}explorer.exe", dirs.syswow64)]);
    }
    SYSTEM32
        .contains(&lower.as_str())
        .then(|| vec![format!("{}{lower}", dirs.system32), format!("{}{lower}", dirs.syswow64)])
}

fn file_name(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

/// Pure assessment of one process; `signature` is `None` when it could not be checked.
pub fn assess(
    pid: u32,
    snapshot_name: &str,
    path: &str,
    signature: Option<&SignatureInfo>,
    dirs: &KnownDirs,
) -> (PathClass, Vec<Finding>) {
    let subject = format!("pid {pid} {snapshot_name}");
    let class = classify_path(path, dirs);
    let mut findings = Vec::new();
    let image = file_name(path);
    if !image.eq_ignore_ascii_case(snapshot_name) {
        findings.push(
            Finding::new(MODULE, Severity::Medium, &subject, "Process name does not match its image path")
                .detail(format!("Snapshot name \"{snapshot_name}\", image file \"{image}\" at {path}.")),
        );
    }
    if let Some(expected) = expected_system_location(image, dirs)
        && !expected.iter().any(|e| path.eq_ignore_ascii_case(e))
    {
        findings.push(
            Finding::new(MODULE, Severity::High, &subject, format!("{image} is running from an unexpected location"))
                .detail(format!("Path {path}. Windows keeps this binary at {}.", expected.join(" or "))),
        );
    }
    let state = signature.map(|s| s.state);
    match state {
        Some(SignatureState::Invalid) => findings.push(
            Finding::new(MODULE, Severity::High, &subject, "Image signature does not verify")
                .detail(format!("{path}: {}", signature.unwrap().summary())),
        ),
        Some(state @ (SignatureState::Unsigned | SignatureState::Untrusted)) => {
            let what = if state == SignatureState::Unsigned { "Unsigned image" } else { "Image with an untrusted signature" };
            let (severity, place) = match class {
                PathClass::TempOrDownloads => (Severity::High, " running from a temp/download folder"),
                PathClass::UserWritable => (Severity::Medium, " running from a user-writable folder"),
                PathClass::Windows => (Severity::Medium, " under the Windows directory"),
                _ => (Severity::Low, ""),
            };
            let detail = match signature {
                Some(s) if state == SignatureState::Untrusted => format!("{path}: {}", s.summary()),
                _ => path.to_string(),
            };
            findings.push(Finding::new(MODULE, severity, &subject, format!("{what}{place}")).detail(detail));
        }
        Some(SignatureState::Valid) if class == PathClass::TempOrDownloads => findings.push(
            Finding::new(MODULE, Severity::Low, &subject, "Signed image running from a temp/download folder")
                .detail(format!("{path}: {}", signature.unwrap().summary())),
        ),
        _ => {}
    }
    (class, findings)
}

const OFFICE: &[&str] = &[
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe", "msaccess.exe", "mspub.exe", "visio.exe",
];
const SHELLS_AND_PROXIES: &[&str] = &[
    "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe",
    "certutil.exe", "bitsadmin.exe", "msbuild.exe", "installutil.exe", "wmic.exe",
];
const BROWSERS: &[&str] = &["chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe", "iexplore.exe"];
const SCRIPT_HOSTS: &[&str] = &["powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe"];
/// Windows processes that are always started by one specific parent.
const EXPECTED_PARENT: &[(&str, &str)] = &[
    ("svchost.exe", "services.exe"),
    ("lsass.exe", "wininit.exe"),
    ("lsaiso.exe", "wininit.exe"),
    ("services.exe", "wininit.exe"),
];

/// Parent/child pairs worth a look. Pure: names only; the caller has already
/// checked that the parent is the real parent (it started before the child).
pub fn assess_lineage(child: &str, parent: &str) -> Option<(Severity, String)> {
    let child = child.to_lowercase();
    let parent = parent.to_lowercase();
    if OFFICE.contains(&parent.as_str()) && SHELLS_AND_PROXIES.contains(&child.as_str()) {
        return Some((Severity::High, format!("Office application {parent} started {child}")));
    }
    if BROWSERS.contains(&parent.as_str()) && SCRIPT_HOSTS.contains(&child.as_str()) {
        return Some((Severity::Medium, format!("Browser {parent} started script host {child}")));
    }
    if let Some((_, expected)) = EXPECTED_PARENT.iter().find(|(c, _)| *c == child)
        && parent != *expected
    {
        return Some((Severity::High, format!("{child} was started by {parent} instead of {expected}")));
    }
    None
}

#[derive(Clone, Debug, Serialize)]
pub struct ProcessRecord {
    pub pid: u32,
    pub parent_pid: u32,
    pub name: String,
    pub path: Option<String>,
    /// Why the path is missing (usually access denied for protected processes).
    pub path_error: Option<String>,
    pub path_class: Option<PathClass>,
    pub signature: Option<SignatureInfo>,
    /// Process creation time (FILETIME ticks), when readable.
    pub created_filetime: Option<u64>,
    pub max_severity: Option<crate::findings::Severity>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct ProcessReport {
    pub scanned_unix: u64,
    pub duration_ms: u128,
    pub processes: Vec<ProcessRecord>,
    pub findings: Vec<Finding>,
    pub inaccessible: usize,
    pub signature_cache_hits: usize,
}

#[derive(Clone, Debug)]
pub struct RawProcess {
    pub pid: u32,
    pub parent_pid: u32,
    pub name: String,
}

/// A Toolhelp snapshot of running processes.
pub fn list_processes() -> Result<Vec<RawProcess>, String> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            return Err(format!("CreateToolhelp32Snapshot failed ({})", GetLastError()));
        }
        let snapshot = OwnedHandle(snapshot);
        let mut entry: PROCESSENTRY32W = zeroed();
        entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;
        let mut out = Vec::new();
        if Process32FirstW(snapshot.0, &mut entry) == 0 {
            return Err(format!("Process32FirstW failed ({})", GetLastError()));
        }
        loop {
            out.push(RawProcess {
                pid: entry.th32ProcessID,
                parent_pid: entry.th32ParentProcessID,
                name: from_wide(&entry.szExeFile),
            });
            if Process32NextW(snapshot.0, &mut entry) == 0 {
                break;
            }
        }
        Ok(out)
    }
}

/// Image path and creation time through a query-only handle.
pub fn image_path(pid: u32) -> Result<(String, Option<u64>), String> {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle.is_null() {
            let code = GetLastError();
            return Err(if code == 5 { "access denied".into() } else { format!("OpenProcess error {code}") });
        }
        let handle = OwnedHandle(handle);
        let mut buffer = vec![0u16; 32_768];
        let mut len = buffer.len() as u32;
        if QueryFullProcessImageNameW(handle.0, PROCESS_NAME_WIN32, buffer.as_mut_ptr(), &mut len) == 0 {
            return Err(format!("QueryFullProcessImageNameW error {}", GetLastError()));
        }
        let (mut created, mut exited, mut kernel, mut user) = (zeroed::<FILETIME>(), zeroed(), zeroed(), zeroed());
        let created = (GetProcessTimes(handle.0, &mut created, &mut exited, &mut kernel, &mut user) != 0)
            .then(|| (u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime));
        Ok((from_wide(&buffer[..len as usize]), created))
    }
}

#[derive(Default)]
pub struct ProcessInventory {
    dirs: Option<KnownDirs>,
}

impl ProcessInventory {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn scan(&mut self, cache: &mut SignatureCache) -> ProcessReport {
        let started = Instant::now();
        let hits_before = cache.hits;
        let mut report = ProcessReport { scanned_unix: now_unix(), ..Default::default() };
        let dirs = self.dirs.get_or_insert_with(KnownDirs::detect).clone();
        let raw = match list_processes() {
            Ok(r) => r,
            Err(e) => {
                report.findings.push(Finding::new(MODULE, Severity::High, "process snapshot", "Process enumeration failed").detail(e));
                return report;
            }
        };
        for p in raw {
            let mut record = ProcessRecord {
                pid: p.pid,
                parent_pid: p.parent_pid,
                name: p.name.clone(),
                path: None,
                path_error: None,
                path_class: None,
                signature: None,
                created_filetime: None,
                max_severity: None,
            };
            // Idle (0) and System (4) have no image file.
            if p.pid == 0 || p.pid == 4 {
                record.path_error = Some("kernel process, no image file".into());
                report.processes.push(record);
                continue;
            }
            match image_path(p.pid) {
                // Minimal processes (Registry, Memory Compression, Secure System) report a bare name.
                Ok((path, created)) if !path.contains('\\') => {
                    record.created_filetime = created;
                    record.path_error = Some(format!("minimal process ({path})"));
                }
                Ok((path, created)) => {
                    let sig = cache.get(&path);
                    let (class, findings) = assess(p.pid, &p.name, &path, sig.as_ref(), &dirs);
                    record.max_severity = findings.iter().map(|f| f.severity).max();
                    record.path_class = Some(class);
                    record.signature = sig;
                    record.created_filetime = created;
                    record.path = Some(path);
                    report.findings.extend(findings);
                }
                Err(e) => {
                    report.inaccessible += 1;
                    record.path_error = Some(e);
                }
            }
            report.processes.push(record);
        }
        self.assess_parents(&mut report);
        report.signature_cache_hits = cache.hits - hits_before;
        report.findings.push(
            Finding::new(MODULE, Severity::Info, "process snapshot", "Process inventory summary").detail(format!(
                "{} processes, {} without an accessible image path (run as administrator for more), {} signature results reused.",
                report.processes.len(),
                report.inaccessible,
                report.signature_cache_hits
            )),
        );
        sort_findings(&mut report.findings);
        report.duration_ms = started.elapsed().as_millis();
        report
    }

    /// Applies [`assess_lineage`] where the parent is still running. A parent that
    /// started after its child is a reused PID, not the real parent, and is skipped.
    fn assess_parents(&self, report: &mut ProcessReport) {
        let by_pid: HashMap<u32, usize> = report.processes.iter().enumerate().map(|(i, p)| (p.pid, i)).collect();
        let mut extra = Vec::new();
        for (i, child) in report.processes.iter().enumerate() {
            let Some(&pi) = by_pid.get(&child.parent_pid) else { continue };
            let parent = &report.processes[pi];
            if parent.pid == child.pid || child.pid == 0 {
                continue;
            }
            let reused = matches!((parent.created_filetime, child.created_filetime), (Some(p), Some(c)) if p > c);
            if reused {
                continue;
            }
            if let Some((severity, title)) = assess_lineage(&child.name, &parent.name) {
                let verified = if parent.created_filetime.is_some() && child.created_filetime.is_some() {
                    "The parent started before the child, so it is the real parent."
                } else {
                    "Creation times were not readable, so a reused parent PID cannot be ruled out."
                };
                extra.push((
                    i,
                    Finding::new(MODULE, severity, format!("pid {} {}", child.pid, child.name), title).detail(format!(
                        "Parent: pid {} {} ({}). Child: {}. {verified}",
                        parent.pid,
                        parent.name,
                        parent.path.as_deref().unwrap_or("path unavailable"),
                        child.path.as_deref().unwrap_or("path unavailable"),
                    )),
                ));
            }
        }
        for (i, finding) in extra {
            let record = &mut report.processes[i];
            record.max_severity = record.max_severity.max(Some(finding.severity));
            report.findings.push(finding);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dirs() -> KnownDirs {
        KnownDirs {
            windows: "c:\\windows\\".into(),
            system32: "c:\\windows\\system32\\".into(),
            syswow64: "c:\\windows\\syswow64\\".into(),
            program_files: vec!["c:\\program files\\".into(), "c:\\program files (x86)\\".into()],
            users: vec!["c:\\users\\".into()],
            temp: vec!["d:\\scratch\\".into()],
            program_data: Some("c:\\programdata\\".into()),
        }
    }

    fn sig(state: SignatureState) -> SignatureInfo {
        SignatureInfo { state, signer: "Test".into(), via_catalog: false, status_code: 0 }
    }

    #[test]
    fn classifies_common_locations() {
        let d = dirs();
        assert_eq!(classify_path("C:\\Windows\\System32\\svchost.exe", &d), PathClass::Windows);
        assert_eq!(classify_path("C:\\Windows\\Temp\\x.exe", &d), PathClass::TempOrDownloads);
        assert_eq!(classify_path("C:\\Users\\a\\AppData\\Local\\Temp\\x.exe", &d), PathClass::TempOrDownloads);
        assert_eq!(classify_path("C:\\Users\\a\\Downloads\\setup.exe", &d), PathClass::TempOrDownloads);
        assert_eq!(classify_path("C:\\Users\\a\\AppData\\Roaming\\x.exe", &d), PathClass::UserWritable);
        assert_eq!(classify_path("C:\\ProgramData\\x\\y.exe", &d), PathClass::UserWritable);
        assert_eq!(classify_path("C:\\Program Files\\App\\app.exe", &d), PathClass::ProgramFiles);
        assert_eq!(classify_path("D:\\Tools\\tool.exe", &d), PathClass::Other);
        assert_eq!(classify_path("D:\\Tools\\Temp\\tool.exe", &d), PathClass::Other);
        assert_eq!(classify_path("D:\\Scratch\\run.exe", &d), PathClass::TempOrDownloads);
    }

    #[test]
    fn genuine_system_process_is_quiet() {
        let (_, f) = assess(900, "svchost.exe", "C:\\Windows\\System32\\svchost.exe", Some(&sig(SignatureState::Valid)), &dirs());
        assert!(f.is_empty(), "{f:?}");
        let (_, f) = assess(901, "explorer.exe", "C:\\Windows\\explorer.exe", Some(&sig(SignatureState::Valid)), &dirs());
        assert!(f.is_empty(), "{f:?}");
    }

    #[test]
    fn masquerading_system_name_is_high() {
        let (class, f) = assess(
            1234,
            "svchost.exe",
            "C:\\Users\\a\\AppData\\Roaming\\svchost.exe",
            Some(&sig(SignatureState::Unsigned)),
            &dirs(),
        );
        assert_eq!(class, PathClass::UserWritable);
        assert!(f.iter().any(|x| x.severity == Severity::High && x.title.contains("unexpected location")));
        assert!(f.iter().any(|x| x.title.contains("Unsigned image running from a user-writable")));
    }

    #[test]
    fn name_mismatch_and_temp_unsigned() {
        let (_, f) = assess(77, "notepad.exe", "C:\\Users\\a\\AppData\\Local\\Temp\\payload.exe", Some(&sig(SignatureState::Unsigned)), &dirs());
        assert!(f.iter().any(|x| x.title.contains("does not match")));
        assert!(f.iter().any(|x| x.severity == Severity::High && x.title.contains("temp/download")));
    }

    #[test]
    fn lineage_rules() {
        assert_eq!(assess_lineage("powershell.exe", "WINWORD.EXE").map(|x| x.0), Some(Severity::High));
        assert_eq!(assess_lineage("mshta.exe", "chrome.exe").map(|x| x.0), Some(Severity::Medium));
        assert_eq!(assess_lineage("svchost.exe", "services.exe"), None);
        assert_eq!(assess_lineage("svchost.exe", "explorer.exe").map(|x| x.0), Some(Severity::High));
        assert_eq!(assess_lineage("lsass.exe", "wininit.exe"), None);
        assert_eq!(assess_lineage("cmd.exe", "explorer.exe"), None);
        assert_eq!(assess_lineage("chrome.exe", "chrome.exe"), None);
    }

    #[test]
    fn untrusted_signature_is_graded_like_unsigned() {
        let (_, f) = assess(5, "game.exe", "D:\\Games\\game.exe", Some(&sig(SignatureState::Untrusted)), &dirs());
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Low);
        assert!(f[0].title.contains("untrusted"), "{}", f[0].title);
    }

    #[test]
    fn invalid_signature_is_high_anywhere() {
        let (_, f) = assess(5, "app.exe", "C:\\Program Files\\App\\app.exe", Some(&sig(SignatureState::Invalid)), &dirs());
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::High);
    }
}
