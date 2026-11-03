//! Driver audit: the kernel's own view of drivers. Detection only.
//!
//! Checks how Windows guards driver loading (signature enforcement, test
//! signing, kernel debugging, memory integrity, the vulnerable-driver
//! blocklist), compares the kernel modules actually loaded with the registered
//! drivers, and matches driver file names against a short list of drivers
//! publicly documented as abused to gain kernel access.

use crate::findings::{Finding, Severity};
use crate::inventory::{SystemInventory, image_path_from_command};
use crate::persistence_audit::{EntryKind, subject};
use crate::process_inventory::{KnownDirs, PathClass, classify_path};
use crate::signature::{SignatureCache, SignatureInfo, SignatureState};
use crate::winutil::{device_path_to_dos, dos_devices, wide, windows_directory};
use std::collections::{HashMap, HashSet};
use std::ffi::c_void;
use std::ptr::null_mut;

pub const MODULE: &str = "driver_audit";
const CODE_INTEGRITY: &str = "code integrity";

// SYSTEM_CODEINTEGRITY_INFORMATION.CodeIntegrityOptions bits.
const CI_ENABLED: u32 = 0x01;
const CI_TESTSIGN: u32 = 0x02;
const CI_DEBUGMODE: u32 = 0x80;
const CI_HVCI_KMCI: u32 = 0x400;

/// Driver files publicly documented as abused to gain kernel access ("bring your
/// own vulnerable driver"). Matched by file name only, so a hit is a lead, not proof.
const ABUSABLE_DRIVERS: &[&str] = &[
    "asrdrv101.sys",
    "asrdrv102.sys",
    "asrdrv103.sys",
    "asrdrv104.sys",
    "asrdrv105.sys",
    "asrdrv106.sys",
    "capcom.sys",
    "cpuz141.sys",
    "dbutil_2_3.sys",
    "elrawdsk.sys",
    "gdrv.sys",
    "inpoutx64.sys",
    "iqvw64e.sys",
    "kprocesshacker.sys",
    "mhyprot2.sys",
    "msio64.sys",
    "rtcore32.sys",
    "rtcore64.sys",
    "rwdrv.sys",
    "rzpnk.sys",
    "speedfan.sys",
    "truesight.sys",
    "winio64.sys",
    "winring0.sys",
    "winring0x64.sys",
    "zam64.sys",
    "zamguard64.sys",
];

/// How Windows guards driver loading. `blocklist` is the registry switch for
/// Microsoft's vulnerable-driver blocklist (absent means the default: on).
pub fn assess_code_integrity(options: u32, blocklist: Option<u32>) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut push = |severity, title: &str, detail: &str| {
        out.push(Finding::new(MODULE, severity, CODE_INTEGRITY, title).detail(format!("{detail} (CodeIntegrityOptions 0x{options:X})")));
    };
    if options & CI_ENABLED == 0 {
        push(Severity::Critical, "Driver signature enforcement is off", "Windows will load kernel drivers without checking their signatures.");
    }
    if options & CI_TESTSIGN != 0 {
        push(Severity::High, "Test-signing mode is on", "Windows accepts drivers signed with any test certificate (bcdedit /set testsigning on).");
    }
    if options & CI_DEBUGMODE != 0 {
        push(Severity::Medium, "Kernel debugging is enabled", "A kernel debugger can be attached, which also relaxes driver signature checks.");
    }
    if options & CI_HVCI_KMCI == 0 {
        push(Severity::Low, "Memory integrity (HVCI) is off", "Windows Security > Device security > Core isolation > Memory integrity.");
    }
    if blocklist == Some(0) {
        out.push(
            Finding::new(MODULE, Severity::Medium, CODE_INTEGRITY, "Microsoft's vulnerable driver blocklist is turned off")
                .detail(r"HKLM\SYSTEM\CurrentControlSet\Control\CI\Config\VulnerableDriverBlocklistEnable = 0"),
        );
    }
    out
}

/// One kernel module from the kernel's loaded-module list.
pub struct LoadedModule<'a> {
    pub path: &'a str,
    /// `None` when the path could not be decoded reliably (non-ASCII names).
    pub exists: Option<bool>,
    pub class: PathClass,
    pub signature: Option<&'a SignatureInfo>,
}

/// A loaded kernel module that no registered driver accounts for. Windows' own
/// boot and export modules (ntoskrnl, hal, …) are unregistered too, so modules
/// under the Windows folder are only flagged on signature problems.
pub fn assess_unregistered(m: &LoadedModule) -> Option<Finding> {
    let file = file_name(m.path);
    let finding = |severity, title: &str, detail: String| {
        let f = Finding::new(MODULE, severity, format!("kernel module {file}"), title).detail(detail);
        Some(if m.exists == Some(true) { f.file(m.path) } else { f })
    };
    if m.exists == Some(false) {
        return finding(
            Severity::High,
            "Loaded kernel module's file is missing",
            format!("{} is loaded in the kernel but is not on disk and has no driver registration.", m.path),
        );
    }
    if let Some(sig) = m.signature.filter(|s| s.state == SignatureState::Invalid) {
        return finding(Severity::High, "Loaded kernel module's signature does not verify", format!("{}: {}", m.path, sig.summary()));
    }
    if let Some(sig) = m.signature.filter(|s| s.state.lacks_assurance()) {
        return finding(Severity::High, "Loaded kernel module has no trusted signature", format!("{}: {}", m.path, sig.summary()));
    }
    match m.class {
        PathClass::TempOrDownloads | PathClass::UserWritable => finding(
            Severity::High,
            "Kernel module loaded from a user-writable folder",
            format!("{} is loaded in the kernel without a driver registration.", m.path),
        ),
        PathClass::ProgramFiles | PathClass::Other => finding(
            Severity::Medium,
            "Kernel module loaded without a driver registration",
            format!(
                "{} is loaded in the kernel, but no registered driver points to it. Some hardware and anti-cheat tools remove their registration after loading.",
                m.path
            ),
        ),
        PathClass::Windows => None,
    }
}

/// Whether a driver file name is on the built-in list of abused drivers.
pub fn is_abusable(path: &str) -> bool {
    ABUSABLE_DRIVERS.contains(&file_name(path).to_lowercase().as_str())
}

fn abusable_finding(subject: String, path: &str, loaded: bool) -> Finding {
    let (severity, title) = if loaded {
        (Severity::Medium, format!("Known-abusable driver is loaded: {}", file_name(path)))
    } else {
        (Severity::Low, format!("Known-abusable driver is installed: {}", file_name(path)))
    };
    Finding::new(MODULE, severity, subject, title)
        .detail(format!(
            "{path}. This file name matches a driver publicly documented as abused to gain kernel access (bring your own vulnerable driver)."
        ))
        .file(path)
}

pub struct DriverAudit {
    pub findings: Vec<Finding>,
    pub summary: String,
}

pub fn scan(inv: &SystemInventory, cache: &mut SignatureCache, dirs: &KnownDirs) -> DriverAudit {
    let mut findings = Vec::new();
    let mut notes = Vec::new();
    match code_integrity_options() {
        Some(options) => {
            let blocklist = registry_dword(r"SYSTEM\CurrentControlSet\Control\CI\Config", "VulnerableDriverBlocklistEnable");
            findings.extend(assess_code_integrity(options, blocklist));
            notes.push(format!(
                "signature enforcement {}, memory integrity {}, vulnerable-driver blocklist {}",
                if options & CI_ENABLED != 0 { "on" } else { "OFF" },
                if options & CI_HVCI_KMCI != 0 { "on" } else { "off" },
                if blocklist == Some(0) { "off" } else { "on" },
            ));
        }
        None => notes.push("code integrity state unreadable".into()),
    }

    // Registered drivers by resolved path, plus their names for path-less entries.
    let windows = windows_directory().unwrap_or_else(|| r"C:\Windows".into());
    let mut registered: HashMap<String, &str> = HashMap::new();
    for d in &inv.drivers {
        let path = image_path_from_command(&d.binary_path).unwrap_or_else(|| format!(r"{windows}\System32\drivers\{}.sys", d.name));
        registered.insert(path.to_lowercase(), &d.name);
    }
    let names: HashSet<String> = inv.drivers.iter().map(|d| format!("{}.sys", d.name.to_lowercase())).collect();
    let registered_files: HashSet<String> = registered.keys().map(|p| file_name(p).to_string()).collect();

    let mut loaded_paths = HashSet::new();
    match loaded_kernel_modules() {
        Ok(modules) => {
            let devices = dos_devices();
            let mut unregistered = 0;
            for raw in &modules {
                let ascii = raw.is_ascii();
                let path = kernel_path_to_dos(raw, &windows, &devices);
                let class = classify_path(&path, dirs);
                let path = match class {
                    PathClass::Windows => crash_dump_source(&path).unwrap_or(path),
                    _ => path,
                };
                let lower = path.to_lowercase();
                loaded_paths.insert(lower.clone());
                let file = file_name(&lower).to_string();
                let in_windows = class == PathClass::Windows;
                let is_registered = registered.contains_key(&lower)
                    || (in_windows && (registered_files.contains(&file) || names.contains(&file)));
                if is_abusable(&path) && !is_registered {
                    findings.push(abusable_finding(format!("kernel module {}", file_name(&path)), &path, true));
                }
                if is_registered {
                    continue;
                }
                unregistered += 1;
                let exists = ascii.then(|| std::path::Path::new(&path).exists());
                let signature = if exists == Some(true) { cache.get(&path) } else { None };
                findings.extend(assess_unregistered(&LoadedModule { path: &path, exists, class, signature: signature.as_ref() }));
            }
            notes.push(format!("{} kernel modules loaded, {unregistered} without a driver registration", modules.len()));
        }
        Err(e) => {
            findings.push(Finding::new(MODULE, Severity::Low, "kernel modules", "Loaded kernel modules could not be listed").detail(e.clone()));
            notes.push("loaded kernel modules unreadable".into());
        }
    }

    // Registered drivers on the abused-driver list: loaded matters more than installed.
    for (path, name) in &registered {
        if !is_abusable(path) {
            continue;
        }
        let running = inv.drivers.iter().any(|d| &d.name.as_str() == name && d.state.eq_ignore_ascii_case("running"));
        let loaded = running || loaded_paths.contains(path);
        if loaded || std::path::Path::new(path).exists() {
            findings.push(abusable_finding(subject(EntryKind::Driver, name, ""), path, loaded));
        }
    }
    let summary = format!("Drivers: {}", notes.join("; "));
    DriverAudit { findings, summary }
}

fn file_name(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

/// Windows loads in-memory copies of the storage drivers for crash dumps and
/// hibernation as `dump_<driver>` and `hiber_<driver>`; only `<driver>` exists on disk.
fn crash_dump_source(path: &str) -> Option<String> {
    let file = file_name(path);
    let lower = file.to_lowercase();
    let stripped = ["dump_", "hiber_"].iter().find_map(|p| lower.starts_with(p).then(|| &file[p.len()..]))?;
    Some(format!("{}{stripped}", &path[..path.len() - file.len()]))
}

/// Kernel module paths come as `\SystemRoot\…`, `\??\C:\…`, `\Windows\…`,
/// `\Device\HarddiskVolumeN\…` or `System32\…`.
fn kernel_path_to_dos(raw: &str, windows: &str, devices: &[(String, String)]) -> String {
    let lower = raw.to_lowercase();
    if lower.starts_with(r"\device\") {
        return device_path_to_dos(raw, devices);
    }
    if lower.starts_with(r"\windows\") {
        return format!("{}{raw}", &windows[..2.min(windows.len())]);
    }
    let path = raw.strip_prefix(r"\??\").unwrap_or(raw);
    let lower = path.to_lowercase();
    if lower.starts_with(r"\systemroot\") {
        format!("{windows}{}", &path[r"\SystemRoot".len()..])
    } else if !path.contains(':') && !path.starts_with('\\') {
        format!(r"{windows}\{path}")
    } else {
        path.to_string()
    }
}

/// CodeIntegrityOptions from NtQuerySystemInformation(SystemCodeIntegrityInformation).
fn code_integrity_options() -> Option<u32> {
    use windows_sys::Wdk::System::SystemInformation::NtQuerySystemInformation;
    const SYSTEM_CODE_INTEGRITY_INFORMATION: i32 = 103;
    let mut info = [8u32, 0u32]; // Length, CodeIntegrityOptions
    let status = unsafe {
        NtQuerySystemInformation(SYSTEM_CODE_INTEGRITY_INFORMATION, info.as_mut_ptr() as *mut c_void, 8, null_mut())
    };
    (status >= 0).then_some(info[1])
}

fn registry_dword(subkey: &str, value: &str) -> Option<u32> {
    use windows_sys::Win32::System::Registry::{HKEY_LOCAL_MACHINE, RRF_RT_REG_DWORD, RegGetValueW};
    let (subkey, value) = (wide(subkey), wide(value));
    let mut data = 0u32;
    let mut size = 4u32;
    let status = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            subkey.as_ptr(),
            value.as_ptr(),
            RRF_RT_REG_DWORD,
            null_mut(),
            &mut data as *mut u32 as *mut c_void,
            &mut size,
        )
    };
    (status == 0).then_some(data)
}

/// RTL_PROCESS_MODULE_INFORMATION on 64-bit Windows: FullPathName[256] at +40.
const MODULE_ENTRY_SIZE: usize = 296;
const MODULE_PATH_OFFSET: usize = 40;

/// Full paths of the kernel modules currently loaded, from the kernel's own list
/// (NtQuerySystemInformation(SystemModuleInformation)).
pub fn loaded_kernel_modules() -> Result<Vec<String>, String> {
    use windows_sys::Wdk::System::SystemInformation::NtQuerySystemInformation;
    const SYSTEM_MODULE_INFORMATION: i32 = 11;
    const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC000_0004_u32 as i32;
    let mut size = 1usize << 17;
    for _ in 0..5 {
        let mut buffer = vec![0u64; size / 8];
        let mut needed = 0u32;
        let status = unsafe {
            NtQuerySystemInformation(SYSTEM_MODULE_INFORMATION, buffer.as_mut_ptr() as *mut c_void, (buffer.len() * 8) as u32, &mut needed)
        };
        if status == STATUS_INFO_LENGTH_MISMATCH {
            size = (needed as usize).max(size * 2) + 4096;
            continue;
        }
        if status < 0 {
            return Err(format!("SystemModuleInformation query failed (NTSTATUS 0x{:08X})", status as u32));
        }
        let bytes = unsafe { std::slice::from_raw_parts(buffer.as_ptr() as *const u8, buffer.len() * 8) };
        return Ok(parse_module_list(bytes));
    }
    Err("The kernel module list kept growing while it was read".into())
}

/// RTL_PROCESS_MODULES: a u32 count, then entries from offset 8.
fn parse_module_list(bytes: &[u8]) -> Vec<String> {
    let Some(count) = bytes.get(..4).map(|b| u32::from_le_bytes(b.try_into().unwrap()) as usize) else {
        return Vec::new();
    };
    (0..count)
        .map_while(|i| bytes.get(8 + i * MODULE_ENTRY_SIZE..8 + (i + 1) * MODULE_ENTRY_SIZE))
        .map(|entry| {
            let name = &entry[MODULE_PATH_OFFSET..];
            let end = name.iter().position(|&b| b == 0).unwrap_or(name.len());
            String::from_utf8_lossy(&name[..end]).into_owned()
        })
        .filter(|p| !p.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sig(state: SignatureState) -> SignatureInfo {
        SignatureInfo { state, signer: String::new(), via_catalog: false, status_code: 0 }
    }

    fn titles(findings: &[Finding]) -> Vec<(Severity, &str)> {
        findings.iter().map(|f| (f.severity, f.title.as_str())).collect()
    }

    #[test]
    fn code_integrity_flags() {
        let healthy = CI_ENABLED | CI_HVCI_KMCI;
        assert!(assess_code_integrity(healthy, None).is_empty());
        assert!(assess_code_integrity(healthy, Some(1)).is_empty());
        let f = assess_code_integrity(CI_TESTSIGN | CI_DEBUGMODE, Some(0));
        let t = titles(&f);
        assert!(t.contains(&(Severity::Critical, "Driver signature enforcement is off")), "{t:?}");
        assert!(t.contains(&(Severity::High, "Test-signing mode is on")));
        assert!(t.contains(&(Severity::Medium, "Kernel debugging is enabled")));
        assert!(t.contains(&(Severity::Low, "Memory integrity (HVCI) is off")));
        assert!(t.contains(&(Severity::Medium, "Microsoft's vulnerable driver blocklist is turned off")));
    }

    #[test]
    fn unregistered_modules() {
        let valid = sig(SignatureState::Valid);
        let unsigned = sig(SignatureState::Unsigned);
        let module = |path, exists, class, signature| LoadedModule { path, exists, class, signature };
        // Windows' own unregistered modules are quiet unless their signature is wrong.
        assert!(assess_unregistered(&module(r"C:\Windows\System32\ntoskrnl.exe", Some(true), PathClass::Windows, Some(&valid))).is_none());
        let f = assess_unregistered(&module(r"C:\Windows\System32\drivers\x.sys", Some(true), PathClass::Windows, Some(&unsigned))).unwrap();
        assert_eq!((f.severity, f.subject.as_str()), (Severity::High, "kernel module x.sys"));
        assert_eq!(f.file.as_deref(), Some(r"C:\Windows\System32\drivers\x.sys"));
        let f = assess_unregistered(&module(r"C:\Tools\hw.sys", Some(true), PathClass::Other, Some(&valid))).unwrap();
        assert_eq!(f.severity, Severity::Medium);
        let f = assess_unregistered(&module(r"C:\Users\a\AppData\Local\Temp\x.sys", Some(true), PathClass::TempOrDownloads, Some(&valid))).unwrap();
        assert_eq!(f.severity, Severity::High);
        let f = assess_unregistered(&module(r"C:\Tools\gone.sys", Some(false), PathClass::Other, None)).unwrap();
        assert_eq!((f.severity, f.file.is_none()), (Severity::High, true));
        // Undecodable (non-ASCII) paths are not reported as missing.
        assert!(assess_unregistered(&module(r"C:\Windows\System32\drivers\?.sys", None, PathClass::Windows, None)).is_none());
    }

    #[test]
    fn abusable_names_match_case_insensitively() {
        assert!(is_abusable(r"C:\Program Files\Tool\RTCore64.sys"));
        assert!(is_abusable(r"C:\Windows\System32\drivers\WinRing0x64.sys"));
        assert!(!is_abusable(r"C:\Windows\System32\drivers\ntfs.sys"));
        let f = abusable_finding("driver RTCore64".into(), r"C:\x\RTCore64.sys", true);
        assert_eq!(f.severity, Severity::Medium);
        assert_eq!(abusable_finding("driver RTCore64".into(), r"C:\x\RTCore64.sys", false).severity, Severity::Low);
    }

    #[test]
    fn kernel_paths_become_drive_paths() {
        let devices = vec![(r"\Device\HarddiskVolume3".to_string(), "C:".to_string())];
        let w = r"C:\Windows";
        assert_eq!(kernel_path_to_dos(r"\SystemRoot\system32\ntoskrnl.exe", w, &devices), r"C:\Windows\system32\ntoskrnl.exe");
        assert_eq!(kernel_path_to_dos(r"\??\C:\Tools\x.sys", w, &devices), r"C:\Tools\x.sys");
        assert_eq!(kernel_path_to_dos(r"\Windows\System32\drivers\a.sys", w, &devices), r"C:\Windows\System32\drivers\a.sys");
        assert_eq!(kernel_path_to_dos(r"\Device\HarddiskVolume3\Tools\b.sys", w, &devices), r"C:\Tools\b.sys");
        assert_eq!(kernel_path_to_dos(r"System32\drivers\c.sys", w, &devices), r"C:\Windows\System32\drivers\c.sys");
    }

    #[test]
    fn crash_dump_copies_map_to_their_source_driver() {
        assert_eq!(crash_dump_source(r"C:\Windows\System32\drivers\dump_examplestor.sys").as_deref(), Some(r"C:\Windows\System32\drivers\examplestor.sys"));
        assert_eq!(crash_dump_source(r"C:\Windows\System32\Drivers\Dump_dumpexample.sys").as_deref(), Some(r"C:\Windows\System32\Drivers\dumpexample.sys"));
        assert_eq!(crash_dump_source(r"C:\Windows\System32\drivers\hiber_examplestor.sys").as_deref(), Some(r"C:\Windows\System32\drivers\examplestor.sys"));
        assert_eq!(crash_dump_source(r"C:\Windows\System32\drivers\example.sys"), None);
    }

    #[test]
    fn module_list_parsing() {
        let mut bytes = vec![0u8; 8 + 2 * MODULE_ENTRY_SIZE];
        bytes[..4].copy_from_slice(&2u32.to_le_bytes());
        for (i, name) in [r"\SystemRoot\system32\ntoskrnl.exe", r"\??\C:\Tools\x.sys"].iter().enumerate() {
            let at = 8 + i * MODULE_ENTRY_SIZE + MODULE_PATH_OFFSET;
            bytes[at..at + name.len()].copy_from_slice(name.as_bytes());
        }
        assert_eq!(parse_module_list(&bytes), vec![r"\SystemRoot\system32\ntoskrnl.exe", r"\??\C:\Tools\x.sys"]);
        // A count larger than the buffer stops at the buffer's end.
        bytes[..4].copy_from_slice(&9u32.to_le_bytes());
        assert_eq!(parse_module_list(&bytes).len(), 2);
    }

    #[test]
    fn live_kernel_module_list() {
        let modules = loaded_kernel_modules().expect("module list");
        assert!(modules.len() > 50, "{}", modules.len());
        assert!(modules[0].to_lowercase().contains("ntoskrnl") || modules.iter().any(|m| m.to_lowercase().contains("ntoskrnl")));
        assert!(code_integrity_options().is_some_and(|o| o & CI_ENABLED != 0), "signature enforcement on");
    }
}
