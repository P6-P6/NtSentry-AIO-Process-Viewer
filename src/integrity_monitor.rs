//! Module A: ntdll.dll integrity monitor. Detection only.
//!
//! What is compared:
//! * the on-disk file's SHA-256, size and Authenticode result against the baseline;
//! * every executable section of the ntdll mapped in *this* process against the
//!   baseline snapshot (primary signal), and against the on-disk file (secondary).
//!
//! Mapped bytes are copied out with `ReadProcessMemory` on our own process and
//! the copy is "un-relocated" so that it is comparable across boots. This module
//! never writes to, re-protects, or restores any memory.
//!
//! Limitation: only the ntdll mapping inside the dashboard process is inspected.
//! A hook placed only in some other process is not visible here.

use crate::findings::{Finding, Severity, sort_findings};
use crate::pe::{Export, ImageIdentity, OverrideSite, PeImage, unrelocate};
use crate::signature::{SignatureInfo, SignatureState, signature_info};
use crate::storage::{DataDir, write_new};
use crate::winutil::{device_path_to_dos, dos_devices, from_wide, hex, now_unix, sha256_hex, system_directory, wide};
use serde::{Deserialize, Serialize};
use std::ffi::c_void;
use std::mem::{size_of, zeroed};
use std::path::{Path, PathBuf};
use std::time::Instant;
use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows_sys::Win32::System::LibraryLoader::{GetModuleFileNameW, GetModuleHandleW};
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE, PAGE_EXECUTE_READ,
    PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_READWRITE, PAGE_WRITECOPY, VirtualQuery,
};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

pub const MODULE: &str = "integrity_monitor";
pub const BASELINE_SCHEMA: u32 = 1;
/// Differences closer than this many equal bytes are reported as one run.
const MERGE_GAP: usize = 4;
/// A difference within this many bytes of an export's entry point looks like an inline hook.
const HOOK_WINDOW: u32 = 16;
const MAX_RUNS_PER_SECTION: usize = 64;
const SHOW_BYTES: usize = 32;
const PAGE: usize = 0x1000;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BaselineSection {
    pub name: String,
    pub rva: u32,
    pub len: u32,
    /// SHA-256 of the un-relocated mapped bytes stored in `file`.
    pub sha256: String,
    pub file: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Baseline {
    pub schema_version: u32,
    pub captured_unix: u64,
    pub ntdll_path: String,
    pub file_size: u64,
    pub file_sha256: String,
    pub signature: SignatureInfo,
    pub image: ImageIdentity,
    pub preferred_base: u64,
    pub sections: Vec<BaselineSection>,
    /// Disk-vs-memory difference runs already present when the baseline was taken
    /// (for example a security product's hooks). They are absorbed into the baseline.
    pub disk_vs_memory_runs_at_capture: usize,
}

pub struct LoadedBaseline {
    pub meta: Baseline,
    /// Section bytes aligned with `meta.sections`; `None` when missing or altered.
    pub sections: Vec<Option<Vec<u8>>>,
    pub problems: Vec<Finding>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct IntegrityReport {
    pub scanned_unix: u64,
    pub duration_ms: u128,
    pub ntdll_path: String,
    pub file_size: u64,
    pub file_sha256: String,
    pub signature: Option<SignatureInfo>,
    pub loaded_base: Option<u64>,
    pub baseline_captured_unix: Option<u64>,
    pub sections_checked: Vec<String>,
    pub disk_vs_memory_runs: usize,
    pub baseline_deviation_runs: usize,
    pub findings: Vec<Finding>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CaptureOutcome {
    pub directory: PathBuf,
    pub baseline: Baseline,
    pub findings: Vec<Finding>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Run {
    pub start: usize,
    pub end: usize,
}

/// Byte ranges where `a` and `b` differ, over their common length. Runs separated by
/// fewer than `merge_gap` equal bytes are merged.
pub fn diff_runs(a: &[u8], b: &[u8], merge_gap: usize) -> Vec<Run> {
    let mut runs: Vec<Run> = Vec::new();
    for (i, (x, y)) in a.iter().zip(b).enumerate() {
        if x == y {
            continue;
        }
        match runs.last_mut() {
            Some(last) if i - last.end <= merge_gap => last.end = i + 1,
            _ => runs.push(Run { start: i, end: i + 1 }),
        }
    }
    runs
}

fn show(bytes: &[u8]) -> String {
    if bytes.len() > SHOW_BYTES {
        format!("{} … (+{} bytes)", hex(&bytes[..SHOW_BYTES]), bytes.len() - SHOW_BYTES)
    } else {
        hex(bytes)
    }
}

/// `NtOpenProcess+0x3`, and whether the range touches an export's first bytes.
fn locate(exports: &[Export], start_rva: u32, end_rva: u32) -> (String, bool) {
    let after = exports.partition_point(|e| e.rva <= start_rva);
    let at_entry = exports[..after].last().is_some_and(|e| start_rva - e.rva < HOOK_WINDOW)
        || exports.get(after).is_some_and(|e| e.rva < end_rva);
    let label = match exports[..after].last() {
        Some(e) if e.rva == start_rva => e.name.clone(),
        Some(e) => format!("{}+0x{:X}", e.name, start_rva - e.rva),
        None => format!("rva 0x{start_rva:X}"),
    };
    (label, at_entry)
}

pub struct SectionView<'a> {
    pub name: &'a str,
    pub rva: u32,
    /// On-disk bytes of the same build, when the loaded image matches the file.
    pub disk: Option<&'a [u8]>,
    /// Un-relocated mapped bytes.
    pub memory: &'a [u8],
    pub baseline: Option<&'a [u8]>,
    /// Section-relative ranges already checked by a dedicated rule (function-override
    /// sites). Difference runs lying entirely inside one are not reported again.
    pub explained: &'a [Run],
}

#[derive(Default)]
pub struct SectionComparison {
    pub findings: Vec<Finding>,
    pub disk_runs: usize,
    pub baseline_runs: usize,
}

/// With a baseline, deviations from it are reported and disk-vs-memory differences
/// that were already present at capture time are summarised as Info. Without one,
/// every disk-vs-memory difference is reported.
pub fn compare_section(view: &SectionView, exports: &[Export]) -> SectionComparison {
    let subject = format!("ntdll.dll {}", view.name);
    let mut out = SectionComparison::default();
    let unexplained = |runs: Vec<Run>| -> Vec<Run> {
        runs.into_iter()
            .filter(|r| !view.explained.iter().any(|e| e.start <= r.start && r.end <= e.end))
            .collect()
    };
    let disk_runs = view.disk.map(|d| unexplained(diff_runs(d, view.memory, MERGE_GAP))).unwrap_or_default();
    out.disk_runs = disk_runs.len();
    let (reference, runs, against) = match (view.baseline, view.disk) {
        (Some(b), _) => (b, unexplained(diff_runs(b, view.memory, MERGE_GAP)), "baseline"),
        (None, Some(d)) => (d, disk_runs.clone(), "on-disk image"),
        (None, None) => return out,
    };
    if view.baseline.is_some() {
        out.baseline_runs = runs.len();
        let absorbed = disk_runs
            .iter()
            .filter(|d| !runs.iter().any(|r| r.start < d.end && d.start < r.end))
            .count();
        if absorbed > 0 {
            out.findings.push(
                Finding::new(MODULE, Severity::Info, &subject, "Known differences from disk, unchanged since baseline")
                    .detail(format!(
                        "{absorbed} run(s) where memory differs from the on-disk file were already present when the \
                         baseline was captured (commonly security-product hooks). They have not changed."
                    )),
            );
        }
    }
    for run in runs.iter().take(MAX_RUNS_PER_SECTION) {
        let start_rva = view.rva + run.start as u32;
        let (label, at_entry) = locate(exports, start_rva, view.rva + run.end as u32);
        let severity = if at_entry { Severity::High } else { Severity::Medium };
        let title = if at_entry {
            format!("Possible inline hook at {label}: memory differs from {against}")
        } else {
            format!("Memory differs from {against} at {label}")
        };
        let mut detail = format!("{} byte(s) at RVA 0x{start_rva:X}.", run.end - run.start);
        if let (Some(_), Some(disk)) = (view.baseline, view.disk) {
            let d = &disk[run.start..run.end];
            detail.push_str(if d == &view.memory[run.start..run.end] {
                " On-disk bytes match memory here; the baseline differs."
            } else if d == &reference[run.start..run.end] {
                " On-disk bytes match the baseline; only memory changed."
            } else {
                " On-disk bytes match neither."
            });
        }
        out.findings.push(
            Finding::new(MODULE, severity, &subject, title).detail(detail).bytes(
                u64::from(start_rva),
                show(&reference[run.start..run.end]),
                show(&view.memory[run.start..run.end]),
            ),
        );
    }
    if runs.len() > MAX_RUNS_PER_SECTION {
        out.findings.push(
            Finding::new(MODULE, Severity::High, &subject, "Many differing byte runs")
                .detail(format!("{} runs differ from the {against}; only the first {MAX_RUNS_PER_SECTION} are listed.", runs.len())),
        );
    }
    out
}

// ---------------------------------------------------------------------------
// Observation (read-only)

pub fn ntdll_path() -> Result<String, String> {
    let dir = system_directory().ok_or("GetSystemDirectoryW failed")?;
    Ok(format!("{}\\ntdll.dll", dir.trim_end_matches('\\')))
}

struct Mapped {
    base: usize,
    path: String,
    image: Vec<u8>,
    /// (offset, length) ranges that could not be read; zero-filled in `image`.
    unreadable: Vec<(usize, usize)>,
}

/// Copies `len` bytes of our own address space starting at `addr`, page by page
/// on failure. The source is never modified.
fn read_own_memory(addr: usize, len: usize) -> (Vec<u8>, Vec<(usize, usize)>) {
    read_process_memory(unsafe { GetCurrentProcess() }, addr, len)
}

/// Copies `len` bytes at `addr` from a process opened with `PROCESS_VM_READ`,
/// page by page on failure; unreadable ranges are zero-filled and returned.
fn read_process_memory(process: windows_sys::Win32::Foundation::HANDLE, addr: usize, len: usize) -> (Vec<u8>, Vec<(usize, usize)>) {
    let mut out = vec![0u8; len];
    let mut unreadable = Vec::new();
    let mut read = 0usize;
    let whole = unsafe {
        ReadProcessMemory(process, addr as *const c_void, out.as_mut_ptr() as *mut c_void, len, &mut read)
    };
    if whole != 0 && read == len {
        return (out, unreadable);
    }
    let mut offset = 0;
    while offset < len {
        let chunk = (PAGE - (addr + offset) % PAGE).min(len - offset);
        let mut read = 0usize;
        let ok = unsafe {
            ReadProcessMemory(
                process,
                (addr + offset) as *const c_void,
                out[offset..].as_mut_ptr() as *mut c_void,
                chunk,
                &mut read,
            )
        };
        if ok == 0 || read != chunk {
            out[offset..offset + chunk].fill(0);
            match unreadable.last_mut() {
                Some((s, l)) if *s + *l == offset => *l += chunk,
                _ => unreadable.push((offset, chunk)),
            }
        }
        offset += chunk;
    }
    (out, unreadable)
}

fn map_ntdll() -> Result<Mapped, String> {
    let name = wide("ntdll.dll");
    let module = unsafe { GetModuleHandleW(name.as_ptr()) };
    if module.is_null() {
        return Err("ntdll.dll is not loaded in this process".into());
    }
    let mut buffer = [0u16; 1024];
    let len = unsafe { GetModuleFileNameW(module, buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
    let path = from_wide(&buffer[..len.min(buffer.len())]);
    let base = module as usize;
    let (header, bad) = read_own_memory(base, PAGE);
    if !bad.is_empty() {
        return Err("ntdll header page is unreadable".into());
    }
    let size = PeImage::parse_mapped(&header)?.identity.size_of_image as usize;
    if !(PAGE..=64 << 20).contains(&size) {
        return Err(format!("implausible mapped SizeOfImage 0x{size:X}"));
    }
    let (image, unreadable) = read_own_memory(base, size);
    Ok(Mapped { base, path, image, unreadable })
}

fn query(addr: usize) -> Option<MEMORY_BASIC_INFORMATION> {
    let mut info: MEMORY_BASIC_INFORMATION = unsafe { zeroed() };
    let got = unsafe { VirtualQuery(addr as *const c_void, &mut info, size_of::<MEMORY_BASIC_INFORMATION>()) };
    (got != 0 && info.RegionSize != 0).then_some(info)
}

fn is_executable(protect: u32) -> bool {
    [PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY].contains(&(protect & 0xFF))
}

/// Human-readable description of what backs an address, for findings.
fn describe_address(addr: usize) -> String {
    let Some(info) = query(addr) else { return format!("0x{addr:X}: not queryable") };
    let kind = match info.Type {
        MEM_IMAGE => "image",
        MEM_MAPPED => "mapped file",
        MEM_PRIVATE => "private",
        _ => "free/unknown",
    };
    format!(
        "0x{addr:X}: {kind} memory, allocation base 0x{:X}, protection 0x{:X}",
        info.AllocationBase as usize, info.Protect
    )
}

/// Executable, committed image pages that belong to ntdll's own allocation but lie
/// beyond SizeOfImage, as (start RVA, end RVA). Windows places function-override
/// code there; nothing else should.
fn appended_exec_regions(base: usize, size_of_image: u32) -> Vec<(u32, u32)> {
    let mut regions = Vec::new();
    let mut addr = base + size_of_image as usize;
    for _ in 0..64 {
        let Some(info) = query(addr) else { break };
        if info.AllocationBase as usize != base || info.Type != MEM_IMAGE {
            break;
        }
        let end = info.BaseAddress as usize + info.RegionSize;
        if info.State == MEM_COMMIT && is_executable(info.Protect) {
            regions.push(((addr - base) as u32, (end - base) as u32));
        }
        addr = end;
    }
    regions
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OverrideState {
    /// Same target as the file.
    Unchanged,
    /// The original function or one of the file's declared alternatives.
    DeclaredTarget,
    /// An executable page appended to ntdll's own image mapping.
    AppendedImagePage,
    /// Anywhere else: not explained by the function-override mechanism.
    Outside,
}

pub fn classify_override(site: &OverrideSite, file_target: Option<i64>, target: i64, appended: &[(u32, u32)]) -> OverrideState {
    if file_target == Some(target) {
        OverrideState::Unchanged
    } else if target == i64::from(site.original_rva) || site.targets.iter().any(|t| i64::from(*t) == target) {
        OverrideState::DeclaredTarget
    } else if appended.iter().any(|(lo, hi)| i64::from(*lo) <= target && target < i64::from(*hi)) {
        OverrideState::AppendedImagePage
    } else {
        OverrideState::Outside
    }
}

fn rel32_target(bytes: &[u8], at: usize, site_rva: u32) -> Option<i64> {
    let rel = i32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?);
    Some(i64::from(site_rva) + 4 + i64::from(rel))
}

/// Regions inside [start, start+len) whose current protection allows writing.
fn writable_regions(start: usize, len: usize) -> Vec<(usize, usize, u32)> {
    let mut regions = Vec::new();
    let end = start + len;
    let mut addr = start;
    while addr < end {
        let Some(info) = query(addr) else { break };
        let region_end = (info.BaseAddress as usize + info.RegionSize).min(end);
        let protect = info.Protect & 0xFF;
        if [PAGE_READWRITE, PAGE_WRITECOPY, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY].contains(&protect) {
            regions.push((addr - start, region_end - addr, info.Protect));
        }
        addr = region_end;
    }
    regions
}

struct ExecSection {
    name: String,
    rva: u32,
    disk: Option<Vec<u8>>,
    memory: Vec<u8>,
    /// Function-override sites, checked separately from the byte comparison.
    explained: Vec<Run>,
}

struct Observation {
    path: String,
    file_size: u64,
    file_sha256: String,
    disk_identity: ImageIdentity,
    preferred_base: u64,
    signature: Result<SignatureInfo, String>,
    exports: Vec<Export>,
    memory: Option<MemoryObservation>,
    findings: Vec<Finding>,
}

struct MemoryObservation {
    base: usize,
    loaded_path: String,
    identity: ImageIdentity,
    matches_disk: bool,
    sections: Vec<ExecSection>,
}

fn observe(with_memory: bool, baseline: Option<&Baseline>) -> Result<Observation, String> {
    let path = ntdll_path()?;
    let disk = std::fs::read(&path).map_err(|e| format!("Cannot read {path}: {e}"))?;
    let disk_pe = PeImage::parse(&disk).map_err(|e| format!("On-disk ntdll is not a parseable PE: {e}"))?;
    let mut findings = Vec::new();
    let mut obs = Observation {
        path: path.clone(),
        file_size: disk.len() as u64,
        file_sha256: sha256_hex(&disk),
        disk_identity: disk_pe.identity,
        preferred_base: disk_pe.image_base,
        signature: signature_info(&path),
        exports: disk_pe.exports().unwrap_or_default(),
        memory: None,
        findings: Vec::new(),
    };
    if !with_memory {
        return Ok(obs);
    }
    let mapped = map_ntdll()?;
    let mem_pe = PeImage::parse_mapped(&mapped.image).map_err(|e| format!("Mapped ntdll headers: {e}"))?;
    let matches_disk = mem_pe.identity == disk_pe.identity;
    // Relocations, overrides and the preferred base must come from the build that is actually mapped.
    let (overrides, unsupported_overrides) = if matches_disk { &disk_pe } else { &mem_pe }
        .function_overrides()
        .unwrap_or_else(|e| {
            findings.push(
                Finding::new(MODULE, Severity::Low, "ntdll.dll", "Function-override table could not be read")
                    .detail(format!("{e}. Override sites will be compared byte-for-byte like any other code.")),
            );
            (Vec::new(), 0)
        });
    if unsupported_overrides > 0 {
        findings.push(
            Finding::new(MODULE, Severity::Info, "ntdll.dll", "Unhandled dynamic relocation entries").detail(format!(
                "{unsupported_overrides} dynamic relocation entries are of kinds this monitor does not interpret; \
                 any bytes they patch are compared normally."
            )),
        );
    }
    let appended = appended_exec_regions(mapped.base, mem_pe.identity.size_of_image);
    let mut retargeted = Vec::new();
    let (relocs, unknown, preferred) = if matches_disk {
        let (r, u) = disk_pe.relocations()?;
        (r, u, disk_pe.image_base)
    } else {
        let (r, u) = mem_pe.relocations()?;
        let preferred = baseline
            .filter(|b| b.image == mem_pe.identity)
            .map_or(mem_pe.image_base, |b| b.preferred_base);
        obs.exports = mem_pe.exports().unwrap_or_default();
        (r, u, preferred)
    };
    if unknown > 0 {
        findings.push(
            Finding::new(MODULE, Severity::Info, "ntdll.dll", "Unhandled relocation types")
                .detail(format!("{unknown} relocation entries of unsupported types were not normalised; they may appear as differences.")),
        );
    }
    let delta = (mapped.base as u64).wrapping_sub(preferred);
    let loaded_path = mapped.path.clone();
    if !loaded_path.eq_ignore_ascii_case(&path) {
        findings.push(
            Finding::new(MODULE, Severity::High, "ntdll.dll", "ntdll is loaded from an unexpected path")
                .detail(format!("Loaded module path: {loaded_path}; expected {path}.")),
        );
    }
    if !matches_disk {
        findings.push(
            Finding::new(MODULE, Severity::Info, "ntdll.dll", "Loaded ntdll build differs from the on-disk file")
                .detail(format!(
                    "Mapped {:?} vs disk {:?}. Typical after an update that is waiting for a reboot. \
                     Disk-vs-memory comparison is skipped.",
                    mem_pe.identity, disk_pe.identity
                )),
        );
    }
    let mut sections = Vec::new();
    for section in mem_pe.executable_sections() {
        let mut memory = mem_pe.section_bytes(section)?.to_vec();
        let straddling = unrelocate(&mut memory, section.virtual_address, &relocs, delta);
        let subject = format!("ntdll.dll {}", section.name);
        if straddling > 0 {
            findings.push(
                Finding::new(MODULE, Severity::Info, &subject, "Relocation sites cross the section edge")
                    .detail(format!("{straddling} site(s) were not normalised.")),
            );
        }
        let lo = section.virtual_address as usize;
        let hi = lo + memory.len();
        for &(offset, len) in &mapped.unreadable {
            if offset < hi && lo < offset + len {
                findings.push(
                    Finding::new(MODULE, Severity::Medium, &subject, "Part of the section is unreadable")
                        .detail(format!("RVA 0x{offset:X}, {len} bytes could not be read; compared as zero.")),
                );
            }
        }
        for (offset, len, protect) in writable_regions(mapped.base + lo, memory.len()) {
            findings.push(
                Finding::new(MODULE, Severity::Medium, &subject, "Executable section is currently writable")
                    .detail(format!(
                        "RVA 0x{:X}, {len} bytes, protection 0x{protect:X}. Code pages are normally execute-read; \
                         writable code is unusual and often accompanies patching.",
                        lo + offset
                    )),
            );
        }
        let disk_bytes = if matches_disk {
            let disk_section = disk_pe
                .sections
                .iter()
                .find(|s| s.virtual_address == section.virtual_address && s.name == section.name)
                .ok_or_else(|| format!("section {} missing from disk image", section.name))?;
            Some(disk_pe.section_bytes(disk_section)?.to_vec())
        } else {
            None
        };
        let mut explained = Vec::new();
        for site in overrides.iter().filter(|o| lo as u32 <= o.site_rva && (o.site_rva as usize) + 4 <= hi) {
            let at = (site.site_rva - section.virtual_address) as usize;
            explained.push(Run { start: at, end: at + 4 });
            let Some(target) = rel32_target(&memory, at, site.site_rva) else { continue };
            let file_target = disk_bytes.as_deref().and_then(|d| rel32_target(d, at, site.site_rva));
            match classify_override(site, file_target, target, &appended) {
                OverrideState::Unchanged => {}
                OverrideState::DeclaredTarget | OverrideState::AppendedImagePage => {
                    retargeted.push(format!("0x{:X} -> rva 0x{target:X}", site.site_rva))
                }
                OverrideState::Outside => {
                    let (label, _) = locate(&obs.exports, site.original_rva, site.original_rva + 1);
                    let address = (mapped.base as i64 + target) as usize;
                    let mut f = Finding::new(
                        MODULE,
                        Severity::High,
                        &subject,
                        format!("Function-override thunk for {label} is redirected outside ntdll"),
                    )
                    .detail(format!(
                        "Thunk displacement at RVA 0x{:X} now targets {}. Windows only retargets these to declared \
                         alternatives or to code appended to ntdll's own mapping.",
                        site.site_rva,
                        describe_address(address)
                    ));
                    if let Some(d) = &disk_bytes {
                        f = f.bytes(u64::from(site.site_rva), hex(&d[at..at + 4]), hex(&memory[at..at + 4]));
                    }
                    findings.push(f);
                }
            }
        }
        sections.push(ExecSection {
            name: section.name.clone(),
            rva: section.virtual_address,
            disk: disk_bytes,
            memory,
            explained,
        });
    }
    if !retargeted.is_empty() {
        findings.push(
            Finding::new(MODULE, Severity::Info, "ntdll.dll", "Function-override thunks retargeted by Windows").detail(
                format!(
                    "{} site(s) declared in the signed file's dynamic relocation table point to a declared \
                     alternative or to code appended to ntdll's own image mapping: {}.",
                    retargeted.len(),
                    retargeted.join(", ")
                ),
            ),
        );
    }
    for &(start, end) in &appended {
        let len = (end - start) as usize;
        let (bytes, _) = read_own_memory(mapped.base + start as usize, len);
        let referenced = !retargeted.is_empty();
        let (severity, title) = if referenced {
            (Severity::Info, "Executable page appended to the ntdll mapping")
        } else {
            (Severity::Medium, "Unexplained executable page appended to the ntdll mapping")
        };
        findings.push(Finding::new(MODULE, severity, "ntdll.dll", title).detail(format!(
            "RVA 0x{start:X}-0x{end:X} ({len} bytes) lies past SizeOfImage inside ntdll's own image allocation; sha256 {}.{}",
            sha256_hex(&bytes),
            if referenced {
                " Referenced by Windows function-override thunks."
            } else {
                " No declared function override points here."
            }
        )));
    }
    obs.memory = Some(MemoryObservation {
        base: mapped.base,
        loaded_path,
        identity: mem_pe.identity,
        matches_disk,
        sections,
    });
    obs.findings = findings;
    Ok(obs)
}

// ---------------------------------------------------------------------------
// Baseline

pub fn load_baseline(data: &DataDir) -> Result<Option<LoadedBaseline>, String> {
    let dir = data.baseline_dir();
    let json_path = dir.join("baseline.json");
    if !json_path.exists() {
        return Ok(None);
    }
    let text = std::fs::read_to_string(&json_path).map_err(|e| format!("Cannot read {}: {e}", json_path.display()))?;
    let meta: Baseline =
        serde_json::from_str(&text).map_err(|e| format!("Baseline {} is not valid: {e}", json_path.display()))?;
    if meta.schema_version != BASELINE_SCHEMA {
        return Err(format!("Baseline schema {} is not supported (expected {BASELINE_SCHEMA})", meta.schema_version));
    }
    let mut sections = Vec::new();
    let mut problems = Vec::new();
    for s in &meta.sections {
        let subject = format!("baseline {}", s.name);
        // Only plain file names are accepted, so a baseline cannot point outside its directory.
        let path = Path::new(&s.file);
        if path.components().count() != 1 || path.is_absolute() {
            problems.push(Finding::new(MODULE, Severity::Critical, &subject, "Baseline references a file outside its directory")
                .detail(s.file.clone()));
            sections.push(None);
            continue;
        }
        match std::fs::read(dir.join(path)) {
            Ok(bytes) if sha256_hex(&bytes) == s.sha256 && bytes.len() == s.len as usize => sections.push(Some(bytes)),
            Ok(_) => {
                problems.push(
                    Finding::new(MODULE, Severity::Critical, &subject, "Baseline snapshot does not match its recorded hash")
                        .detail(format!("{} was altered or corrupted after capture; it is not used.", s.file)),
                );
                sections.push(None);
            }
            Err(e) => {
                problems.push(
                    Finding::new(MODULE, Severity::High, &subject, "Baseline snapshot is missing")
                        .detail(format!("{}: {e}", s.file)),
                );
                sections.push(None);
            }
        }
    }
    Ok(Some(LoadedBaseline { meta, sections, problems }))
}

/// Records the current state as known-good. Run on a machine you trust is clean.
/// Refuses when a baseline exists, when the file's signature does not verify, or
/// when the loaded build is not the on-disk build.
pub fn capture_baseline(data: &DataDir) -> Result<CaptureOutcome, String> {
    if data.has_baseline() {
        return Err(format!(
            "A baseline already exists at {}. Archive it before capturing a new one.",
            data.baseline_dir().display()
        ));
    }
    let obs = observe(true, None)?;
    let signature = obs.signature.clone()?;
    if signature.state != SignatureState::Valid {
        return Err(format!("Refusing to baseline ntdll.dll: {}", signature.summary()));
    }
    let memory = obs.memory.as_ref().ok_or("Mapped ntdll was not observed")?;
    if !memory.matches_disk {
        return Err("The loaded ntdll build differs from the on-disk file. Reboot, then capture.".into());
    }
    let mut findings = obs.findings.clone();
    if findings.iter().any(|f| f.severity >= Severity::Medium) {
        return Err(format!(
            "Refusing to baseline while the current state has warnings: {}",
            findings.iter().filter(|f| f.severity >= Severity::Medium).map(|f| f.title.as_str()).collect::<Vec<_>>().join("; ")
        ));
    }
    let staging = data.begin_baseline()?;
    let mut sections = Vec::new();
    let mut disk_runs = 0;
    for s in &memory.sections {
        let file = format!("exec-{:08X}.bin", s.rva);
        write_new(&staging.join(&file), &s.memory)?;
        if let Some(disk) = &s.disk {
            disk_runs += diff_runs(disk, &s.memory, MERGE_GAP).len();
        }
        sections.push(BaselineSection {
            name: s.name.clone(),
            rva: s.rva,
            len: s.memory.len() as u32,
            sha256: sha256_hex(&s.memory),
            file,
        });
    }
    let baseline = Baseline {
        schema_version: BASELINE_SCHEMA,
        captured_unix: now_unix(),
        ntdll_path: obs.path.clone(),
        file_size: obs.file_size,
        file_sha256: obs.file_sha256.clone(),
        signature,
        image: memory.identity,
        preferred_base: obs.preferred_base,
        sections,
        disk_vs_memory_runs_at_capture: disk_runs,
    };
    let json = serde_json::to_string_pretty(&baseline).map_err(|e| e.to_string())?;
    write_new(&staging.join("baseline.json"), json.as_bytes())?;
    let directory = data.commit_baseline(&staging)?;
    findings.push(
        Finding::new(MODULE, Severity::Info, "ntdll.dll", "Baseline captured")
            .detail(format!("Stored in {}. sha256 {}.", directory.display(), baseline.file_sha256)),
    );
    if disk_runs > 0 {
        findings.push(
            Finding::new(MODULE, Severity::Low, "ntdll.dll", "Baseline includes in-memory differences from disk")
                .detail(format!(
                    "{disk_runs} run(s) already differed from the on-disk file and are now treated as known-good. \
                     Only accept this if the machine is known-clean (a security product's hooks would explain it)."
                )),
        );
    }
    Ok(CaptureOutcome { directory, baseline, findings })
}

// ---------------------------------------------------------------------------
// Scan

pub fn scan(data: &DataDir, compare_memory: bool) -> IntegrityReport {
    let started = Instant::now();
    let mut report = IntegrityReport { scanned_unix: now_unix(), ..Default::default() };
    let mut findings = Vec::new();
    let baseline = match load_baseline(data) {
        Ok(b) => b,
        Err(e) => {
            findings.push(Finding::new(MODULE, Severity::High, "baseline", "Baseline could not be loaded").detail(e));
            None
        }
    };
    let obs = match observe(compare_memory, baseline.as_ref().map(|b| &b.meta)) {
        Ok(o) => o,
        Err(e) => {
            findings.push(Finding::new(MODULE, Severity::High, "ntdll.dll", "Integrity scan could not complete").detail(e));
            sort_findings(&mut findings);
            report.findings = findings;
            report.duration_ms = started.elapsed().as_millis();
            return report;
        }
    };
    report.ntdll_path = obs.path.clone();
    report.file_size = obs.file_size;
    report.file_sha256 = obs.file_sha256.clone();
    findings.extend(obs.findings.iter().cloned());

    match &obs.signature {
        Ok(sig) => {
            report.signature = Some(sig.clone());
            if sig.state != SignatureState::Valid {
                findings.push(
                    Finding::new(MODULE, Severity::Critical, "ntdll.dll", "On-disk ntdll.dll fails Authenticode verification")
                        .detail(sig.summary()),
                );
            }
        }
        Err(e) => findings.push(
            Finding::new(MODULE, Severity::High, "ntdll.dll", "Signature could not be checked").detail(e.clone()),
        ),
    }

    if let Some(b) = &baseline {
        report.baseline_captured_unix = Some(b.meta.captured_unix);
        findings.extend(b.problems.iter().cloned());
        compare_file_with_baseline(&obs, &b.meta, &mut findings);
    } else {
        findings.push(
            Finding::new(MODULE, Severity::Info, "baseline", "No baseline captured")
                .detail("Every in-memory difference from the on-disk file is reported. Capture a baseline on a known-clean system to suppress expected security-product hooks."),
        );
    }

    if let Some(memory) = &obs.memory {
        report.loaded_base = Some(memory.base as u64);
        let comparable = baseline.as_ref().filter(|b| b.meta.image == memory.identity);
        if let Some(b) = &baseline
            && comparable.is_none()
        {
            findings.push(
                Finding::new(MODULE, Severity::Medium, "baseline", "Baseline was taken from a different ntdll build")
                    .detail(format!(
                        "Baseline image {:?}, loaded image {:?}. Memory is compared with the on-disk file only. \
                         After verifying the update, archive the baseline and capture a new one.",
                        b.meta.image, memory.identity
                    )),
            );
        }
        for s in &memory.sections {
            let base_bytes = comparable.and_then(|b| {
                let i = b.meta.sections.iter().position(|bs| bs.rva == s.rva && bs.name == s.name)?;
                b.sections[i].as_deref().filter(|bytes| bytes.len() == s.memory.len())
            });
            if comparable.is_some() && base_bytes.is_none() {
                findings.push(
                    Finding::new(MODULE, Severity::Medium, format!("ntdll.dll {}", s.name), "No usable baseline for this section")
                        .detail("Compared with the on-disk file instead."),
                );
            }
            let view = SectionView {
                name: &s.name,
                rva: s.rva,
                disk: s.disk.as_deref(),
                memory: &s.memory,
                baseline: base_bytes,
                explained: &s.explained,
            };
            let cmp = compare_section(&view, &obs.exports);
            report.disk_vs_memory_runs += cmp.disk_runs;
            report.baseline_deviation_runs += cmp.baseline_runs;
            report.sections_checked.push(format!("{} ({} bytes)", s.name, s.memory.len()));
            findings.extend(cmp.findings);
        }
        findings.push(
            Finding::new(MODULE, Severity::Info, "ntdll.dll", "Integrity scan summary").detail(format!(
                "{} sha256 {}; signature: {}; loaded {} at 0x{:X}; sections: {}; disk-vs-memory runs: {}; deviations from baseline: {}.",
                obs.path,
                obs.file_sha256,
                report.signature.as_ref().map_or("unknown".into(), |s| s.summary()),
                memory.loaded_path,
                memory.base,
                report.sections_checked.join(", "),
                report.disk_vs_memory_runs,
                if comparable.is_some() { report.baseline_deviation_runs.to_string() } else { "n/a".into() },
            )),
        );
    }
    sort_findings(&mut findings);
    report.findings = findings;
    report.duration_ms = started.elapsed().as_millis();
    report
}

fn compare_file_with_baseline(obs: &Observation, b: &Baseline, findings: &mut Vec<Finding>) {
    let signature_ok = obs.signature.as_ref().is_ok_and(|s| s.state == SignatureState::Valid);
    if !obs.path.eq_ignore_ascii_case(&b.ntdll_path) {
        findings.push(
            Finding::new(MODULE, Severity::Low, "baseline", "Baseline was recorded for a different path")
                .detail(format!("Baseline path {}, current path {}.", b.ntdll_path, obs.path)),
        );
    }
    if obs.file_sha256 != b.file_sha256 || obs.file_size != b.file_size {
        let (severity, why) = if signature_ok {
            (Severity::Medium, "The file still verifies, which is consistent with a Windows update. Confirm the update, then archive the baseline and capture a new one.")
        } else {
            (Severity::High, "The file no longer verifies.")
        };
        findings.push(
            Finding::new(MODULE, severity, "ntdll.dll", "On-disk ntdll.dll differs from the baseline").detail(format!(
                "Baseline sha256 {} ({} bytes), now {} ({} bytes). {why}",
                b.file_sha256, b.file_size, obs.file_sha256, obs.file_size
            )),
        );
    } else if obs.disk_identity != b.image {
        findings.push(Finding::new(MODULE, Severity::High, "baseline", "Baseline metadata is inconsistent")
            .detail("The file hash matches the baseline but its header identity does not; the baseline may have been edited."));
    }
    if let Ok(sig) = &obs.signature
        && sig.state == SignatureState::Valid
        && !b.signature.signer.is_empty()
        && sig.signer != b.signature.signer
    {
        findings.push(
            Finding::new(MODULE, Severity::High, "ntdll.dll", "Signer differs from the baseline")
                .detail(format!("Baseline signer \"{}\", now \"{}\".", b.signature.signer, sig.signer)),
        );
    }
}

// ---------------------------------------------------------------------------
// Cross-process sweep (read-only)

pub const SWEEP_MODULE: &str = "ntdll_sweep";
pub const SWEEP_KIND: &str = "ntdll_sweep";
const MAX_UNDECODED_PER_PROCESS: usize = 8;
const MAX_LISTED_FUNCTIONS: usize = 24;

/// Where an inline hook's first instruction sends execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HookJump {
    Direct(u64),
    /// `jmp [ptr]`: the target is the 8-byte value stored at this address.
    Indirect(u64),
}

/// Decodes the common x64 hook stubs: `jmp rel32`, `jmp rel8`, `jmp [rip+rel32]`,
/// `mov r64, imm64; jmp r64` (or `push r64; ret`), and `push imm32; ret`.
pub fn decode_hook(code: &[u8], address: u64) -> Option<HookJump> {
    let rel32 = |at: usize| code.get(at..at + 4).map(|b| i32::from_le_bytes(b.try_into().unwrap()) as i64);
    match code {
        [0xE9, ..] => Some(HookJump::Direct(address.wrapping_add(5).wrapping_add_signed(rel32(1)?))),
        [0xEB, r, ..] => Some(HookJump::Direct(address.wrapping_add(2).wrapping_add_signed(*r as i8 as i64))),
        [0xFF, 0x25, ..] => Some(HookJump::Indirect(address.wrapping_add(6).wrapping_add_signed(rel32(2)?))),
        [prefix @ (0x48 | 0x49), op @ 0xB8..=0xBF, ..] => {
            let imm = u64::from_le_bytes(code.get(2..10)?.try_into().ok()?);
            let reg = op - 0xB8;
            let tail = &code[10.min(code.len())..13.min(code.len())];
            let jumps = if *prefix == 0x48 {
                tail.starts_with(&[0xFF, 0xE0 + reg]) || tail.starts_with(&[0x50 + reg, 0xC3])
            } else {
                tail.starts_with(&[0x41, 0xFF, 0xE0 + reg]) || tail.starts_with(&[0x41, 0x50 + reg, 0xC3])
            };
            jumps.then_some(HookJump::Direct(imm))
        }
        [0x68, a, b, c, d, 0xC3, ..] => Some(HookJump::Direct(u64::from(u32::from_le_bytes([*a, *b, *c, *d])))),
        _ => None,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HookOwner {
    /// A file mapped as an image (EXE/DLL), with its DOS path.
    Image(String),
    /// Executable memory not backed by any file.
    Unbacked,
    Unknown,
}

/// Grades a decoded hook by what owns its target. Pure, for testing.
/// Returns (severity, short owner label, explanation).
pub fn grade_hook_owner(
    owner: &HookOwner,
    process_path: Option<&str>,
    owner_class: Option<crate::process_inventory::PathClass>,
    signature: Option<&SignatureInfo>,
) -> (Severity, String, String) {
    use crate::process_inventory::PathClass;
    match owner {
        HookOwner::Image(path) => {
            let file = path.rsplit('\\').next().unwrap_or(path).to_string();
            let own_dir = process_path
                .and_then(|p| p.rsplit_once('\\'))
                .map(|(dir, _)| format!("{}\\", dir.to_lowercase()));
            let own_code = own_dir.is_some_and(|d| path.to_lowercase().starts_with(&d));
            let state = signature.map(|s| s.state);
            let signed_by = signature.filter(|s| s.state == SignatureState::Valid).map(|s| s.signer.clone()).unwrap_or_default();
            match state {
                Some(SignatureState::Valid) if own_code => (
                    Severity::Info,
                    file,
                    format!("into the program's own signed code ({signed_by}); browsers and Electron apps sandbox themselves this way"),
                ),
                Some(SignatureState::Valid) if matches!(owner_class, Some(PathClass::Windows | PathClass::ProgramFiles)) => {
                    (Severity::Low, file, format!("into signed module {path} ({signed_by})"))
                }
                Some(SignatureState::Valid) => (Severity::Medium, file, format!("into signed module {path} ({signed_by}) outside Program Files and Windows")),
                Some(SignatureState::Unsigned) => (Severity::High, file, format!("into unsigned module {path}")),
                Some(SignatureState::Untrusted) => (Severity::High, file, format!("into {path}, whose signature is not trusted")),
                Some(SignatureState::Invalid) => (Severity::High, file, format!("into {path}, whose signature does not verify")),
                None => (Severity::Medium, file, format!("into {path} (signature could not be checked)")),
            }
        }
        HookOwner::Unbacked => (
            Severity::Medium,
            "unbacked memory".into(),
            "into executable memory that is not backed by any file".into(),
        ),
        HookOwner::Unknown => (Severity::Medium, "unknown memory".into(), "into memory that could not be queried".into()),
    }
}

fn hook_owner(process: windows_sys::Win32::Foundation::HANDLE, address: u64, devices: &[(String, String)]) -> HookOwner {
    use windows_sys::Win32::System::Memory::VirtualQueryEx;
    use windows_sys::Win32::System::ProcessStatus::K32GetMappedFileNameW;
    let mut info: MEMORY_BASIC_INFORMATION = unsafe { zeroed() };
    let got = unsafe {
        VirtualQueryEx(process, address as *const c_void, &mut info, size_of::<MEMORY_BASIC_INFORMATION>())
    };
    if got == 0 || info.State != MEM_COMMIT {
        return HookOwner::Unknown;
    }
    if info.Type != MEM_IMAGE {
        return HookOwner::Unbacked;
    }
    let mut buffer = [0u16; 1024];
    let len = unsafe { K32GetMappedFileNameW(process, address as *const c_void, buffer.as_mut_ptr(), buffer.len() as u32) };
    if len == 0 {
        return HookOwner::Unknown;
    }
    HookOwner::Image(device_path_to_dos(&from_wide(&buffer[..len as usize]), devices))
}

struct OwnerGroup {
    severity: Severity,
    label: String,
    reason: String,
    functions: Vec<String>,
    first: (u32, String, String),
    target: u64,
}

/// Compares ntdll's executable sections in other processes with the copy in this
/// process. ntdll is mapped at the same address in every process of a boot and its
/// pages stay shared until written, so any difference is a modification made after
/// load. Each hook's jump target is decoded and attributed to the module (or
/// anonymous memory) that owns it, so a program sandboxing itself is not reported
/// like foreign code. Processes are opened with query and read rights only.
pub fn sweep_processes(
    processes: &[(u32, String)],
    cache: &mut crate::signature::SignatureCache,
    dirs: &crate::process_inventory::KnownDirs,
) -> crate::findings::ScanReport {
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ,
    };
    let started = Instant::now();
    let mut findings = Vec::new();
    let reference = map_ntdll().and_then(|m| {
        let identity = PeImage::parse_mapped(&m.image)?.identity;
        Ok((identity, m))
    });
    let (identity, mapped) = match reference {
        Ok(r) => r,
        Err(e) => {
            findings.push(Finding::new(SWEEP_MODULE, Severity::High, "ntdll.dll", "Cross-process sweep could not start").detail(e));
            return crate::findings::ScanReport {
                kind: SWEEP_KIND.into(),
                scanned_unix: now_unix(),
                duration_ms: started.elapsed().as_millis(),
                summary: "ntdll sweep: could not read the reference copy".into(),
                findings,
            };
        }
    };
    let pe = PeImage::parse_mapped(&mapped.image).expect("parsed above");
    let exports = pe.exports().unwrap_or_default();
    let sections: Vec<(String, u32, usize)> = pe
        .executable_sections()
        .map(|s| (s.name.clone(), s.virtual_address, s.comparable_len() as usize))
        .collect();
    let devices = dos_devices();
    let own = std::process::id();
    let (mut compared, mut denied, mut other_build, mut differing, mut foreign) = (0usize, 0usize, 0usize, 0usize, 0usize);
    let mut skipped = 0usize;
    for (pid, name) in processes {
        if *pid == 0 || *pid == 4 || *pid == own {
            continue;
        }
        let process_path =
            crate::process_inventory::image_path(*pid).ok().map(|(p, _)| p).or_else(|| crate::system::image_path_by_pid(*pid));
        if process_path.as_deref().is_some_and(crate::system::is_credential_store) {
            skipped += 1;
            continue;
        }
        let mut handle = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, *pid) };
        if handle.is_null() {
            handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, 0, *pid) };
        }
        if handle.is_null() {
            denied += 1;
            continue;
        }
        let handle = crate::winutil::OwnedHandle(handle);
        let (header, bad) = read_process_memory(handle.0, mapped.base, PAGE);
        // Minimal and exiting processes have no readable user-mode ntdll.
        if !bad.is_empty() {
            denied += 1;
            continue;
        }
        if PeImage::parse_mapped(&header).map(|h| h.identity) != Ok(identity) {
            other_build += 1;
            continue;
        }
        compared += 1;
        let subject = format!("pid {pid} {name}");
        let mut groups: Vec<OwnerGroup> = Vec::new();
        let mut undecoded = Vec::new();
        let mut any = false;
        for (section, rva, len) in &sections {
            let ours = &mapped.image[*rva as usize..*rva as usize + len];
            let (theirs, unreadable) = read_process_memory(handle.0, mapped.base + *rva as usize, *len);
            if !unreadable.is_empty() {
                findings.push(
                    Finding::new(SWEEP_MODULE, Severity::Low, &subject, format!("Part of ntdll {section} is unreadable in this process"))
                        .detail(format!("{} range(s) could not be read.", unreadable.len())),
                );
            }
            for run in diff_runs(ours, &theirs, MERGE_GAP) {
                any = true;
                let run_rva = rva + run.start as u32;
                let (label, at_entry) = locate(&exports, run_rva, rva + run.end as u32);
                // Decode at the export entry when the run touches one, else where the change starts.
                let entry_rva = if at_entry {
                    let after = exports.partition_point(|e| e.rva <= run_rva);
                    exports[..after]
                        .last()
                        .filter(|e| run_rva - e.rva < HOOK_WINDOW)
                        .or_else(|| exports.get(after))
                        .map_or(run_rva, |e| e.rva)
                } else {
                    run_rva
                };
                let offset = (entry_rva - rva) as usize;
                let address = mapped.base as u64 + u64::from(entry_rva);
                let jump = theirs.get(offset..).and_then(|code| decode_hook(code, address));
                let target = match jump {
                    Some(HookJump::Direct(t)) => Some(t),
                    Some(HookJump::Indirect(ptr)) => {
                        let (bytes, bad) = read_process_memory(handle.0, ptr as usize, 8);
                        bad.is_empty().then(|| u64::from_le_bytes(bytes[..8].try_into().unwrap()))
                    }
                    None => None,
                };
                let expected = show(&ours[run.start..run.end]);
                let observed = show(&theirs[run.start..run.end]);
                let Some(target) = target else {
                    undecoded.push((run_rva, label, expected, observed, run.end - run.start, section.clone()));
                    continue;
                };
                let owner = hook_owner(handle.0, target, &devices);
                let (owner_class, signature) = match &owner {
                    HookOwner::Image(path) => (Some(crate::process_inventory::classify_path(path, dirs)), cache.get(path)),
                    _ => (None, None),
                };
                let (severity, owner_label, reason) = grade_hook_owner(&owner, process_path.as_deref(), owner_class, signature.as_ref());
                let function = exports.iter().find(|e| e.rva == entry_rva).map_or(label, |e| e.name.clone());
                match groups.iter_mut().find(|g| g.label == owner_label && g.reason == reason) {
                    Some(g) => g.functions.push(function),
                    None => groups.push(OwnerGroup {
                        severity,
                        label: owner_label,
                        reason,
                        functions: vec![function],
                        first: (run_rva, expected, observed),
                        target,
                    }),
                }
            }
        }
        if any {
            differing += 1;
        }
        for g in groups {
            if g.severity > Severity::Info {
                foreign += 1;
            }
            let count = g.functions.len();
            let mut list: Vec<&str> = g.functions.iter().map(String::as_str).take(MAX_LISTED_FUNCTIONS).collect();
            list.dedup();
            let more = if count > MAX_LISTED_FUNCTIONS { format!(" and {} more", count - MAX_LISTED_FUNCTIONS) } else { String::new() };
            findings.push(
                Finding::new(SWEEP_MODULE, g.severity, &subject, format!("ntdll functions redirected into {}", g.label))
                    .detail(format!(
                        "{count} ntdll function(s) jump {} (first target 0x{:X}): {}{more}.",
                        g.reason,
                        g.target,
                        list.join(", ")
                    ))
                    .bytes(u64::from(g.first.0), g.first.1, g.first.2),
            );
        }
        let total_undecoded = undecoded.len();
        for (run_rva, label, expected, observed, len, section) in undecoded.into_iter().take(MAX_UNDECODED_PER_PROCESS) {
            findings.push(
                Finding::new(SWEEP_MODULE, Severity::Medium, &subject, format!("ntdll code differs at {label} (not a recognisable jump)"))
                    .detail(format!("{len} byte(s) in {section} at RVA 0x{run_rva:X} differ from the dashboard's own ntdll."))
                    .bytes(u64::from(run_rva), expected, observed),
            );
        }
        if total_undecoded > MAX_UNDECODED_PER_PROCESS {
            findings.push(
                Finding::new(SWEEP_MODULE, Severity::Medium, &subject, "Many other ntdll differences in this process")
                    .detail(format!("{total_undecoded} differing runs are not recognisable jumps; the first {MAX_UNDECODED_PER_PROCESS} are listed.")),
            );
        }
    }
    let mut summary = format!(
        "ntdll sweep: {compared} processes compared, {differing} modified ({foreign} with hooks not explained as the program's own code), {denied} not readable, {other_build} on another ntdll build"
    );
    if skipped > 0 {
        summary.push_str(", lsass.exe skipped (credential store)");
    }
    findings.push(Finding::new(SWEEP_MODULE, Severity::Info, "process snapshot", "ntdll sweep summary").detail(summary.clone()));
    sort_findings(&mut findings);
    crate::findings::ScanReport {
        kind: SWEEP_KIND.into(),
        scanned_unix: now_unix(),
        duration_ms: started.elapsed().as_millis(),
        summary,
        findings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exports() -> Vec<Export> {
        vec![Export { name: "NtA".into(), rva: 0x1000 }, Export { name: "NtB".into(), rva: 0x1020 }]
    }

    #[test]
    fn diff_runs_merges_close_differences() {
        let a = [0u8; 32];
        let mut b = a;
        b[2] = 1;
        b[5] = 1;
        b[20] = 1;
        assert_eq!(diff_runs(&a, &b, 4), vec![Run { start: 2, end: 6 }, Run { start: 20, end: 21 }]);
        assert_eq!(diff_runs(&a, &b, 0).len(), 3);
        assert!(diff_runs(&a, &a, 4).is_empty());
    }

    #[test]
    fn locate_names_exports_and_flags_entry_points() {
        let e = exports();
        assert_eq!(locate(&e, 0x1000, 0x1005), ("NtA".into(), true));
        assert_eq!(locate(&e, 0x1018, 0x101A), ("NtA+0x18".into(), false));
        assert_eq!(locate(&e, 0x101C, 0x1024), ("NtA+0x1C".into(), true));
        assert_eq!(locate(&e, 0x0800, 0x0801), ("rva 0x800".into(), false));
    }

    #[test]
    fn no_baseline_reports_disk_differences_as_hooks() {
        let disk = vec![0x4C, 0x8B, 0xD1, 0xB8, 0x26, 0, 0, 0, 0x90, 0x90];
        let mut memory = disk.clone();
        memory[0..5].copy_from_slice(&[0xE9, 0x11, 0x22, 0x33, 0x44]);
        let view = SectionView { name: ".text", rva: 0x1000, disk: Some(&disk), memory: &memory, baseline: None, explained: &[] };
        let cmp = compare_section(&view, &exports());
        assert_eq!(cmp.disk_runs, 1);
        assert_eq!(cmp.findings.len(), 1);
        let f = &cmp.findings[0];
        assert_eq!(f.severity, Severity::High);
        assert!(f.title.contains("NtA"), "{}", f.title);
        assert_eq!(f.offset, Some(0x1000));
        assert_eq!(f.expected.as_deref(), Some("4C 8B D1 B8 26"));
        assert_eq!(f.observed.as_deref(), Some("E9 11 22 33 44"));
    }

    #[test]
    fn baseline_absorbs_known_hooks_and_reports_new_ones() {
        let disk = vec![0u8; 64];
        let mut baseline = disk.clone();
        baseline[0] = 0xE9; // a hook present at capture time, e.g. a security product
        let mut memory = baseline.clone();
        let view = SectionView { name: ".text", rva: 0x1000, disk: Some(&disk), memory: &memory, baseline: Some(&baseline), explained: &[] };
        let quiet = compare_section(&view, &exports());
        assert_eq!(quiet.baseline_runs, 0);
        assert!(quiet.findings.iter().all(|f| f.severity == Severity::Info));
        assert_eq!(quiet.findings.len(), 1);

        memory[0x20] = 0xCC; // new change at NtB's entry
        let view = SectionView { name: ".text", rva: 0x1000, disk: Some(&disk), memory: &memory, baseline: Some(&baseline), explained: &[] };
        let alert = compare_section(&view, &exports());
        assert_eq!(alert.baseline_runs, 1);
        let f = alert.findings.iter().find(|f| f.severity == Severity::High).unwrap();
        assert!(f.title.contains("NtB") && f.title.contains("baseline"), "{}", f.title);
        assert!(f.detail.contains("only memory changed"), "{}", f.detail);
    }

    #[test]
    fn override_sites_are_classified_by_target() {
        // Synthetic layout: thunk displacement at 0x10011, image ends at 0x20000.
        let site = OverrideSite { site_rva: 0x10011, original_rva: 0x8004, targets: vec![0x18000] };
        let appended = [(0x20000, 0x21000)];
        let file = Some(0x8004);
        assert_eq!(classify_override(&site, file, 0x8004, &appended), OverrideState::Unchanged);
        assert_eq!(classify_override(&site, file, 0x18000, &appended), OverrideState::DeclaredTarget);
        assert_eq!(classify_override(&site, file, 0x20100, &appended), OverrideState::AppendedImagePage);
        assert_eq!(classify_override(&site, file, 0x7FFF_0000, &appended), OverrideState::Outside);
        assert_eq!(classify_override(&site, file, 0x20100, &[]), OverrideState::Outside);
        // rel32 is relative to the end of the 4-byte displacement.
        assert_eq!(rel32_target(&[0xEF, 0x7F, 0xFF, 0xFF], 0, 0x10011), Some(0x8004));
        assert_eq!(rel32_target(&[0xEB, 0x00, 0x01, 0x00], 0, 0x10011), Some(0x20100));
    }

    #[test]
    fn explained_ranges_are_not_reported_twice() {
        let disk = vec![0xCCu8; 32];
        let mut memory = disk.clone();
        memory[0x11..0x15].copy_from_slice(&[0xEB, 0x00, 0x01, 0x00]);
        let explained = [Run { start: 0x11, end: 0x15 }];
        let view = SectionView { name: ".text", rva: 0x10000, disk: Some(&disk), memory: &memory, baseline: None, explained: &explained };
        let cmp = compare_section(&view, &[]);
        assert_eq!(cmp.disk_runs, 0);
        assert!(cmp.findings.is_empty());
        // A change next to the site that extends the run past it is still reported.
        memory[0x16] = 0x90;
        let view = SectionView { name: ".text", rva: 0x10000, disk: Some(&disk), memory: &memory, baseline: None, explained: &explained };
        assert_eq!(compare_section(&view, &[]).disk_runs, 1);
    }

    #[test]
    fn long_byte_runs_are_truncated_for_display() {
        let s = show(&[0xAB; 40]);
        assert!(s.ends_with("(+8 bytes)"), "{s}");
    }

    #[test]
    fn decodes_common_hook_stubs() {
        let at = 0x7FFE_0000_1000u64;
        assert_eq!(decode_hook(&[0xE9, 0xFB, 0xFF, 0xFF, 0xFF], at), Some(HookJump::Direct(at)));
        assert_eq!(decode_hook(&[0xEB, 0xFE], at), Some(HookJump::Direct(at)));
        assert_eq!(decode_hook(&[0xFF, 0x25, 0, 0, 0, 0], at), Some(HookJump::Indirect(at + 6)));
        // mov rax, imm64; jmp rax
        let stub = [0x48, 0xB8, 0x70, 0x56, 0x34, 0x12, 0xF6, 0x7F, 0, 0, 0xFF, 0xE0];
        assert_eq!(decode_hook(&stub, at), Some(HookJump::Direct(0x7FF6_1234_5670)));
        // mov r11, imm64; jmp r11
        let stub = [0x49, 0xBB, 0xF0, 0xDE, 0xBC, 0x0A, 0xF6, 0x7F, 0, 0, 0x41, 0xFF, 0xE3];
        assert_eq!(decode_hook(&stub, at), Some(HookJump::Direct(0x7FF6_0ABC_DEF0)));
        // mov rax, imm64 without a jump is not a hook stub; nor is the original syscall stub.
        assert_eq!(decode_hook(&[0x48, 0xB8, 1, 2, 3, 4, 5, 6, 7, 8, 0x90, 0x90], at), None);
        assert_eq!(decode_hook(&[0x4C, 0x8B, 0xD1, 0xB8, 0x26, 0, 0, 0], at), None);
    }

    #[test]
    fn hook_owners_are_graded() {
        use crate::process_inventory::PathClass;
        let valid = SignatureInfo { state: SignatureState::Valid, signer: "Example Vendor".into(), via_catalog: false, status_code: 0 };
        let unsigned = SignatureInfo { state: SignatureState::Unsigned, signer: String::new(), via_catalog: false, status_code: 0 };
        let browser = Some(r"C:\Program Files\Example Browser\browser.exe");
        let own = HookOwner::Image(r"C:\Program Files\Example Browser\browser.exe".into());
        assert_eq!(grade_hook_owner(&own, browser, Some(PathClass::ProgramFiles), Some(&valid)).0, Severity::Info);
        let av = HookOwner::Image(r"C:\Program Files\Some AV\hook64.dll".into());
        assert_eq!(grade_hook_owner(&av, browser, Some(PathClass::ProgramFiles), Some(&valid)).0, Severity::Low);
        let bad = HookOwner::Image(r"C:\Users\a\AppData\Local\Temp\x.dll".into());
        assert_eq!(grade_hook_owner(&bad, browser, Some(PathClass::TempOrDownloads), Some(&unsigned)).0, Severity::High);
        assert_eq!(grade_hook_owner(&HookOwner::Unbacked, browser, None, None).0, Severity::Medium);
    }
}
