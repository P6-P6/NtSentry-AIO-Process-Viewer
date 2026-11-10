//! Read-only Windows inventories: live process metrics, services and drivers,
//! startup entries, network endpoints, loaded modules and file version details.
//!
//! CPU is normalized to the whole machine (0..100%), not one logical core.
//! Missing access is reported as an unknown or zero observation.
//!
//! The only functions that change anything are the explicit process controls at
//! the end (end, suspend, resume). They re-check the PID and its creation time
//! immediately before acting, and refuse Idle, System, critical processes and
//! this process.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::ffi::c_void;
use std::mem::{size_of, zeroed};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::ptr::{null, null_mut};
use std::time::{Duration, Instant, UNIX_EPOCH};
use crate::startup_control::{self, Hive, Switch};
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::NetworkManagement::IpHelper::*;
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6, IN6_ADDR, IN6_ADDR_0};
use windows_sys::Win32::Storage::FileSystem::{GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW};
use windows_sys::Win32::System::Diagnostics::ToolHelp::*;
use windows_sys::Win32::System::ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
use windows_sys::Win32::System::Registry::*;
use windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows_sys::Win32::System::Services::*;
use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
use windows_sys::Win32::System::Threading::*;

pub type SystemResult<T> = Result<T, String>;

/// A process is identified by PID plus creation time, so a reused PID is never
/// mistaken for the process that was observed earlier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ProcessIdentity {
    pub pid: u32,
    /// FILETIME creation timestamp; zero means unavailable.
    pub creation_time: u64,
}

#[derive(Clone, Debug)]
pub struct ProcessInfo {
    pub identity: ProcessIdentity,
    pub parent_pid: u32,
    pub name: String,
    pub path: String,
    pub cpu_percent: f64,
    pub memory_bytes: u64,
    pub thread_count: u32,
    /// u32::MAX means that Windows did not disclose the session.
    pub session_id: u32,
    pub priority_class: u32,
    /// True only when the API positively reports critical status.
    pub is_critical: bool,
    pub accessible: bool,
    /// `DOMAIN\\user` that owns the process; empty when not readable.
    pub user: String,
    /// Full command line; empty when not readable.
    pub command_line: String,
}

#[derive(Clone, Debug, Default)]
pub struct ProcessSnapshot {
    pub processes: Vec<ProcessInfo>,
    pub cpu_percent: f64,
    pub memory_total_bytes: u64,
    pub memory_available_bytes: u64,
    pub process_count: u32,
    pub thread_count: u32,
}

#[derive(Clone, Debug)]
pub struct ModuleInfo {
    pub name: String,
    pub path: String,
    pub base_address: usize,
    pub size_bytes: u32,
}

#[derive(Clone, Debug, Default)]
pub struct FileDetails {
    pub path: String,
    pub size_bytes: u64,
    pub modified_unix_seconds: Option<u64>,
    pub description: String,
    pub company: String,
    pub file_version: String,
    pub product_name: String,
}

#[derive(Clone, Debug)]
pub struct ServiceInfo {
    pub name: String,
    pub display_name: String,
    pub pid: u32,
    pub state: String,
    pub start_type: String,
    pub binary_path: String,
    pub service_type: u32,
}

impl ServiceInfo {
    pub fn is_driver(&self) -> bool {
        self.service_type & SERVICE_DRIVER != 0
    }
}

/// The start types NtSentry can set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceStart {
    Automatic,
    Manual,
    Disabled,
}

#[derive(Clone, Debug)]
pub struct AutorunInfo {
    pub location: String,
    pub name: String,
    pub command: String,
    /// Where Windows keeps this entry's on/off state. None when it has none (Run
    /// once entries, desktop.ini) or the state could not be read.
    pub switch: Option<Switch>,
    /// Windows skips this entry at sign-in.
    pub disabled: bool,
}

impl AutorunInfo {
    fn new(location: String, name: String, command: String, switch: Option<Switch>) -> Self {
        // A state that can't be read is shown as unknown, never guessed.
        let disabled = switch.as_ref().and_then(|s| s.is_disabled().ok());
        let switch = switch.filter(|_| disabled.is_some());
        AutorunInfo { location, name, command, switch, disabled: disabled.unwrap_or(false) }
    }

    pub fn status(&self) -> &'static str {
        match (&self.switch, self.disabled) {
            (None, _) => "Not switchable",
            (_, true) => "Disabled",
            (_, false) => "Enabled",
        }
    }

    /// All-users entries keep their switch in HKLM.
    pub fn needs_admin(&self) -> bool {
        self.switch.as_ref().is_some_and(|s| s.hive == Hive::LocalMachine)
    }
}

#[derive(Clone, Debug)]
pub struct NetworkConnection {
    pub protocol: String,
    pub local_address: String,
    pub remote_address: String,
    pub state: String,
    pub pid: u32,
    /// Measured TCP traffic; `None` for UDP, idle states and unprivileged runs.
    pub traffic: Option<ConnectionTraffic>,
}

/// Bytes moved by one TCP connection. Totals count from when it was first measured.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ConnectionTraffic {
    pub down_per_sec: f64,
    pub up_per_sec: f64,
    pub total_down: u64,
    pub total_up: u64,
}

struct OwnedHandle(HANDLE);

impl OwnedHandle {
    fn checked(value: HANDLE, operation: &str) -> SystemResult<Self> {
        if value.is_null() || value == INVALID_HANDLE_VALUE { Err(last_error(operation)) } else { Ok(Self(value)) }
    }
}

// Kernel handles may be moved between threads; ownership stays unique.
unsafe impl Send for OwnedHandle {}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

struct ServiceHandle(SC_HANDLE);

impl Drop for ServiceHandle {
    fn drop(&mut self) {
        unsafe { CloseServiceHandle(self.0) };
    }
}

fn last_error(operation: &str) -> String {
    format!("{operation}: {}", std::io::Error::last_os_error())
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn from_wide(value: &[u16]) -> String {
    let end = value.iter().position(|x| *x == 0).unwrap_or(value.len());
    String::from_utf16_lossy(&value[..end])
}

unsafe fn wide_ptr(value: *const u16) -> String {
    if value.is_null() {
        return String::new();
    }
    let mut len = 0;
    while len < 32768 && unsafe { *value.add(len) } != 0 {
        len += 1;
    }
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(value, len) })
}

fn ticks(value: FILETIME) -> u64 {
    ((value.dwHighDateTime as u64) << 32) | value.dwLowDateTime as u64
}

/// (creation time, kernel + user time) of an open process.
unsafe fn process_times(handle: HANDLE) -> Option<(u64, u64)> {
    let (mut creation, mut exit, mut kernel, mut user): (FILETIME, FILETIME, FILETIME, FILETIME) =
        unsafe { (zeroed(), zeroed(), zeroed(), zeroed()) };
    if unsafe { GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user) } == 0 {
        None
    } else {
        Some((ticks(creation), ticks(kernel).saturating_add(ticks(user))))
    }
}

unsafe fn image_path(handle: HANDLE) -> String {
    let mut buffer = vec![0u16; 32768];
    let mut length = buffer.len() as u32;
    if unsafe { QueryFullProcessImageNameW(handle, 0, buffer.as_mut_ptr(), &mut length) } == 0 {
        String::new()
    } else {
        String::from_utf16_lossy(&buffer[..length as usize])
    }
}

/// Turns on SeDebugPrivilege when the account holds it (elevated administrators),
/// as Task Manager and Process Explorer do, so query-only handles open for
/// service and protected processes. Enables a right the token already has;
/// grants nothing new. Returns whether it is on.
pub fn enable_debug_privilege() -> bool {
    use windows_sys::Win32::Security::{
        AdjustTokenPrivileges, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW, SE_DEBUG_NAME, SE_PRIVILEGE_ENABLED,
        TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
    };
    unsafe {
        let mut token: HANDLE = null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let token = OwnedHandle(token);
        let mut luid: LUID = zeroed();
        if LookupPrivilegeValueW(null(), SE_DEBUG_NAME, &mut luid) == 0 {
            return false;
        }
        let privileges = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES { Luid: luid, Attributes: SE_PRIVILEGE_ENABLED }],
        };
        // Succeeds with ERROR_NOT_ALL_ASSIGNED when the token lacks the privilege.
        AdjustTokenPrivileges(token.0, 0, &privileges, 0, null_mut(), null_mut()) != 0 && GetLastError() == ERROR_SUCCESS
    }
}

/// Whether this process runs elevated (Run as administrator).
pub fn is_elevated() -> bool {
    use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation};
    unsafe {
        let mut token: HANDLE = null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let token = OwnedHandle(token);
        let mut elevation: TOKEN_ELEVATION = zeroed();
        let mut returned = 0u32;
        GetTokenInformation(
            token.0,
            TokenElevation,
            &mut elevation as *mut TOKEN_ELEVATION as *mut c_void,
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        ) != 0
            && elevation.TokenIsElevated != 0
    }
}

/// Image path of a process by PID without opening it, for processes that refuse
/// even query-only handles (some protected and anti-cheat guarded ones).
pub fn image_path_by_pid(pid: u32) -> Option<String> {
    use windows_sys::Wdk::System::SystemInformation::NtQuerySystemInformation;
    #[repr(C)]
    struct SystemProcessIdInformation {
        process_id: HANDLE,
        image_name: UNICODE_STRING,
    }
    const SYSTEM_PROCESS_ID_INFORMATION: i32 = 88;
    if pid == 0 || pid == 4 {
        return None;
    }
    let mut buffer = vec![0u16; 32_767];
    let mut info = SystemProcessIdInformation {
        process_id: pid as usize as HANDLE,
        image_name: UNICODE_STRING { Length: 0, MaximumLength: (buffer.len() * 2) as u16, Buffer: buffer.as_mut_ptr() },
    };
    let status = unsafe {
        NtQuerySystemInformation(
            SYSTEM_PROCESS_ID_INFORMATION,
            &mut info as *mut SystemProcessIdInformation as *mut c_void,
            size_of::<SystemProcessIdInformation>() as u32,
            null_mut(),
        )
    };
    if status < 0 || info.image_name.Length == 0 {
        return None;
    }
    let len = (info.image_name.Length as usize / 2).min(buffer.len());
    let path = crate::winutil::device_path_to_dos(&String::from_utf16_lossy(&buffer[..len]), &crate::winutil::dos_devices());
    Some(path)
}

/// lsass.exe keeps sign-in secrets. Windows credential-theft protection flags any
/// tool that opens it for memory reads, so the memory-reading checks skip it.
pub fn is_credential_store(path: &str) -> bool {
    crate::winutil::system_directory().is_some_and(|dir| path.eq_ignore_ascii_case(&format!("{dir}\\lsass.exe")))
}

/// `DOMAIN\\user` owning the process, from its token (query rights only).
unsafe fn process_user(process: HANDLE) -> Option<String> {
    use windows_sys::Win32::Security::{GetTokenInformation, LookupAccountSidW, TOKEN_QUERY, TOKEN_USER, TokenUser};
    unsafe {
        let mut token: HANDLE = null_mut();
        if OpenProcessToken(process, TOKEN_QUERY, &mut token) == 0 {
            return None;
        }
        let token = OwnedHandle(token);
        let mut needed = 0u32;
        GetTokenInformation(token.0, TokenUser, null_mut(), 0, &mut needed);
        if needed == 0 || needed > 4096 {
            return None;
        }
        let mut buffer = vec![0u64; (needed as usize).div_ceil(8)];
        if GetTokenInformation(token.0, TokenUser, buffer.as_mut_ptr() as *mut c_void, needed, &mut needed) == 0 {
            return None;
        }
        let user = &*(buffer.as_ptr() as *const TOKEN_USER);
        let (mut name, mut domain) = ([0u16; 256], [0u16; 256]);
        let (mut name_len, mut domain_len) = (name.len() as u32, domain.len() as u32);
        let mut kind = 0;
        if LookupAccountSidW(
            null(),
            user.User.Sid,
            name.as_mut_ptr(),
            &mut name_len,
            domain.as_mut_ptr(),
            &mut domain_len,
            &mut kind,
        ) == 0
        {
            return None;
        }
        let (name, domain) = (from_wide(&name), from_wide(&domain));
        Some(if domain.is_empty() { name } else { format!("{domain}\\{name}") })
    }
}

/// Command line of a process (Windows 8.1+, query rights only).
unsafe fn process_command_line(process: HANDLE) -> Option<String> {
    use windows_sys::Wdk::System::Threading::{NtQueryInformationProcess, ProcessCommandLineInformation};
    unsafe {
        let mut needed = 0u32;
        NtQueryInformationProcess(process, ProcessCommandLineInformation, null_mut(), 0, &mut needed);
        if needed == 0 || needed > 1 << 20 {
            return None;
        }
        let mut buffer = vec![0u64; (needed as usize).div_ceil(8)];
        let status = NtQueryInformationProcess(
            process,
            ProcessCommandLineInformation,
            buffer.as_mut_ptr() as *mut c_void,
            (buffer.len() * 8) as u32,
            &mut needed,
        );
        if status < 0 {
            return None;
        }
        let text = &*(buffer.as_ptr() as *const UNICODE_STRING);
        if text.Buffer.is_null() || text.Length == 0 {
            return Some(String::new());
        }
        // The string must lie inside the buffer the kernel filled.
        let (start, end) = (buffer.as_ptr() as usize, buffer.as_ptr() as usize + buffer.len() * 8);
        let (ptr, bytes) = (text.Buffer as usize, text.Length as usize);
        if ptr < start || ptr + bytes > end {
            return None;
        }
        Some(String::from_utf16_lossy(std::slice::from_raw_parts(text.Buffer, bytes / 2)))
    }
}

/// FILETIME ticks to Unix seconds.
pub fn filetime_to_unix(filetime: u64) -> Option<u64> {
    const EPOCH_DIFFERENCE: u64 = 116_444_736_000_000_000;
    (filetime > EPOCH_DIFFERENCE).then(|| (filetime - EPOCH_DIFFERENCE) / 10_000_000)
}

/// Opens the standard Windows Properties dialog for a file.
pub fn open_file_properties(path: &str) -> SystemResult<()> {
    use windows_sys::Win32::UI::Shell::{SEE_MASK_INVOKEIDLIST, SHELLEXECUTEINFOW, ShellExecuteExW};
    let file = wide(path);
    let verb = wide("properties");
    unsafe {
        let mut info: SHELLEXECUTEINFOW = zeroed();
        info.cbSize = size_of::<SHELLEXECUTEINFOW>() as u32;
        info.fMask = SEE_MASK_INVOKEIDLIST;
        info.lpVerb = verb.as_ptr();
        info.lpFile = file.as_ptr();
        info.nShow = 1; // SW_SHOWNORMAL
        if ShellExecuteExW(&mut info) == 0 {
            return Err(last_error("Open file properties"));
        }
    }
    Ok(())
}

/// Saturating deltas prevent bogus spikes across counter resets or failed samples.
pub fn cpu_from_deltas(process_delta: u64, machine_delta: u64) -> f64 {
    if machine_delta == 0 {
        return 0.0;
    }
    (100.0 * process_delta as f64 / machine_delta as f64).clamp(0.0, 100.0)
}

/// Live process metrics. CPU needs two samples; the first refresh reports 0 %.
#[derive(Default)]
pub struct Monitor {
    previous_machine: Option<(u64, u64)>,
    previous_process: HashMap<ProcessIdentity, u64>,
    /// Paths are cached only while the same PID/creation identity lives.
    paths: HashMap<ProcessIdentity, String>,
    /// User and command line, read once per process.
    details: HashMap<ProcessIdentity, (String, String)>,
}

impl Monitor {
    pub fn new() -> Self {
        Self::default()
    }

    /// Enumerates live processes without signature checks or file-version I/O.
    pub fn refresh(&mut self) -> SystemResult<ProcessSnapshot> {
        unsafe {
            let mut output = ProcessSnapshot::default();
            let (mut idle, mut kernel, mut user): (FILETIME, FILETIME, FILETIME) = (zeroed(), zeroed(), zeroed());
            if GetSystemTimes(&mut idle, &mut kernel, &mut user) == 0 {
                return Err(last_error("GetSystemTimes"));
            }
            let total = ticks(kernel).saturating_add(ticks(user));
            let idle_now = ticks(idle);
            let machine_delta = self.previous_machine.map(|x| total.saturating_sub(x.0)).unwrap_or(0);
            let idle_delta = self.previous_machine.map(|x| idle_now.saturating_sub(x.1)).unwrap_or(0);
            output.cpu_percent = cpu_from_deltas(machine_delta.saturating_sub(idle_delta), machine_delta);
            let mut memory: MEMORYSTATUSEX = zeroed();
            memory.dwLength = size_of::<MEMORYSTATUSEX>() as u32;
            if GlobalMemoryStatusEx(&mut memory) != 0 {
                output.memory_total_bytes = memory.ullTotalPhys;
                output.memory_available_bytes = memory.ullAvailPhys;
            }
            let snapshot = OwnedHandle::checked(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0), "Process snapshot")?;
            let mut entry: PROCESSENTRY32W = zeroed();
            entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;
            let mut next = Process32FirstW(snapshot.0, &mut entry);
            if next == 0 && GetLastError() != ERROR_NO_MORE_FILES {
                return Err(last_error("Read process snapshot"));
            }
            let mut current_times = HashMap::new();
            let mut current_paths = HashMap::new();
            let mut current_details = HashMap::new();
            while next != 0 {
                let pid = entry.th32ProcessID;
                let name = from_wide(&entry.szExeFile);
                let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
                let mut identity = ProcessIdentity { pid, creation_time: 0 };
                let path: String;
                let mut cpu_percent = 0.0;
                let mut memory_bytes = 0;
                let mut priority_class = 0;
                let mut is_critical = false;
                let (mut user, mut command_line) = (String::new(), String::new());
                let accessible = !handle.is_null();
                if accessible {
                    let handle = OwnedHandle(handle);
                    if let Some((creation, elapsed)) = process_times(handle.0) {
                        identity.creation_time = creation;
                        if let Some(previous) = self.previous_process.get(&identity) {
                            cpu_percent = cpu_from_deltas(elapsed.saturating_sub(*previous), machine_delta);
                        }
                        current_times.insert(identity, elapsed);
                    }
                    path = if identity.creation_time == 0 {
                        image_path(handle.0)
                    } else {
                        self.paths.get(&identity).cloned().unwrap_or_else(|| image_path(handle.0))
                    };
                    if identity.creation_time != 0 {
                        current_paths.insert(identity, path.clone());
                        let details = self.details.get(&identity).cloned().unwrap_or_else(|| {
                            (process_user(handle.0).unwrap_or_default(), process_command_line(handle.0).unwrap_or_default())
                        });
                        (user, command_line) = details.clone();
                        current_details.insert(identity, details);
                    }
                    priority_class = GetPriorityClass(handle.0);
                    let mut critical = 0;
                    if IsProcessCritical(handle.0, &mut critical) != 0 {
                        is_critical = critical != 0;
                    }
                    let mut counters: PROCESS_MEMORY_COUNTERS = zeroed();
                    counters.cb = size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
                    if GetProcessMemoryInfo(handle.0, &mut counters, counters.cb) != 0 {
                        memory_bytes = counters.WorkingSetSize as u64;
                    } else if !is_credential_store(&path) {
                        // Older Windows versions can require QUERY_INFORMATION | VM_READ.
                        let memory_handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid);
                        if !memory_handle.is_null() {
                            let memory_handle = OwnedHandle(memory_handle);
                            if process_times(memory_handle.0).map(|x| x.0) == Some(identity.creation_time)
                                && GetProcessMemoryInfo(memory_handle.0, &mut counters, counters.cb) != 0
                            {
                                memory_bytes = counters.WorkingSetSize as u64;
                            }
                        }
                    }
                } else {
                    // Refuses even query-only handles: ask the kernel for the path instead.
                    path = image_path_by_pid(pid).unwrap_or_default();
                }
                let mut session_id = u32::MAX;
                ProcessIdToSessionId(pid, &mut session_id);
                output.thread_count = output.thread_count.saturating_add(entry.cntThreads);
                output.processes.push(ProcessInfo {
                    identity,
                    parent_pid: entry.th32ParentProcessID,
                    name,
                    path,
                    cpu_percent,
                    memory_bytes,
                    thread_count: entry.cntThreads,
                    session_id,
                    priority_class,
                    is_critical,
                    accessible,
                    user,
                    command_line,
                });
                next = Process32NextW(snapshot.0, &mut entry);
            }
            output.process_count = output.processes.len() as u32;
            output.processes.sort_by(|a, b| {
                a.name.to_lowercase().cmp(&b.name.to_lowercase()).then(a.identity.pid.cmp(&b.identity.pid))
            });
            self.previous_machine = Some((total, idle_now));
            self.previous_process = current_times;
            self.paths = current_paths;
            self.details = current_details;
            Ok(output)
        }
    }
}

/// Modules loaded in a process. The PID and creation time are re-checked first,
/// so a PID reused by another process is refused.
pub fn process_modules(identity: &ProcessIdentity) -> SystemResult<Vec<ModuleInfo>> {
    unsafe {
        let process = OwnedHandle::checked(
            OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, identity.pid),
            "Open process for module identity",
        )?;
        let creation = process_times(process.0).ok_or_else(|| last_error("Read module process identity"))?.0;
        if identity.creation_time == 0 || identity.creation_time != creation {
            return Err("Process identity changed; refresh before inspecting modules".into());
        }
        if is_credential_store(&image_path(process.0)) {
            return Err("Not inspected: lsass.exe holds sign-in secrets, and reading its memory trips Windows credential protection".into());
        }
        let snapshot = OwnedHandle::checked(
            CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, identity.pid),
            "Module snapshot",
        )?;
        let mut entry: MODULEENTRY32W = zeroed();
        entry.dwSize = size_of::<MODULEENTRY32W>() as u32;
        let mut items = Vec::new();
        let mut next = Module32FirstW(snapshot.0, &mut entry);
        if next == 0 {
            return Err(last_error("Read modules (protected or cross-architecture targets can deny access)"));
        }
        while next != 0 {
            items.push(ModuleInfo {
                name: from_wide(&entry.szModule),
                path: from_wide(&entry.szExePath),
                base_address: entry.modBaseAddr as usize,
                size_bytes: entry.modBaseSize,
            });
            next = Module32NextW(snapshot.0, &mut entry);
        }
        Ok(items)
    }
}

/// Size, modification time and version resource strings of a file.
pub fn file_details(path: &str) -> SystemResult<FileDetails> {
    if path.is_empty() || path.contains('\0') {
        return Err("No accessible executable path".into());
    }
    let metadata = std::fs::metadata(path).map_err(|e| format!("File metadata: {e}"))?;
    let mut details = FileDetails {
        path: path.into(),
        size_bytes: metadata.len(),
        modified_unix_seconds: metadata.modified().ok().and_then(|v| v.duration_since(UNIX_EPOCH).ok()).map(|v| v.as_secs()),
        ..Default::default()
    };
    unsafe {
        let filename = wide(path);
        let mut ignored = 0;
        let size = GetFileVersionInfoSizeW(filename.as_ptr(), &mut ignored);
        if size > 0 && size <= 16 * 1024 * 1024 {
            let mut block = vec![0u8; size as usize];
            if GetFileVersionInfoW(filename.as_ptr(), 0, size, block.as_mut_ptr() as _) != 0 {
                let mut translation: *mut c_void = null_mut();
                let mut length = 0;
                let translation_key = wide("\\VarFileInfo\\Translation");
                let mut pairs = Vec::new();
                if VerQueryValueW(block.as_ptr() as _, translation_key.as_ptr(), &mut translation, &mut length) != 0
                    && length >= 4
                {
                    for i in 0..(length as usize / 4).min(64) {
                        let p = (translation as *const u8).add(i * 4);
                        pairs.push((std::ptr::read_unaligned(p as *const u16), std::ptr::read_unaligned(p.add(2) as *const u16)));
                    }
                }
                pairs.push((0x0409, 0x04b0));
                let read = |field: &str| -> String {
                    for (lang, code) in &pairs {
                        let key = wide(&format!("\\StringFileInfo\\{lang:04x}{code:04x}\\{field}"));
                        let mut value: *mut c_void = null_mut();
                        let mut len = 0;
                        if VerQueryValueW(block.as_ptr() as _, key.as_ptr(), &mut value, &mut len) != 0
                            && !value.is_null()
                            && len > 0
                        {
                            return from_wide(std::slice::from_raw_parts(value as *const u16, (len as usize).min(32768)));
                        }
                    }
                    String::new()
                };
                details.description = read("FileDescription");
                details.company = read("CompanyName");
                details.file_version = read("FileVersion");
                details.product_name = read("ProductName");
            }
        }
    }
    Ok(details)
}

/// Services (or drivers) from the Service Control Manager. Configuration that
/// cannot be read leaves the path blank.
pub fn list_services(drivers: bool) -> SystemResult<Vec<ServiceInfo>> {
    unsafe {
        let raw = OpenSCManagerW(null(), null(), SC_MANAGER_ENUMERATE_SERVICE | SC_MANAGER_CONNECT);
        if raw.is_null() {
            return Err(last_error("OpenSCManager"));
        }
        let manager = ServiceHandle(raw);
        let service_type = if drivers { SERVICE_DRIVER } else { SERVICE_WIN32 };
        let mut output = Vec::new();
        let mut resume = 0;
        loop {
            let mut buffer = vec![0u64; 256 * 1024 / 8];
            let mut needed = 0;
            let mut returned = 0;
            let ok = EnumServicesStatusExW(
                manager.0,
                SC_ENUM_PROCESS_INFO,
                service_type,
                SERVICE_STATE_ALL,
                buffer.as_mut_ptr() as *mut u8,
                (buffer.len() * 8) as u32,
                &mut needed,
                &mut returned,
                &mut resume,
                null(),
            );
            let error = if ok == 0 { GetLastError() } else { 0 };
            if ok == 0 && error != ERROR_MORE_DATA {
                return Err(last_error("Enumerate services"));
            }
            if (returned as usize).saturating_mul(size_of::<ENUM_SERVICE_STATUS_PROCESSW>()) > buffer.len() * 8 {
                return Err("SCM returned an invalid service table size".into());
            }
            let records = std::slice::from_raw_parts(buffer.as_ptr() as *const ENUM_SERVICE_STATUS_PROCESSW, returned as usize);
            for row in records {
                let name = wide_ptr(row.lpServiceName);
                let mut item = ServiceInfo {
                    name: name.clone(),
                    display_name: wide_ptr(row.lpDisplayName),
                    pid: row.ServiceStatusProcess.dwProcessId,
                    state: service_state(row.ServiceStatusProcess.dwCurrentState).into(),
                    start_type: "Unknown".into(),
                    binary_path: String::new(),
                    service_type: row.ServiceStatusProcess.dwServiceType,
                };
                let name_w = wide(&name);
                let service = OpenServiceW(manager.0, name_w.as_ptr(), SERVICE_QUERY_CONFIG);
                if !service.is_null() {
                    let service = ServiceHandle(service);
                    let mut size = 0;
                    QueryServiceConfigW(service.0, null_mut(), 0, &mut size);
                    if size > 0 && size <= 1024 * 1024 {
                        let mut data = vec![0u64; (size as usize).div_ceil(8)];
                        if QueryServiceConfigW(service.0, data.as_mut_ptr() as *mut QUERY_SERVICE_CONFIGW, (data.len() * 8) as u32, &mut size) != 0 {
                            let config = &*(data.as_ptr() as *const QUERY_SERVICE_CONFIGW);
                            item.binary_path = effective_binary_path(wide_ptr(config.lpBinaryPathName), &name, item.service_type);
                            item.start_type = match config.dwStartType {
                                SERVICE_BOOT_START => "Boot",
                                SERVICE_SYSTEM_START => "System",
                                SERVICE_AUTO_START => "Automatic",
                                SERVICE_DEMAND_START => "Manual",
                                SERVICE_DISABLED => "Disabled",
                                _ => "Unknown",
                            }
                            .into();
                        }
                    }
                }
                output.push(item);
            }
            if ok != 0 {
                break;
            }
            if returned == 0 {
                return Err("SCM enumeration made no progress".into());
            }
        }
        output.sort_by_key(|s| s.display_name.to_lowercase());
        Ok(output)
    }
}

/// A driver registered without a path loads from Windows' default location.
fn effective_binary_path(registered: String, name: &str, service_type: u32) -> String {
    if registered.trim().is_empty() && service_type & SERVICE_DRIVER != 0 {
        format!(r"\SystemRoot\System32\drivers\{name}.sys")
    } else {
        registered
    }
}

/// How long [`stop_service`] waits for Windows to report the item stopped.
const SERVICE_STOP_TIMEOUT: Duration = Duration::from_secs(15);
/// How long [`stop_service`] then waits for a service's own process to exit.
const SERVICE_EXIT_TIMEOUT_MS: u32 = 5000;

/// The manager handle comes back too, so it outlives the service handle.
unsafe fn open_service(name: &str, access: u32) -> SystemResult<(ServiceHandle, ServiceHandle)> {
    unsafe {
        let manager = OpenSCManagerW(null(), null(), SC_MANAGER_CONNECT);
        if manager.is_null() {
            return Err(last_error("OpenSCManager"));
        }
        let manager = ServiceHandle(manager);
        let name_w = wide(name);
        let service = OpenServiceW(manager.0, name_w.as_ptr(), access);
        if service.is_null() {
            return Err(last_error(&format!("Open {name}")));
        }
        Ok((manager, ServiceHandle(service)))
    }
}

unsafe fn service_status(service: &ServiceHandle) -> SystemResult<SERVICE_STATUS_PROCESS> {
    unsafe {
        let mut status: SERVICE_STATUS_PROCESS = zeroed();
        let mut needed = 0;
        let ok = QueryServiceStatusEx(service.0, SC_STATUS_PROCESS_INFO, (&raw mut status).cast(), size_of_val(&status) as u32, &mut needed);
        if ok == 0 { Err(last_error("Query service status")) } else { Ok(status) }
    }
}

/// Stops a service or driver and waits until Windows reports it stopped. A
/// service in its own process is also given time to exit, so its file is free.
pub fn stop_service(name: &str) -> SystemResult<()> {
    unsafe {
        let (_manager, service) = open_service(name, SERVICE_STOP | SERVICE_QUERY_STATUS)?;
        let before = service_status(&service)?;
        if before.dwCurrentState == SERVICE_STOPPED {
            return Ok(());
        }
        if before.dwCurrentState != SERVICE_STOP_PENDING {
            let mut status: SERVICE_STATUS = zeroed();
            if ControlService(service.0, SERVICE_CONTROL_STOP, &mut status) == 0 {
                let error = GetLastError();
                if error != ERROR_SERVICE_NOT_ACTIVE {
                    return Err(format!("Stop {name}: {}", std::io::Error::from_raw_os_error(error as i32)));
                }
            }
        }
        let deadline = Instant::now() + SERVICE_STOP_TIMEOUT;
        while service_status(&service)?.dwCurrentState != SERVICE_STOPPED {
            if Instant::now() >= deadline {
                return Err(format!("{name} did not stop within {} seconds", SERVICE_STOP_TIMEOUT.as_secs()));
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        if before.dwProcessId != 0 && before.dwServiceType & SERVICE_WIN32_OWN_PROCESS != 0 {
            // A process that is already gone cannot be opened, which is fine.
            let process = OpenProcess(PROCESS_SYNCHRONIZE, 0, before.dwProcessId);
            if !process.is_null() {
                let process = OwnedHandle(process);
                WaitForSingleObject(process.0, SERVICE_EXIT_TIMEOUT_MS);
            }
        }
        Ok(())
    }
}

/// Changes only the start type of a service or driver.
pub fn set_service_start(name: &str, start: ServiceStart) -> SystemResult<()> {
    let start_type = match start {
        ServiceStart::Automatic => SERVICE_AUTO_START,
        ServiceStart::Manual => SERVICE_DEMAND_START,
        ServiceStart::Disabled => SERVICE_DISABLED,
    };
    unsafe {
        let (_manager, service) = open_service(name, SERVICE_CHANGE_CONFIG)?;
        let ok = ChangeServiceConfigW(
            service.0,
            SERVICE_NO_CHANGE,
            start_type,
            SERVICE_NO_CHANGE,
            null(),
            null(),
            null_mut(),
            null(),
            null(),
            null(),
            null(),
        );
        if ok == 0 { Err(last_error(&format!("Change {name}"))) } else { Ok(()) }
    }
}

fn service_state(state: u32) -> &'static str {
    match state {
        SERVICE_STOPPED => "Stopped",
        SERVICE_START_PENDING => "Starting",
        SERVICE_STOP_PENDING => "Stopping",
        SERVICE_RUNNING => "Running",
        SERVICE_CONTINUE_PENDING => "Continuing",
        SERVICE_PAUSE_PENDING => "Pausing",
        SERVICE_PAUSED => "Paused",
        _ => "Unknown",
    }
}

/// Run/RunOnce values and the startup folders, each with the state Windows keeps
/// for it. HKCU\Software is one key in both registry views, so only HKLM is read
/// twice. Read-only: nothing is launched and no registry value is written.
pub fn list_autoruns() -> SystemResult<Vec<AutorunInfo>> {
    let mut output = Vec::new();
    let sources = [
        (HKEY_CURRENT_USER, "HKCU", Hive::CurrentUser, KEY_WOW64_64KEY, "", startup_control::RUN),
        (HKEY_LOCAL_MACHINE, "HKLM", Hive::LocalMachine, KEY_WOW64_64KEY, " (64-bit)", startup_control::RUN),
        (HKEY_LOCAL_MACHINE, "HKLM", Hive::LocalMachine, KEY_WOW64_32KEY, " (32-bit)", startup_control::RUN32),
    ];
    unsafe {
        for (root, root_name, hive, view, view_name, group) in sources {
            // Windows has no off switch for RunOnce.
            for (key_name, switchable) in [
                ("Software\\Microsoft\\Windows\\CurrentVersion\\Run", true),
                ("Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", false),
            ] {
                let key_path = wide(key_name);
                let mut key: HKEY = null_mut();
                if RegOpenKeyExW(root, key_path.as_ptr(), 0, KEY_READ | view, &mut key) != ERROR_SUCCESS {
                    continue;
                }
                let mut index = 0;
                loop {
                    let mut name = vec![0u16; 16384];
                    let mut name_len = name.len() as u32;
                    let mut data = vec![0u16; 32768];
                    let mut data_bytes = (data.len() * 2) as u32;
                    let mut kind = 0;
                    let status = RegEnumValueW(
                        key,
                        index,
                        name.as_mut_ptr(),
                        &mut name_len,
                        null(),
                        &mut kind,
                        data.as_mut_ptr() as _,
                        &mut data_bytes,
                    );
                    if status == ERROR_NO_MORE_ITEMS {
                        break;
                    }
                    if status == ERROR_SUCCESS && [REG_SZ, REG_EXPAND_SZ].contains(&kind) {
                        let name = String::from_utf16_lossy(&name[..name_len as usize]);
                        let switch = switchable.then(|| Switch { hive, group, value: name.clone() });
                        output.push(AutorunInfo::new(
                            format!("{root_name}\\{key_name}{view_name}"),
                            name,
                            from_wide(&data[..((data_bytes as usize) / 2).min(data.len())]),
                            switch,
                        ));
                    }
                    index += 1;
                    if index >= 100_000 {
                        break;
                    }
                }
                RegCloseKey(key);
            }
        }
    }
    for (env_name, hive) in [("APPDATA", Hive::CurrentUser), ("PROGRAMDATA", Hive::LocalMachine)] {
        if let Some(base) = std::env::var_os(env_name) {
            let folder = Path::new(&base).join("Microsoft\\Windows\\Start Menu\\Programs\\Startup");
            if let Ok(entries) = std::fs::read_dir(&folder) {
                for entry in entries.flatten() {
                    if entry.file_type().map(|v| v.is_file()).unwrap_or(false) {
                        let name: String = entry.file_name().to_string_lossy().into();
                        let switch = Switch::for_folder_file(hive, &name);
                        output.push(AutorunInfo::new(
                            folder.to_string_lossy().into(),
                            name,
                            entry.path().to_string_lossy().into(),
                            switch,
                        ));
                    }
                }
            }
        }
    }
    output.sort_by(|a, b| a.location.cmp(&b.location).then(a.name.cmp(&b.name)));
    Ok(output)
}

fn tcp_state(state: u32) -> &'static str {
    match state {
        1 => "Closed",
        2 => "Listening",
        3 => "SYN sent",
        4 => "SYN received",
        5 => "Established",
        6 => "FIN wait 1",
        7 => "FIN wait 2",
        8 => "Close wait",
        9 => "Closing",
        10 => "Last ACK",
        11 => "Time wait",
        12 => "Delete TCB",
        _ => "Unknown",
    }
}

fn port(value: u32) -> u16 {
    u16::from_be(value as u16)
}

fn ipv4(value: u32, port_value: u32) -> String {
    format!("{}:{}", Ipv4Addr::from(value.to_ne_bytes()), port(port_value))
}

fn ipv6(value: [u8; 16], scope: u32, port_value: u32) -> String {
    if scope == 0 {
        format!("[{}]:{}", Ipv6Addr::from(value), port(port_value))
    } else {
        format!("[{}%{}]:{}", Ipv6Addr::from(value), scope, port(port_value))
    }
}

/// Shorter gaps between samples keep the previous rate, since a tiny window
/// would turn one burst into a wild number.
const MIN_RATE_WINDOW_SECS: f64 = 0.2;

struct Flow {
    down: u64,
    up: u64,
    at: Instant,
    down_rate: f64,
    up_rate: f64,
    generation: u64,
}

impl Flow {
    fn advance(&mut self, down: u64, up: u64, now: Instant, generation: u64) -> ConnectionTraffic {
        self.generation = generation;
        let elapsed = now.duration_since(self.at).as_secs_f64();
        if elapsed >= MIN_RATE_WINDOW_SECS {
            self.down_rate = down.saturating_sub(self.down) as f64 / elapsed;
            self.up_rate = up.saturating_sub(self.up) as f64 / elapsed;
            self.down = down;
            self.up = up;
            self.at = now;
        }
        ConnectionTraffic { down_per_sec: self.down_rate, up_per_sec: self.up_rate, total_down: down, total_up: up }
    }
}

/// Windows TCP states that can still carry data (Established through Last ACK).
fn tcp_state_carries_data(state: u32) -> bool {
    (5..=10).contains(&state)
}

/// Turns on the per-connection counters when `enable` is set, then reads
/// (bytes in, bytes out). Windows requires elevation to turn them on.
unsafe fn read_tcp4_counters(row: &MIB_TCPROW_LH, enable: bool) -> Option<(u64, u64)> {
    unsafe {
        if enable {
            let rw = TCP_ESTATS_DATA_RW_v0 { EnableCollection: 1 };
            let status = SetPerTcpConnectionEStats(row, TcpConnectionEstatsData, (&raw const rw).cast(), 0, size_of_val(&rw) as u32, 0);
            if status != ERROR_SUCCESS {
                return None;
            }
        }
        let mut rod: TCP_ESTATS_DATA_ROD_v0 = zeroed();
        let status = GetPerTcpConnectionEStats(
            row,
            TcpConnectionEstatsData,
            null_mut(),
            0,
            0,
            null_mut(),
            0,
            0,
            (&raw mut rod).cast(),
            0,
            size_of_val(&rod) as u32,
        );
        (status == ERROR_SUCCESS).then_some((rod.DataBytesIn, rod.DataBytesOut))
    }
}

/// The IPv6 twin of [`read_tcp4_counters`].
unsafe fn read_tcp6_counters(row: &MIB_TCP6ROW, enable: bool) -> Option<(u64, u64)> {
    unsafe {
        if enable {
            let rw = TCP_ESTATS_DATA_RW_v0 { EnableCollection: 1 };
            let status = SetPerTcp6ConnectionEStats(row, TcpConnectionEstatsData, (&raw const rw).cast(), 0, size_of_val(&rw) as u32, 0);
            if status != ERROR_SUCCESS {
                return None;
            }
        }
        let mut rod: TCP_ESTATS_DATA_ROD_v0 = zeroed();
        let status = GetPerTcp6ConnectionEStats(
            row,
            TcpConnectionEstatsData,
            null_mut(),
            0,
            0,
            null_mut(),
            0,
            0,
            (&raw mut rod).cast(),
            0,
            size_of_val(&rod) as u32,
        );
        (status == ERROR_SUCCESS).then_some((rod.DataBytesIn, rod.DataBytesOut))
    }
}

/// Tracks TCP byte counters between listings to work out transfer rates.
#[derive(Default)]
pub struct TrafficMeter {
    flows: HashMap<(String, String, u32), Flow>,
    generation: u64,
}

impl TrafficMeter {
    pub fn new() -> Self {
        Self::default()
    }

    /// The connection list with traffic filled in. A connection that left the
    /// data-carrying states is forgotten, so a reused address pair starts fresh.
    pub fn list(&mut self) -> SystemResult<Vec<NetworkConnection>> {
        self.generation += 1;
        let output = connections(Some(self))?;
        let generation = self.generation;
        self.flows.retain(|_, flow| flow.generation == generation);
        Ok(output)
    }

    fn sample(&mut self, key: (String, String, u32), read: impl FnOnce(bool) -> Option<(u64, u64)>) -> Option<ConnectionTraffic> {
        let (down, up) = read(!self.flows.contains_key(&key))?;
        let now = Instant::now();
        let generation = self.generation;
        let flow = self.flows.entry(key).or_insert(Flow { down, up, at: now, down_rate: 0.0, up_rate: 0.0, generation });
        Some(flow.advance(down, up, now, generation))
    }

    fn sample_v4(&mut self, r: &MIB_TCPROW_OWNER_PID, local: &str, remote: &str) -> Option<ConnectionTraffic> {
        if !tcp_state_carries_data(r.dwState) {
            return None;
        }
        let row = MIB_TCPROW_LH {
            Anonymous: MIB_TCPROW_LH_0 { dwState: r.dwState },
            dwLocalAddr: r.dwLocalAddr,
            dwLocalPort: r.dwLocalPort,
            dwRemoteAddr: r.dwRemoteAddr,
            dwRemotePort: r.dwRemotePort,
        };
        self.sample((local.into(), remote.into(), r.dwOwningPid), |enable| unsafe { read_tcp4_counters(&row, enable) })
    }

    fn sample_v6(&mut self, r: &MIB_TCP6ROW_OWNER_PID, local: &str, remote: &str) -> Option<ConnectionTraffic> {
        if !tcp_state_carries_data(r.dwState) {
            return None;
        }
        let row = MIB_TCP6ROW {
            State: r.dwState as MIB_TCP_STATE,
            LocalAddr: IN6_ADDR { u: IN6_ADDR_0 { Byte: r.ucLocalAddr } },
            dwLocalScopeId: r.dwLocalScopeId,
            dwLocalPort: r.dwLocalPort,
            RemoteAddr: IN6_ADDR { u: IN6_ADDR_0 { Byte: r.ucRemoteAddr } },
            dwRemoteScopeId: r.dwRemoteScopeId,
            dwRemotePort: r.dwRemotePort,
        };
        self.sample((local.into(), remote.into(), r.dwOwningPid), |enable| unsafe { read_tcp6_counters(&row, enable) })
    }
}

/// TCP and UDP endpoints with their owning PID, IPv4 and IPv6. UDP has no
/// remote endpoint in the owning-PID tables, so it is left blank.
pub fn list_network_connections() -> SystemResult<Vec<NetworkConnection>> {
    connections(None)
}

fn connections(mut meter: Option<&mut TrafficMeter>) -> SystemResult<Vec<NetworkConnection>> {
    let mut output = Vec::new();
    unsafe {
        for family in [AF_INET as u32, AF_INET6 as u32] {
            for tcp in [true, false] {
                let mut bytes = 0;
                let query = |ptr: *mut c_void, size: &mut u32| -> u32 {
                    if tcp {
                        GetExtendedTcpTable(ptr, size, 1, family, TCP_TABLE_OWNER_PID_ALL, 0)
                    } else {
                        GetExtendedUdpTable(ptr, size, 1, family, UDP_TABLE_OWNER_PID, 0)
                    }
                };
                let first = query(null_mut(), &mut bytes);
                if first != ERROR_INSUFFICIENT_BUFFER && first != ERROR_SUCCESS {
                    return Err(format!("Network table sizing failed: Win32 error {first}"));
                }
                let mut finished = false;
                for _ in 0..5 {
                    if bytes > 64 * 1024 * 1024 {
                        return Err("Network table exceeds the supported 64 MiB bound".into());
                    }
                    let mut buffer = vec![0u64; (bytes as usize).div_ceil(8) + 1];
                    let status = query(buffer.as_mut_ptr() as _, &mut bytes);
                    if status == ERROR_INSUFFICIENT_BUFFER {
                        continue;
                    }
                    if status != ERROR_SUCCESS {
                        return Err(format!("Network table query failed: Win32 error {status}"));
                    }
                    let count = std::ptr::read_unaligned(buffer.as_ptr() as *const u32) as usize;
                    let ipv4_family = family == AF_INET as u32;
                    let stride = match (tcp, ipv4_family) {
                        (true, true) => size_of::<MIB_TCPROW_OWNER_PID>(),
                        (true, false) => size_of::<MIB_TCP6ROW_OWNER_PID>(),
                        (false, true) => size_of::<MIB_UDPROW_OWNER_PID>(),
                        (false, false) => size_of::<MIB_UDP6ROW_OWNER_PID>(),
                    };
                    if count.saturating_mul(stride).saturating_add(4) > buffer.len() * 8 {
                        return Err("Windows returned an invalid network table length".into());
                    }
                    for index in 0..count {
                        let ptr = (buffer.as_ptr() as *const u8).add(4 + index * stride);
                        let row = match (tcp, ipv4_family) {
                            (true, true) => {
                                let r = std::ptr::read_unaligned(ptr as *const MIB_TCPROW_OWNER_PID);
                                let local_address = ipv4(r.dwLocalAddr, r.dwLocalPort);
                                let remote_address = ipv4(r.dwRemoteAddr, r.dwRemotePort);
                                let traffic = meter.as_deref_mut().and_then(|m| m.sample_v4(&r, &local_address, &remote_address));
                                NetworkConnection {
                                    protocol: "TCP4".into(),
                                    local_address,
                                    remote_address,
                                    state: tcp_state(r.dwState).into(),
                                    pid: r.dwOwningPid,
                                    traffic,
                                }
                            }
                            (true, false) => {
                                let r = std::ptr::read_unaligned(ptr as *const MIB_TCP6ROW_OWNER_PID);
                                let local_address = ipv6(r.ucLocalAddr, r.dwLocalScopeId, r.dwLocalPort);
                                let remote_address = ipv6(r.ucRemoteAddr, r.dwRemoteScopeId, r.dwRemotePort);
                                let traffic = meter.as_deref_mut().and_then(|m| m.sample_v6(&r, &local_address, &remote_address));
                                NetworkConnection {
                                    protocol: "TCP6".into(),
                                    local_address,
                                    remote_address,
                                    state: tcp_state(r.dwState).into(),
                                    pid: r.dwOwningPid,
                                    traffic,
                                }
                            }
                            (false, true) => {
                                let r = std::ptr::read_unaligned(ptr as *const MIB_UDPROW_OWNER_PID);
                                NetworkConnection {
                                    protocol: "UDP4".into(),
                                    local_address: ipv4(r.dwLocalAddr, r.dwLocalPort),
                                    remote_address: String::new(),
                                    state: "Bound".into(),
                                    pid: r.dwOwningPid,
                                    traffic: None,
                                }
                            }
                            (false, false) => {
                                let r = std::ptr::read_unaligned(ptr as *const MIB_UDP6ROW_OWNER_PID);
                                NetworkConnection {
                                    protocol: "UDP6".into(),
                                    local_address: ipv6(r.ucLocalAddr, r.dwLocalScopeId, r.dwLocalPort),
                                    remote_address: String::new(),
                                    state: "Bound".into(),
                                    pid: r.dwOwningPid,
                                    traffic: None,
                                }
                            }
                        };
                        output.push(row);
                    }
                    finished = true;
                    break;
                }
                if !finished {
                    return Err("Network tables kept changing; retry the inventory".into());
                }
            }
        }
    }
    output.sort_by(|a, b| a.pid.cmp(&b.pid).then(a.protocol.cmp(&b.protocol)).then(a.local_address.cmp(&b.local_address)));
    Ok(output)
}

// ---------------------------------------------------------------- controls

/// Refusals that need no handle: Idle, System, this process, unknown identity.
pub fn control_refusal(identity: &ProcessIdentity, own_pid: u32) -> Option<&'static str> {
    if identity.pid == 0 || identity.pid == 4 {
        Some("Idle and System cannot be controlled")
    } else if identity.pid == own_pid {
        Some("The dashboard does not act on itself")
    } else if identity.creation_time == 0 {
        Some("The process start time is unknown; refresh and try again")
    } else {
        None
    }
}

/// Opens the process and re-checks that it is still the same process (PID and
/// creation time) and not a Windows critical process.
unsafe fn open_controlled(identity: &ProcessIdentity, access: u32) -> SystemResult<OwnedHandle> {
    if let Some(reason) = control_refusal(identity, std::process::id()) {
        return Err(reason.into());
    }
    let handle = unsafe {
        OwnedHandle::checked(OpenProcess(access | PROCESS_QUERY_LIMITED_INFORMATION, 0, identity.pid), "Open process")?
    };
    let creation = unsafe { process_times(handle.0) }.ok_or_else(|| last_error("Read process start time"))?.0;
    if creation != identity.creation_time {
        return Err("The PID now belongs to a different process; nothing was done".into());
    }
    let mut critical = 0;
    if unsafe { IsProcessCritical(handle.0, &mut critical) } == 0 {
        return Err("Windows did not disclose whether the process is critical; nothing was done".into());
    }
    if critical != 0 {
        return Err("This is a Windows critical process; ending or suspending it would crash Windows".into());
    }
    Ok(handle)
}

/// Ends the process and waits up to five seconds for it to exit.
pub fn terminate_process(identity: &ProcessIdentity) -> SystemResult<()> {
    unsafe {
        let handle = open_controlled(identity, PROCESS_TERMINATE | PROCESS_SYNCHRONIZE)?;
        if TerminateProcess(handle.0, 1) == 0 {
            return Err(last_error("End process"));
        }
        if WaitForSingleObject(handle.0, 5000) != WAIT_OBJECT_0 {
            return Err("The process was told to end but has not exited after 5 seconds".into());
        }
        Ok(())
    }
}

/// Threads suspended by the dashboard, per process. Only these are ever resumed,
/// so a suspension made by something else (a debugger) is left alone.
fn suspended() -> &'static Mutex<HashMap<ProcessIdentity, Vec<OwnedHandle>>> {
    static SUSPENDED: OnceLock<Mutex<HashMap<ProcessIdentity, Vec<OwnedHandle>>>> = OnceLock::new();
    SUSPENDED.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Suspends every thread of the process; returns how many were suspended.
pub fn suspend_process(identity: &ProcessIdentity) -> SystemResult<usize> {
    let mut map = suspended().lock().map_err(|_| "Suspension registry is unavailable")?;
    if map.contains_key(identity) {
        return Err("The dashboard has already suspended this process".into());
    }
    unsafe {
        let _process = open_controlled(identity, 0)?;
        let snapshot = OwnedHandle::checked(CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0), "Thread snapshot")?;
        let mut entry: THREADENTRY32 = zeroed();
        entry.dwSize = size_of::<THREADENTRY32>() as u32;
        let mut handles = Vec::new();
        let mut next = Thread32First(snapshot.0, &mut entry);
        while next != 0 {
            if entry.th32OwnerProcessID == identity.pid {
                let thread = OpenThread(THREAD_SUSPEND_RESUME, 0, entry.th32ThreadID);
                if !thread.is_null() {
                    let thread = OwnedHandle(thread);
                    if SuspendThread(thread.0) != u32::MAX {
                        handles.push(thread);
                    }
                }
            }
            next = Thread32Next(snapshot.0, &mut entry);
        }
        if handles.is_empty() {
            return Err(last_error("Suspend threads (none could be opened)"));
        }
        let count = handles.len();
        map.insert(*identity, handles);
        Ok(count)
    }
}

/// Resumes the threads this dashboard suspended in the process.
pub fn resume_process(identity: &ProcessIdentity) -> SystemResult<usize> {
    let handles = suspended()
        .lock()
        .map_err(|_| "Suspension registry is unavailable")?
        .remove(identity)
        .ok_or("The dashboard has not suspended this process")?;
    Ok(handles.iter().filter(|h| unsafe { ResumeThread(h.0) } != u32::MAX).count())
}

/// Processes currently suspended by the dashboard.
pub fn suspended_processes() -> Vec<ProcessIdentity> {
    suspended().lock().map(|m| m.keys().copied().collect()).unwrap_or_default()
}

/// Resumes everything the dashboard suspended (called on exit).
pub fn resume_all_suspended() -> usize {
    let all: Vec<(ProcessIdentity, Vec<OwnedHandle>)> = suspended().lock().map(|mut m| m.drain().collect()).unwrap_or_default();
    all.iter().map(|(_, handles)| handles.iter().filter(|h| unsafe { ResumeThread(h.0) } != u32::MAX).count()).sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn machine_normalized_cpu_does_not_multiply_by_core_count() {
        assert_eq!(cpu_from_deltas(25, 100), 25.0);
        assert_eq!(cpu_from_deltas(0, 0), 0.0);
        assert_eq!(cpu_from_deltas(200, 100), 100.0);
    }

    #[test]
    fn network_byte_order_is_decoded_for_ipv4_and_ports() {
        assert_eq!(ipv4(u32::from_ne_bytes([127, 0, 0, 1]), u16::to_be(443) as u32), "127.0.0.1:443");
        assert_eq!(ipv6(Ipv6Addr::LOCALHOST.octets(), 0, u16::to_be(80) as u32), "[::1]:80");
    }

    #[test]
    fn controls_refuse_protected_targets() {
        let own = std::process::id();
        for pid in [0, 4, own] {
            assert!(control_refusal(&ProcessIdentity { pid, creation_time: 1 }, own).is_some());
        }
        assert!(control_refusal(&ProcessIdentity { pid: 1234, creation_time: 0 }, own).is_some());
        assert!(control_refusal(&ProcessIdentity { pid: 1234, creation_time: 1 }, own).is_none());
        // A stale start time is refused before anything happens.
        let snapshot = Monitor::new().refresh().unwrap();
        let other = snapshot
            .processes
            .iter()
            .find(|p| p.accessible && p.identity.creation_time != 0 && p.identity.pid != own)
            .unwrap();
        let stale = ProcessIdentity { pid: other.identity.pid, creation_time: other.identity.creation_time + 1 };
        assert!(terminate_process(&stale).unwrap_err().contains("different process"));
        assert!(suspend_process(&stale).is_err());
        assert!(resume_process(&stale).is_err(), "nothing was suspended by the dashboard");
    }

    /// End to end on a throwaway child process started by the test itself.
    #[test]
    fn suspend_resume_and_end_a_child_process() {
        use std::os::windows::process::CommandExt;
        let mut child = std::process::Command::new("cmd.exe")
            .args(["/c", "ping -n 30 127.0.0.1 >nul"])
            .creation_flags(0x0800_0000) // CREATE_NO_WINDOW
            .spawn()
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(300));
        let snapshot = Monitor::new().refresh().unwrap();
        let identity = snapshot.processes.iter().find(|p| p.identity.pid == child.id()).unwrap().identity;
        assert!(suspend_process(&identity).unwrap() >= 1);
        assert!(suspended_processes().contains(&identity));
        assert!(suspend_process(&identity).is_err(), "double suspend is refused");
        assert!(resume_process(&identity).unwrap() >= 1);
        terminate_process(&identity).unwrap();
        assert!(child.try_wait().unwrap().is_some(), "the child has exited");
    }

    #[test]
    fn live_inventories_include_this_process() {
        let snapshot = Monitor::new().refresh().expect("process snapshot");
        let own = snapshot.processes.iter().find(|p| p.identity.pid == std::process::id()).expect("own process");
        assert!(own.identity.creation_time > 0 && !own.path.is_empty());
        let by_pid = image_path_by_pid(own.identity.pid).expect("path without a handle");
        assert!(by_pid.eq_ignore_ascii_case(&own.path), "{by_pid} vs {}", own.path);
        if !is_elevated() {
            assert!(!enable_debug_privilege(), "only elevated tokens hold SeDebugPrivilege");
        }
        let lsass = format!("{}\\LSASS.EXE", crate::winutil::system_directory().unwrap());
        assert!(is_credential_store(&lsass) && !is_credential_store(&own.path));
        assert!(own.user.contains('\\'), "user is DOMAIN\\name: {}", own.user);
        let exe = std::env::current_exe().unwrap();
        let file = exe.file_name().unwrap().to_string_lossy().to_lowercase();
        assert!(own.command_line.to_lowercase().contains(&file), "{}", own.command_line);
        let started = filetime_to_unix(own.identity.creation_time).unwrap();
        assert!(started <= crate::winutil::now_unix() && started > 1_600_000_000);
        assert!(snapshot.memory_total_bytes > 0 && (0.0..=100.0).contains(&snapshot.cpu_percent));
        let modules = process_modules(&own.identity).expect("own modules");
        assert!(modules.iter().any(|m| m.name.eq_ignore_ascii_case("ntdll.dll")));
        let stale = ProcessIdentity { pid: own.identity.pid, creation_time: own.identity.creation_time + 1 };
        assert!(process_modules(&stale).is_err(), "a changed creation time is refused");
        assert!(file_details(&own.path).unwrap().size_bytes > 0);
        assert!(!list_services(false).unwrap().is_empty());
        assert!(!list_services(true).unwrap().is_empty());
        let autoruns = list_autoruns().unwrap();
        let unique: std::collections::HashSet<_> = autoruns.iter().map(|a| (&a.location, &a.name, &a.command)).collect();
        assert_eq!(unique.len(), autoruns.len(), "no startup entry is listed twice");
        list_network_connections().unwrap();
    }

    #[test]
    fn drivers_without_a_registered_path_use_the_default_location() {
        assert_eq!(effective_binary_path(String::new(), "Beep", 1), r"\SystemRoot\System32\drivers\Beep.sys");
        assert_eq!(effective_binary_path(String::new(), "Ntfs", 2), r"\SystemRoot\System32\drivers\Ntfs.sys");
        assert_eq!(effective_binary_path(r"system32\drivers\a.sys".into(), "a", 1), r"system32\drivers\a.sys");
        assert_eq!(effective_binary_path(String::new(), "svc", 0x10), "", "only drivers have that default");
    }

    #[test]
    fn every_running_driver_resolves_to_a_file_path() {
        let unresolved: Vec<String> = list_services(true)
            .unwrap()
            .into_iter()
            .filter(|d| d.state == "Running" && crate::inventory::image_path_from_command(&d.binary_path).is_none())
            .map(|d| d.name)
            .collect();
        assert!(unresolved.is_empty(), "{unresolved:?}");
    }

    #[test]
    fn flow_rates_use_the_elapsed_window() {
        let start = Instant::now();
        let mut flow = Flow { down: 1000, up: 500, at: start, down_rate: 0.0, up_rate: 0.0, generation: 0 };
        let one_second = start + std::time::Duration::from_secs(1);
        let t = flow.advance(3000, 600, one_second, 1);
        assert_eq!((t.down_per_sec, t.up_per_sec, t.total_down, t.total_up), (2000.0, 100.0, 3000, 600));
        // Too soon to measure: totals move, the rate holds.
        let t = flow.advance(9000, 600, one_second + std::time::Duration::from_millis(10), 2);
        assert_eq!((t.down_per_sec, t.total_down), (2000.0, 9000));
        // A counter that goes backwards never yields a huge rate.
        let t = flow.advance(10, 10, one_second + std::time::Duration::from_secs(1), 3);
        assert_eq!((t.down_per_sec, t.up_per_sec), (0.0, 0.0));
    }

    #[test]
    fn meter_measures_real_loopback_traffic() {
        use std::io::{Read, Write};
        use std::net::{TcpListener, TcpStream};
        if !is_elevated() {
            eprintln!("skipped: per-connection counters need elevation");
            return;
        }
        const BYTES: usize = 2 * 1024 * 1024;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut server, _) = listener.accept().unwrap();
        let (client_local, client_remote) = (client.local_addr().unwrap().to_string(), client.peer_addr().unwrap().to_string());
        let find = |list: &[NetworkConnection], local: &str, remote: &str| {
            list.iter().find(|c| c.local_address == local && c.remote_address == remote).and_then(|c| c.traffic)
        };

        let mut meter = TrafficMeter::new();
        let before = meter.list().unwrap();
        assert!(find(&before, &client_local, &client_remote).is_some(), "the counters switch on");

        std::thread::sleep(std::time::Duration::from_millis(300));
        let sender = std::thread::spawn(move || client.write_all(&vec![7u8; BYTES]).map(|()| client));
        let mut received = vec![0u8; BYTES];
        server.read_exact(&mut received).unwrap();
        let _client = sender.join().unwrap().unwrap();

        let after = meter.list().unwrap();
        let sent = find(&after, &client_local, &client_remote).expect("client row");
        let got = find(&after, &client_remote, &client_local).expect("server row");
        assert!(sent.total_up >= BYTES as u64, "{sent:?}");
        assert!(got.total_down >= BYTES as u64, "{got:?}");
        assert!(sent.up_per_sec > 0.0 && got.down_per_sec > 0.0, "{sent:?} {got:?}");
    }
}
