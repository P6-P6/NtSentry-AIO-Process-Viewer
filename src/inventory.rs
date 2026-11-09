//! Inventory collection for the dashboard (see [`crate::system`] for the Windows
//! calls) plus command-line and shortcut resolution.

pub use crate::system::{
    AutorunInfo, FileDetails, ModuleInfo, Monitor, NetworkConnection, ProcessIdentity, ProcessInfo, ProcessSnapshot,
    ServiceInfo,
};
use crate::system as backend;

#[derive(Clone, Debug, Default)]
pub struct SystemInventory {
    pub collected_unix: u64,
    pub services: Vec<ServiceInfo>,
    pub drivers: Vec<ServiceInfo>,
    pub startup: Vec<AutorunInfo>,
    pub connections: Vec<NetworkConnection>,
    /// One message per inventory that could not be read.
    pub errors: Vec<String>,
}

pub fn collect() -> SystemInventory {
    let mut inv = SystemInventory { collected_unix: crate::winutil::now_unix(), ..Default::default() };
    match backend::list_services(false) {
        Ok(v) => inv.services = v,
        Err(e) => inv.errors.push(format!("Services: {e}")),
    }
    match backend::list_services(true) {
        Ok(v) => inv.drivers = v,
        Err(e) => inv.errors.push(format!("Drivers: {e}")),
    }
    match backend::list_autoruns() {
        Ok(v) => inv.startup = v,
        Err(e) => inv.errors.push(format!("Startup: {e}")),
    }
    match backend::list_network_connections() {
        Ok(v) => inv.connections = v,
        Err(e) => inv.errors.push(format!("Connections: {e}")),
    }
    inv
}

#[derive(Clone, Debug)]
pub struct ProcessDetails {
    pub pid: u32,
    pub modules: Result<Vec<ModuleInfo>, String>,
    pub file: Result<FileDetails, String>,
}

pub fn process_details(identity: ProcessIdentity, path: &str) -> ProcessDetails {
    ProcessDetails {
        pid: identity.pid,
        modules: backend::process_modules(&identity),
        file: if path.is_empty() { Err("No image path".into()) } else { backend::file_details(path) },
    }
}

const IMAGE_EXTENSIONS: [&str; 14] = [
    ".exe", ".sys", ".dll", ".com", ".scr", ".bat", ".cmd", ".lnk", ".vbs", ".vbe", ".js", ".ps1", ".hta", ".wsf",
];

/// Best-effort file path from a service ImagePath or a startup command line, for
/// "open file location". Returns `None` when no file can be identified.
pub fn image_path_from_command(command: &str) -> Option<String> {
    let command = command.trim();
    let raw = if let Some(rest) = command.strip_prefix('"') {
        rest.split('"').next()?.to_string()
    } else {
        let lower = command.to_lowercase();
        let end = IMAGE_EXTENSIONS
            .iter()
            .filter_map(|ext| {
                lower.match_indices(ext).map(|(i, _)| i + ext.len()).find(|&end| {
                    lower[end..].chars().next().is_none_or(|c| c == ' ' || c == ',')
                })
            })
            .min()
            .unwrap_or(command.len());
        command[..end].to_string()
    };
    let windows = crate::winutil::windows_directory().unwrap_or_else(|| "C:\\Windows".into());
    let mut path = raw.trim().to_string();
    if let Some(rest) = path.strip_prefix(r"\??\") {
        path = rest.to_string();
    }
    let lower = path.to_lowercase();
    if lower.starts_with(r"\systemroot\") {
        path = format!("{windows}{}", &path[r"\SystemRoot".len()..]);
    } else if lower.starts_with(r"system32\") {
        path = format!("{windows}\\{path}");
    }
    path = expand_environment(&path);
    (path.len() > 3 && path.contains('\\')).then_some(path)
}

/// The file a service or startup command runs, following a Startup-folder
/// shortcut to the program it opens rather than the .lnk file itself.
pub fn command_target(command: &str) -> Option<String> {
    let path = image_path_from_command(command)?;
    if !path.to_lowercase().ends_with(".lnk") {
        return Some(path);
    }
    std::fs::read(&path).ok().and_then(|bytes| shortcut_target(&bytes))
}

/// Target path of a Windows shortcut (.lnk), from its LinkInfo block
/// (MS-SHLLINK: LocalBasePath + CommonPathSuffix). `None` when the shortcut has
/// no local target (e.g. a shell or network item) or is malformed.
pub fn shortcut_target(bytes: &[u8]) -> Option<String> {
    let u16_at = |o: usize| bytes.get(o..o + 2).map(|b| u16::from_le_bytes([b[0], b[1]]) as usize);
    let u32_at = |o: usize| bytes.get(o..o + 4).map(|b| u32::from_le_bytes(b.try_into().unwrap()) as usize);
    if u32_at(0)? != 0x4C {
        return None;
    }
    let flags = u32_at(0x14)?;
    let mut offset = 0x4C;
    if flags & 0x1 != 0 {
        offset += 2 + u16_at(offset)?;
    }
    if flags & 0x2 == 0 {
        return None;
    }
    let info = offset;
    let header_size = u32_at(info + 4)?;
    if u32_at(info + 8)? & 0x1 == 0 {
        return None; // No VolumeIDAndLocalBasePath.
    }
    let ansi = |o: usize| -> Option<String> {
        let tail = bytes.get(info + o..)?;
        let end = tail.iter().position(|b| *b == 0)?;
        Some(tail[..end].iter().map(|&b| b as char).collect())
    };
    let unicode = |o: usize| -> Option<String> {
        let tail = bytes.get(info + o..)?;
        let units: Vec<u16> = tail.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).take_while(|u| *u != 0).collect();
        Some(String::from_utf16_lossy(&units))
    };
    let (base, suffix) = if header_size >= 0x24 {
        (unicode(u32_at(info + 28)?)?, unicode(u32_at(info + 32)?).unwrap_or_default())
    } else {
        (ansi(u32_at(info + 16)?)?, ansi(u32_at(info + 24)?).unwrap_or_default())
    };
    let path = if suffix.is_empty() || base.ends_with('\\') { format!("{base}{suffix}") } else { format!("{base}\\{suffix}") };
    (!base.is_empty()).then_some(path)
}

/// Expands `%NAME%` from the environment; unknown names are left as written.
fn expand_environment(text: &str) -> String {
    let mut out = String::new();
    let mut rest = text;
    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        match after.find('%') {
            Some(end) => {
                let name = &after[..end];
                match std::env::var(name) {
                    Ok(value) if !name.is_empty() => out.push_str(&value),
                    _ => out.push_str(&rest[start..start + end + 2]),
                }
                rest = &after[end + 1..];
            }
            None => {
                out.push_str(&rest[start..]);
                rest = "";
            }
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_paths_from_service_and_startup_commands() {
        let windows = crate::winutil::windows_directory().unwrap();
        assert_eq!(
            image_path_from_command(r#""C:\Program Files\App\app.exe" --background"#).as_deref(),
            Some(r"C:\Program Files\App\app.exe")
        );
        assert_eq!(
            image_path_from_command(r"C:\WINDOWS\system32\svchost.exe -k netsvcs -p").as_deref(),
            Some(r"C:\WINDOWS\system32\svchost.exe")
        );
        assert_eq!(
            image_path_from_command(r"\SystemRoot\System32\drivers\ACPI.sys"),
            Some(format!(r"{windows}\System32\drivers\ACPI.sys"))
        );
        assert_eq!(
            image_path_from_command(r"\??\C:\Program Files\AntiCheatExpert\ACE-CORE101308.sys").as_deref(),
            Some(r"C:\Program Files\AntiCheatExpert\ACE-CORE101308.sys")
        );
        assert_eq!(
            image_path_from_command(r"system32\drivers\Acx01000.sys"),
            Some(format!(r"{windows}\system32\drivers\Acx01000.sys"))
        );
        assert_eq!(
            image_path_from_command(r"C:\Windows\System32\rundll32.exe shell32.dll,Control_RunDLL").as_deref(),
            Some(r"C:\Windows\System32\rundll32.exe")
        );
        assert_eq!(image_path_from_command(""), None);
    }

    /// Minimal shell link: header with HasLinkInfo, LinkInfo with an ANSI local base path.
    fn sample_shortcut() -> Vec<u8> {
        let mut lnk = vec![0u8; 0x4C];
        lnk[0..4].copy_from_slice(&0x4Cu32.to_le_bytes());
        lnk[0x14..0x18].copy_from_slice(&0x2u32.to_le_bytes());
        let base = b"C:\\Program Files\\Example App\\app.exe\0";
        let header = 0x1Cusize;
        let suffix_at = header + base.len();
        let mut info = vec![0u8; header];
        let size = (header + base.len() + 1) as u32;
        info[0..4].copy_from_slice(&size.to_le_bytes());
        info[4..8].copy_from_slice(&(header as u32).to_le_bytes());
        info[8..12].copy_from_slice(&1u32.to_le_bytes());
        info[16..20].copy_from_slice(&(header as u32).to_le_bytes());
        info[24..28].copy_from_slice(&(suffix_at as u32).to_le_bytes());
        info.extend_from_slice(base);
        info.push(0);
        lnk.extend_from_slice(&info);
        lnk
    }

    #[test]
    fn command_target_follows_shortcuts_only() {
        assert_eq!(command_target(r#""C:\App\app.exe" --quiet"#).as_deref(), Some(r"C:\App\app.exe"));
        let path = std::env::temp_dir().join(format!("ntsentry-target-{}.lnk", std::process::id()));
        std::fs::write(&path, sample_shortcut()).unwrap();
        let target = command_target(&format!("\"{}\"", path.display()));
        std::fs::remove_file(&path).unwrap();
        assert_eq!(target.as_deref(), Some(r"C:\Program Files\Example App\app.exe"));
    }

    #[test]
    fn reads_shortcut_targets() {
        let mut lnk = sample_shortcut();
        assert_eq!(shortcut_target(&lnk).as_deref(), Some(r"C:\Program Files\Example App\app.exe"));
        assert_eq!(shortcut_target(b"not a shortcut"), None);
        lnk[0x14] = 0;
        assert_eq!(shortcut_target(&lnk), None);
    }

    #[test]
    fn expands_known_variables_only() {
        let windir = std::env::var("SystemRoot").unwrap();
        assert_eq!(expand_environment(r"%SystemRoot%\x.exe"), format!(r"{windir}\x.exe"));
        assert_eq!(expand_environment("%NO_SUCH_VAR_TD%\\x"), "%NO_SUCH_VAR_TD%\\x");
        assert_eq!(expand_environment("100%"), "100%");
    }
}
