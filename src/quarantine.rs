//! Quarantine: move an executable out of the way, restorably.
//!
//! The file is copied into `quarantine\<id>\payload.bin`, masked with a repeating
//! key so it cannot be run or re-scanned by accident (this is obfuscation, not
//! encryption), next to a `manifest.json` with its original path and SHA-256.
//! The copy is verified before the original is deleted. Restoring writes the file
//! back only if nothing exists at the original path, and checks the hash.

use crate::storage::{DataDir, write_new};
use crate::winutil::{now_unix, sha256_hex};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

const MASK: &[u8] = b"ntsentry-quarantine";
const MANIFEST: &str = "manifest.json";
const PAYLOAD: &str = "payload.bin";
const RESTORED_SUFFIX: &str = ".restored";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuarantineEntry {
    pub id: String,
    pub original_path: String,
    pub sha256: String,
    pub size: u64,
    pub quarantined_unix: u64,
    /// Process that was running the file, e.g. `pid 1234 tool.exe`.
    pub process: String,
    pub signature: String,
}

pub fn quarantine_dir(data: &DataDir) -> PathBuf {
    data.root.join("quarantine")
}

fn mask(bytes: &mut [u8]) {
    for (i, b) in bytes.iter_mut().enumerate() {
        *b ^= MASK[i % MASK.len()];
    }
}

/// Files that must never be quarantined: Windows' own files and this program.
pub fn refusal(path: &str, windows_dir: &str) -> Option<String> {
    let lower = path.to_lowercase();
    let windows = format!("{}\\", windows_dir.trim_end_matches('\\').to_lowercase());
    if lower.starts_with(&windows) {
        return Some(format!("{path} is under the Windows folder; quarantining Windows files can break the system"));
    }
    own_file_refusal(path)
}

/// Refuses this program's own file.
pub fn own_file_refusal(path: &str) -> Option<String> {
    let own = std::env::current_exe().ok().map(|p| p.to_string_lossy().to_lowercase());
    (own.as_deref() == Some(path.to_lowercase().as_str())).then(|| "The dashboard does not quarantine itself".to_string())
}

/// Copies `path` into quarantine, verifies the copy, then deletes the original.
/// If the original cannot be deleted, the copy is kept and an error says so.
pub fn quarantine_file(data: &DataDir, path: &str, process: &str, signature: &str) -> Result<QuarantineEntry, String> {
    let windows = crate::winutil::windows_directory().unwrap_or_else(|| "C:\\Windows".into());
    if let Some(reason) = refusal(path, &windows) {
        return Err(reason);
    }
    move_into_quarantine(data, path, process, signature)
}

/// For a stopped service or driver. Third-party drivers normally live under the
/// Windows folder, so the caller refuses Microsoft's own files by signature instead.
pub fn quarantine_service_file(data: &DataDir, path: &str, owner: &str, signature: &str) -> Result<QuarantineEntry, String> {
    if let Some(reason) = own_file_refusal(path) {
        return Err(reason);
    }
    move_into_quarantine(data, path, owner, signature)
}

fn move_into_quarantine(data: &DataDir, path: &str, process: &str, signature: &str) -> Result<QuarantineEntry, String> {
    let bytes = fs::read(path).map_err(|e| format!("Cannot read {path}: {e}"))?;
    let sha256 = sha256_hex(&bytes);
    let root = quarantine_dir(data);
    fs::create_dir_all(&root).map_err(|e| format!("Cannot create {}: {e}", root.display()))?;
    let stamp = now_unix();
    let (id, dir) = (0..1000)
        .map(|n| if n == 0 { format!("{stamp}") } else { format!("{stamp}-{n}") })
        .find_map(|id| {
            let dir = root.join(&id);
            fs::create_dir(&dir).ok().map(|_| (id, dir))
        })
        .ok_or("Cannot create a quarantine folder")?;
    let entry = QuarantineEntry {
        id,
        original_path: path.to_string(),
        sha256: sha256.clone(),
        size: bytes.len() as u64,
        quarantined_unix: stamp,
        process: process.to_string(),
        signature: signature.to_string(),
    };
    let mut masked = bytes;
    mask(&mut masked);
    write_new(&dir.join(PAYLOAD), &masked)?;
    let json = serde_json::to_string_pretty(&entry).map_err(|e| e.to_string())?;
    write_new(&dir.join(MANIFEST), json.as_bytes())?;
    let mut check = fs::read(dir.join(PAYLOAD)).map_err(|e| format!("Cannot verify the quarantine copy: {e}"))?;
    mask(&mut check);
    if sha256_hex(&check) != sha256 {
        return Err(format!("The quarantine copy in {} does not match; the original was left in place", dir.display()));
    }
    fs::remove_file(path).map_err(|e| {
        format!("Copied to {} but could not delete the original ({e}); it may still be in use or need administrator rights", dir.display())
    })?;
    Ok(entry)
}

/// Quarantined (not yet restored) entries, newest first.
pub fn list(data: &DataDir) -> Vec<QuarantineEntry> {
    let Ok(dirs) = fs::read_dir(quarantine_dir(data)) else { return Vec::new() };
    let mut entries: Vec<QuarantineEntry> = dirs
        .flatten()
        .filter(|d| !d.file_name().to_string_lossy().ends_with(RESTORED_SUFFIX))
        .filter_map(|d| serde_json::from_str(&fs::read_to_string(d.path().join(MANIFEST)).ok()?).ok())
        .collect();
    entries.sort_by_key(|e| std::cmp::Reverse(e.quarantined_unix));
    entries
}

/// Writes the file back to its original path (never overwriting) and marks the
/// entry restored; the quarantine copy is kept under `<id>.restored`.
pub fn restore(data: &DataDir, id: &str) -> Result<String, String> {
    if id.is_empty() || id.contains(['\\', '/', '.']) {
        return Err("Invalid quarantine id".into());
    }
    let dir = quarantine_dir(data).join(id);
    let entry: QuarantineEntry = serde_json::from_str(
        &fs::read_to_string(dir.join(MANIFEST)).map_err(|e| format!("Cannot read the quarantine manifest: {e}"))?,
    )
    .map_err(|e| format!("Quarantine manifest is not valid: {e}"))?;
    let target = Path::new(&entry.original_path);
    if target.exists() {
        return Err(format!("{} already exists; restore refuses to overwrite it", entry.original_path));
    }
    let mut bytes = fs::read(dir.join(PAYLOAD)).map_err(|e| format!("Cannot read the quarantine copy: {e}"))?;
    mask(&mut bytes);
    if sha256_hex(&bytes) != entry.sha256 {
        return Err("The quarantine copy no longer matches its recorded hash; not restored".into());
    }
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("Cannot recreate {}: {e}", parent.display()))?;
    }
    write_new(target, &bytes)?;
    let done = quarantine_dir(data).join(format!("{id}{RESTORED_SUFFIX}"));
    fs::rename(&dir, &done).map_err(|e| format!("Restored, but could not mark the entry restored: {e}"))?;
    Ok(entry.original_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::tests::scratch_dir;

    #[test]
    fn quarantine_and_restore_round_trip() {
        let root = scratch_dir("quarantine");
        let data = DataDir::at(root.join("data"));
        let victim_dir = root.join("app");
        fs::create_dir_all(&victim_dir).unwrap();
        let victim = victim_dir.join("tool.exe");
        fs::write(&victim, b"MZ pretend program").unwrap();
        let path = victim.to_string_lossy().to_string();

        let entry = quarantine_file(&data, &path, "pid 1 tool.exe", "Unsigned").unwrap();
        assert!(!victim.exists(), "original removed");
        let payload = fs::read(quarantine_dir(&data).join(&entry.id).join(PAYLOAD)).unwrap();
        assert_ne!(payload, b"MZ pretend program", "stored masked");
        assert_eq!(list(&data), vec![entry.clone()]);

        fs::write(&victim, b"something new").unwrap();
        assert!(restore(&data, &entry.id).unwrap_err().contains("refuses to overwrite"));
        fs::remove_file(&victim).unwrap();
        assert_eq!(restore(&data, &entry.id).unwrap(), path);
        assert_eq!(fs::read(&victim).unwrap(), b"MZ pretend program");
        assert!(list(&data).is_empty());
        assert!(restore(&data, "..\\x").is_err());
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn windows_files_are_refused() {
        assert!(refusal(r"C:\Windows\System32\svchost.exe", r"C:\Windows").is_some());
        assert!(refusal(r"C:\WINDOWS\explorer.exe", r"C:\Windows\").is_some());
        assert!(refusal(r"C:\Users\a\AppData\Local\Temp\x.exe", r"C:\Windows").is_none());
    }
}
