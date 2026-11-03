//! On-disk state: the integrity baseline and the append-only findings log.
//!
//! Nothing here overwrites: files are created with `create_new`, a baseline is
//! replaced only by first archiving (renaming) the old one, and the log is appended.

use crate::findings::Finding;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

pub const DATA_DIR_ENV: &str = "NTSENTRY_DATA";
/// Size at which `findings.jsonl` is rotated.
pub const LOG_ROTATE_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct DataDir {
    pub root: PathBuf,
}

impl DataDir {
    /// `%NTSENTRY_DATA%` if set, else `%LOCALAPPDATA%\NtSentry`.
    pub fn default_location() -> Result<Self, String> {
        if let Some(dir) = std::env::var_os(DATA_DIR_ENV).filter(|v| !v.is_empty()) {
            return Ok(DataDir { root: PathBuf::from(dir) });
        }
        let local = std::env::var_os("LOCALAPPDATA").ok_or("LOCALAPPDATA is not set")?;
        Ok(DataDir { root: PathBuf::from(local).join("NtSentry") })
    }

    pub fn at(root: impl Into<PathBuf>) -> Self {
        DataDir { root: root.into() }
    }

    pub fn baseline_dir(&self) -> PathBuf {
        self.root.join("baseline")
    }

    pub fn findings_log(&self) -> PathBuf {
        self.root.join("findings.jsonl")
    }

    pub fn settings_path(&self) -> PathBuf {
        self.root.join("settings.json")
    }

    /// Findings of the most recent logged scan of this kind, read from the log.
    pub fn last_logged(&self, scan: &str) -> Option<Vec<Finding>> {
        let text = fs::read_to_string(self.findings_log()).ok()?;
        text.lines().rev().find_map(|line| {
            let value: serde_json::Value = serde_json::from_str(line).ok()?;
            if value.get("scan")?.as_str()? != scan {
                return None;
            }
            serde_json::from_value(value.get("findings")?.clone()).ok()
        })
    }

    pub fn has_baseline(&self) -> bool {
        self.baseline_dir().join("baseline.json").exists()
    }

    /// Creates a fresh staging directory for a capture. Fails if a baseline exists.
    pub fn begin_baseline(&self) -> Result<PathBuf, String> {
        if self.baseline_dir().exists() {
            return Err(format!(
                "A baseline already exists at {}. Archive it before capturing a new one.",
                self.baseline_dir().display()
            ));
        }
        fs::create_dir_all(&self.root).map_err(|e| format!("Cannot create {}: {e}", self.root.display()))?;
        let stem = format!("baseline.partial-{}-{}", crate::winutil::now_unix(), std::process::id());
        for n in 0..1000 {
            let staging = self.root.join(if n == 0 { stem.clone() } else { format!("{stem}-{n}") });
            match fs::create_dir(&staging) {
                Ok(()) => return Ok(staging),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(format!("Cannot create {}: {e}", staging.display())),
            }
        }
        Err(format!("Cannot find an unused staging directory name under {}", self.root.display()))
    }

    /// Moves a completed staging directory into place as the baseline. A baseline
    /// that appeared meanwhile is left untouched and the staging directory is kept.
    pub fn commit_baseline(&self, staging: &Path) -> Result<PathBuf, String> {
        let target = self.baseline_dir();
        if target.exists() {
            return Err(format!(
                "A baseline appeared at {} during capture; the new capture is kept at {}",
                target.display(),
                staging.display()
            ));
        }
        fs::rename(staging, &target).map_err(|e| format!("Cannot move baseline into {}: {e}", target.display()))?;
        Ok(target)
    }

    /// Renames the current baseline to `baseline-archived-<unix>`; the old data is kept.
    pub fn archive_baseline(&self) -> Result<PathBuf, String> {
        let from = self.baseline_dir();
        if !from.exists() {
            return Err("There is no baseline to archive.".into());
        }
        let mut to = self.root.join(format!("baseline-archived-{}", crate::winutil::now_unix()));
        let mut n = 1;
        while to.exists() {
            to = self.root.join(format!("baseline-archived-{}-{n}", crate::winutil::now_unix()));
            n += 1;
        }
        fs::rename(&from, &to).map_err(|e| format!("Cannot archive baseline to {}: {e}", to.display()))?;
        Ok(to)
    }

    /// One JSON line per scan: `{"unix":..,"scan":..,"findings":[..]}`. When the
    /// log passes [`LOG_ROTATE_BYTES`] it is renamed to `findings-<unix>.jsonl`
    /// (kept, never deleted) and a new one is started.
    pub fn append_log(&self, scan: &str, findings: &[Finding]) -> Result<(), String> {
        self.append_log_rotating(scan, findings, LOG_ROTATE_BYTES)
    }

    fn append_log_rotating(&self, scan: &str, findings: &[Finding], limit: u64) -> Result<(), String> {
        fs::create_dir_all(&self.root).map_err(|e| format!("Cannot create {}: {e}", self.root.display()))?;
        if fs::metadata(self.findings_log()).is_ok_and(|m| m.len() >= limit) {
            let stamp = crate::winutil::now_unix();
            let mut to = self.root.join(format!("findings-{stamp}.jsonl"));
            let mut n = 1;
            while to.exists() {
                to = self.root.join(format!("findings-{stamp}-{n}.jsonl"));
                n += 1;
            }
            fs::rename(self.findings_log(), &to).map_err(|e| format!("Cannot rotate the findings log to {}: {e}", to.display()))?;
        }
        let line = serde_json::json!({
            "unix": crate::winutil::now_unix(),
            "scan": scan,
            "findings": findings,
        });
        let path = self.findings_log();
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| format!("Cannot open {}: {e}", path.display()))?;
        writeln!(file, "{line}").map_err(|e| format!("Cannot append to {}: {e}", path.display()))
    }
}

pub fn write_new(path: &Path, contents: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| format!("Cannot create {}: {e}", path.display()))?;
    file.write_all(contents)
        .and_then(|_| file.sync_all())
        .map_err(|e| format!("Cannot finish {}: {e}", path.display()))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn scratch_dir(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("ntsentry-test-{tag}-{}-{nanos}", std::process::id()))
    }

    #[test]
    fn baseline_is_never_overwritten_and_archive_keeps_data() {
        let root = scratch_dir("storage");
        let data = DataDir::at(&root);
        let staging = data.begin_baseline().unwrap();
        write_new(&staging.join("baseline.json"), b"{}").unwrap();
        assert!(write_new(&staging.join("baseline.json"), b"{}").is_err());
        let first = data.begin_baseline().unwrap();
        data.commit_baseline(&staging).unwrap();
        assert!(data.has_baseline());
        assert!(data.begin_baseline().unwrap_err().contains("already exists"));
        assert!(data.commit_baseline(&first).is_err());
        assert!(first.exists());
        let archived = data.archive_baseline().unwrap();
        assert!(archived.join("baseline.json").exists());
        assert!(!data.has_baseline());
        data.append_log("test", &[]).unwrap();
        let marker = Finding::new("m", crate::findings::Severity::Low, "s", "first");
        data.append_log("other", &[marker]).unwrap();
        data.append_log("test", &[]).unwrap();
        let log = fs::read_to_string(data.findings_log()).unwrap();
        assert_eq!(log.lines().count(), 3);
        assert_eq!(data.last_logged("other").unwrap()[0].title, "first");
        assert!(data.last_logged("test").unwrap().is_empty());
        assert!(data.last_logged("missing").is_none());
        // Rotation keeps the old log under a new name and starts a fresh one.
        data.append_log_rotating("test", &[], 1).unwrap();
        let rotated: Vec<_> = fs::read_dir(&root)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with("findings-"))
            .collect();
        assert_eq!(rotated.len(), 1);
        assert_eq!(fs::read_to_string(rotated[0].path()).unwrap().lines().count(), 3);
        assert_eq!(fs::read_to_string(data.findings_log()).unwrap().lines().count(), 1);
        fs::remove_dir_all(&root).unwrap();
    }
}
