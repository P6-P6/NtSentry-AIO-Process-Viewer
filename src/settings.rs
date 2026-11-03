//! User preferences, saved as `settings.json` in the data folder. Unknown or
//! missing fields fall back to defaults, so older files keep loading.

use crate::findings::Severity;
use crate::storage::DataDir;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::Duration;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// Run the ntdll and process scans as soon as the window opens.
    pub scan_on_open: bool,
    /// Run both scans (and log them) on a fixed interval.
    pub scheduled_scans: bool,
    pub scan_interval_minutes: u32,
    /// Refresh live CPU/memory and the inventories automatically.
    pub live_refresh: bool,
    pub live_refresh_seconds: u32,
    pub compare_memory: bool,
    /// Flash the taskbar when a scan finds something that was not in the previous scan.
    pub alert_on_new: bool,
    pub alert_min_severity: Severity,
    pub hide_system_processes: bool,
    /// Show the Processes tab as a parent/child tree.
    pub process_tree: bool,
    /// Write new findings at or above the threshold to the Application event log.
    pub event_log: bool,
    pub event_log_min_severity: Severity,
    /// Hide to the notification area when minimized.
    pub minimize_to_tray: bool,
    /// Include the cross-process ntdll, module and persistence checks in "Scan all"
    /// and scheduled scans.
    pub deep_scans: bool,
    pub show_activity: bool,
    pub light_theme: bool,
    pub zoom: f32,
    /// Hidden column titles per table id.
    pub hidden_columns: BTreeMap<String, Vec<String>>,
    /// Sort column title and direction (true = ascending) per table id.
    pub sorts: BTreeMap<String, (String, bool)>,
    /// Inventory tab shown last.
    pub last_tab: String,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            scan_on_open: true,
            scheduled_scans: true,
            scan_interval_minutes: 60,
            live_refresh: true,
            live_refresh_seconds: 2,
            compare_memory: true,
            alert_on_new: true,
            alert_min_severity: Severity::Medium,
            hide_system_processes: false,
            process_tree: false,
            event_log: false,
            event_log_min_severity: Severity::High,
            minimize_to_tray: true,
            deep_scans: true,
            show_activity: true,
            light_theme: false,
            zoom: 1.0,
            hidden_columns: BTreeMap::from([("processes".to_string(), vec!["Command line".to_string()])]),
            sorts: BTreeMap::new(),
            last_tab: "Processes".into(),
        }
    }
}

impl Settings {
    /// Returns defaults plus a warning when the file exists but cannot be used.
    pub fn load(data: &DataDir) -> (Settings, Option<String>) {
        let path = data.settings_path();
        match std::fs::read_to_string(&path) {
            Ok(text) => match serde_json::from_str::<Settings>(&text) {
                Ok(s) => (s.sanitized(), None),
                Err(e) => (Settings::default(), Some(format!("{} is not valid ({e}); using defaults", path.display()))),
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (Settings::default(), None),
            Err(e) => (Settings::default(), Some(format!("Cannot read {}: {e}; using defaults", path.display()))),
        }
    }

    /// Writes a temporary file, then replaces `settings.json` with it.
    pub fn save(&self, data: &DataDir) -> Result<(), String> {
        std::fs::create_dir_all(&data.root).map_err(|e| format!("Cannot create {}: {e}", data.root.display()))?;
        let path = data.settings_path();
        let temp = path.with_extension("json.tmp");
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(&temp, json).map_err(|e| format!("Cannot write {}: {e}", temp.display()))?;
        std::fs::rename(&temp, &path).map_err(|e| format!("Cannot replace {}: {e}", path.display()))
    }

    pub fn sanitized(mut self) -> Self {
        self.scan_interval_minutes = self.scan_interval_minutes.clamp(5, 1440);
        self.live_refresh_seconds = self.live_refresh_seconds.clamp(1, 300);
        if !self.zoom.is_finite() {
            self.zoom = 1.0;
        }
        self.zoom = self.zoom.clamp(0.5, 3.0);
        self
    }

    pub fn scan_interval(&self) -> Duration {
        Duration::from_secs(u64::from(self.scan_interval_minutes.clamp(5, 1440)) * 60)
    }

    pub fn live_interval(&self) -> Duration {
        Duration::from_secs(u64::from(self.live_refresh_seconds.clamp(1, 300)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::tests::scratch_dir;

    #[test]
    fn round_trips_and_tolerates_partial_or_bad_files() {
        let root = scratch_dir("settings");
        let data = DataDir::at(&root);
        let (s, warning) = Settings::load(&data);
        assert_eq!(s, Settings::default());
        assert!(warning.is_none());

        let changed = Settings { scan_interval_minutes: 30, light_theme: true, ..Settings::default() };
        changed.save(&data).unwrap();
        changed.save(&data).unwrap();
        assert_eq!(Settings::load(&data).0, changed);

        std::fs::write(data.settings_path(), r#"{"scan_interval_minutes": 1}"#).unwrap();
        let (s, _) = Settings::load(&data);
        assert_eq!(s.scan_interval_minutes, 5);
        assert!(s.scan_on_open);

        std::fs::write(data.settings_path(), "not json").unwrap();
        let (s, warning) = Settings::load(&data);
        assert_eq!(s, Settings::default());
        assert!(warning.is_some());
        std::fs::remove_dir_all(&root).unwrap();
    }
}
