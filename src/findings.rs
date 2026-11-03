//! The one record type every scanner reports. Findings are observations for a
//! human to review; none of them triggers an action.

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub const ALL: [Severity; 5] =
        [Severity::Info, Severity::Low, Severity::Medium, Severity::High, Severity::Critical];

    pub fn label(self) -> &'static str {
        match self {
            Severity::Info => "Info",
            Severity::Low => "Low",
            Severity::Medium => "Medium",
            Severity::High => "High",
            Severity::Critical => "Critical",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Finding {
    /// `integrity_monitor` or `process_inventory`.
    pub module: String,
    pub severity: Severity,
    /// What was examined: `ntdll.dll .text`, `pid 1234 foo.exe`, ...
    pub subject: String,
    pub title: String,
    pub detail: String,
    /// Relative virtual address inside the image, when the finding is about bytes.
    pub offset: Option<u64>,
    /// Expected bytes as space-separated hex (baseline or on-disk).
    pub expected: Option<String>,
    /// Observed bytes as space-separated hex (in memory).
    pub observed: Option<String>,
    pub observed_unix: u64,
}

impl Finding {
    pub fn new(module: &str, severity: Severity, subject: impl Into<String>, title: impl Into<String>) -> Self {
        Finding {
            module: module.into(),
            severity,
            subject: subject.into(),
            title: title.into(),
            detail: String::new(),
            offset: None,
            expected: None,
            observed: None,
            observed_unix: crate::winutil::now_unix(),
        }
    }

    pub fn detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = detail.into();
        self
    }

    pub fn bytes(mut self, offset: u64, expected: String, observed: String) -> Self {
        self.offset = Some(offset);
        self.expected = Some(expected);
        self.observed = Some(observed);
        self
    }

    /// The process ID when the subject is a process (`pid 1234 name.exe`).
    pub fn pid(&self) -> Option<u32> {
        self.subject.strip_prefix("pid ")?.split(' ').next()?.parse().ok()
    }

    /// Identifies one row of one scan.
    pub fn row_key(&self) -> String {
        format!("{}|{}|{}|{:?}", self.module, self.subject, self.title, self.offset)
    }

    /// Identifies the same condition across scans and restarts; process IDs are
    /// dropped because they change.
    pub fn stable_key(&self) -> String {
        let subject = match self.pid() {
            Some(_) => self.subject.splitn(3, ' ').nth(2).unwrap_or(""),
            None => self.subject.as_str(),
        };
        format!("{}|{}|{}|{:?}|{}|{}", self.module, self.title, subject, self.offset, self.observed.as_deref().unwrap_or(""), self.detail)
    }
}

/// Result of a scan that only produces findings (persistence, modules, ntdll sweep).
#[derive(Clone, Debug, Default, Serialize)]
pub struct ScanReport {
    /// Log kind: `persistence`, `modules`, `ntdll_sweep`.
    pub kind: String,
    pub scanned_unix: u64,
    pub duration_ms: u128,
    /// One line for the dashboard summary.
    pub summary: String,
    pub findings: Vec<Finding>,
}

/// Highest severity first, then by subject and offset, so the UI and logs read the same way.
pub fn sort_findings(findings: &mut [Finding]) {
    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.subject.cmp(&b.subject))
            .then_with(|| a.offset.cmp(&b.offset))
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_key_ignores_pid_but_row_key_does_not() {
        let a = Finding::new("process_inventory", Severity::Medium, "pid 100 app.exe", "Unsigned image").detail("C:\\x\\app.exe");
        let b = Finding::new("process_inventory", Severity::Medium, "pid 200 app.exe", "Unsigned image").detail("C:\\x\\app.exe");
        assert_eq!(a.pid(), Some(100));
        assert_eq!(a.stable_key(), b.stable_key());
        assert_ne!(a.row_key(), b.row_key());
        let n = Finding::new("integrity_monitor", Severity::High, "ntdll.dll .text", "x");
        assert_eq!(n.pid(), None);
        assert!(n.stable_key().contains("ntdll.dll .text"));
    }
}
