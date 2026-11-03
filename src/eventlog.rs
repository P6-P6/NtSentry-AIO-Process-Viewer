//! Opt-in: write findings to the Windows Application event log (source
//! "NtSentry"), so other monitoring tools can collect them.
//!
//! The source is not registered with a message file, which needs administrator
//! rights. Event Viewer therefore prefixes each event with a note that the
//! description is missing; the finding text itself is included in full.

use crate::findings::{Finding, Severity};
use crate::winutil::wide;
use std::ptr::{null, null_mut};
use windows_sys::Win32::System::EventLog::{
    DeregisterEventSource, EVENTLOG_ERROR_TYPE, EVENTLOG_INFORMATION_TYPE, EVENTLOG_WARNING_TYPE, RegisterEventSourceW,
    ReportEventW,
};

pub const SOURCE: &str = "NtSentry";

/// Event ID per severity, so events can be filtered: 1000 + severity (Info = 0).
pub fn event_id(severity: Severity) -> u32 {
    1000 + severity as u32
}

pub fn message(f: &Finding) -> String {
    let mut text = format!("[{}] {}\r\nModule: {}\r\nSubject: {}\r\n", f.severity.label(), f.title, f.module, f.subject);
    if let Some(o) = f.offset {
        text.push_str(&format!("RVA: 0x{o:X}\r\n"));
    }
    if let (Some(e), Some(o)) = (&f.expected, &f.observed) {
        text.push_str(&format!("Expected: {e}\r\nObserved: {o}\r\n"));
    }
    if !f.detail.is_empty() {
        text.push_str(&format!("Detail: {}\r\n", f.detail));
    }
    text
}

pub fn write(findings: &[&Finding]) -> Result<usize, String> {
    if findings.is_empty() {
        return Ok(0);
    }
    let source = wide(SOURCE);
    let handle = unsafe { RegisterEventSourceW(null(), source.as_ptr()) };
    if handle.is_null() {
        return Err(format!("Cannot open the Application event log ({})", std::io::Error::last_os_error()));
    }
    let mut written = 0;
    let mut last_error = None;
    for f in findings {
        let kind = match f.severity {
            Severity::Critical | Severity::High => EVENTLOG_ERROR_TYPE,
            Severity::Medium | Severity::Low => EVENTLOG_WARNING_TYPE,
            Severity::Info => EVENTLOG_INFORMATION_TYPE,
        };
        let text = wide(&message(f));
        let strings = [text.as_ptr()];
        let ok = unsafe {
            ReportEventW(handle, kind, 0, event_id(f.severity), null_mut(), 1, 0, strings.as_ptr(), null())
        };
        if ok != 0 {
            written += 1;
        } else {
            last_error = Some(std::io::Error::last_os_error().to_string());
        }
    }
    unsafe { DeregisterEventSource(handle) };
    match last_error {
        Some(e) if written == 0 => Err(format!("Cannot write to the Application event log ({e})")),
        _ => Ok(written),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_contains_every_field() {
        let f = Finding::new("integrity_monitor", Severity::High, "ntdll.dll .text", "Possible inline hook at NtOpenProcess")
            .detail("5 byte(s)")
            .bytes(0x1000, "4C 8B D1".into(), "E9 00 00".into());
        let m = message(&f);
        for part in ["[High]", "NtOpenProcess", "ntdll.dll .text", "0x1000", "4C 8B D1", "E9 00 00", "5 byte(s)"] {
            assert!(m.contains(part), "{part} missing from {m}");
        }
        assert_eq!(event_id(Severity::Critical), 1004);
    }
}
