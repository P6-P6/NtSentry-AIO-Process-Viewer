//! CSV and JSON exports of what the dashboard shows.

use crate::findings::Finding;
use crate::winutil::format_utc;

/// Quotes a CSV field and neutralises leading characters that spreadsheet programs
/// would otherwise evaluate as formulas.
pub fn csv_field(value: &str) -> String {
    let guarded = if value.starts_with(['=', '+', '-', '@', '\t', '\r']) { format!("'{value}") } else { value.to_string() };
    format!("\"{}\"", guarded.replace('"', "\"\""))
}

pub fn csv<S: AsRef<str>>(headers: &[&str], rows: impl IntoIterator<Item = Vec<S>>) -> String {
    let mut out = headers.iter().map(|h| csv_field(h)).collect::<Vec<_>>().join(",");
    out.push_str("\r\n");
    for row in rows {
        out.push_str(&row.iter().map(|c| csv_field(c.as_ref())).collect::<Vec<_>>().join(","));
        out.push_str("\r\n");
    }
    out
}

pub fn findings_csv(findings: &[Finding]) -> String {
    csv(
        &["Severity", "Module", "Subject", "Finding", "RVA", "Expected", "Observed", "Detail", "Observed (UTC)"],
        findings.iter().map(|f| {
            vec![
                f.severity.label().to_string(),
                f.module.clone(),
                f.subject.clone(),
                f.title.clone(),
                f.offset.map(|o| format!("0x{o:X}")).unwrap_or_default(),
                f.expected.clone().unwrap_or_default(),
                f.observed.clone().unwrap_or_default(),
                f.detail.clone(),
                format_utc(f.observed_unix),
            ]
        }),
    )
}

/// Table rows as JSON objects keyed by column header.
pub fn table_json<S: AsRef<str>>(headers: &[&str], rows: impl IntoIterator<Item = Vec<S>>) -> serde_json::Value {
    serde_json::Value::Array(
        rows.into_iter()
            .map(|row| {
                serde_json::Value::Object(
                    headers
                        .iter()
                        .zip(row.iter())
                        .map(|(h, v)| ((*h).to_string(), serde_json::Value::String(v.as_ref().to_string())))
                        .collect(),
                )
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_quotes_and_guards_formulas() {
        assert_eq!(csv_field("plain"), "\"plain\"");
        assert_eq!(csv_field("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(csv_field("=cmd|'/c calc'!A1"), "\"'=cmd|'/c calc'!A1\"");
        assert_eq!(csv_field("C:\\a,b.exe"), "\"C:\\a,b.exe\"");
        let text = csv(&["A", "B"], vec![vec!["1", "2"]]);
        assert_eq!(text, "\"A\",\"B\"\r\n\"1\",\"2\"\r\n");
    }

    #[test]
    fn table_json_keys_by_header() {
        let v = table_json(&["PID", "Name"], vec![vec!["4", "System"]]);
        assert_eq!(v[0]["PID"], "4");
        assert_eq!(v[0]["Name"], "System");
    }
}
