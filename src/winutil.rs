//! Small Win32 helpers shared by the scanners.

use std::time::{SystemTime, UNIX_EPOCH};
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::SystemInformation::{GetSystemDirectoryW, GetWindowsDirectoryW};

pub fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

pub fn from_wide(value: &[u16]) -> String {
    let end = value.iter().position(|x| *x == 0).unwrap_or(value.len());
    String::from_utf16_lossy(&value[..end])
}

/// Closes a kernel handle on drop. Null and INVALID_HANDLE_VALUE are ignored.
pub struct OwnedHandle(pub HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            unsafe { CloseHandle(self.0) };
        }
    }
}

pub fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// `YYYY-MM-DD HH:MM:SS UTC` without a date-time dependency.
pub fn format_utc(unix: u64) -> String {
    let days = (unix / 86_400) as i64;
    let secs = unix % 86_400;
    // Civil-from-days (Howard Hinnant), valid for the proleptic Gregorian calendar.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02} UTC",
        secs / 3600,
        (secs / 60) % 60,
        secs % 60
    )
}

fn directory_from(call: unsafe extern "system" fn(*mut u16, u32) -> u32) -> Option<String> {
    let mut buffer = [0u16; 520];
    let len = unsafe { call(buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
    (len > 0 && len < buffer.len()).then(|| from_wide(&buffer[..len]))
}

/// The native system directory, normally `C:\Windows\System32`.
pub fn system_directory() -> Option<String> {
    directory_from(GetSystemDirectoryW)
}

/// The Windows directory, normally `C:\Windows`.
pub fn windows_directory() -> Option<String> {
    directory_from(GetWindowsDirectoryW)
}

pub fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 3);
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        out.push_str(&format!("{b:02X}"));
    }
    out
}

/// SHA-256 of a file, read in 1 MiB chunks.
pub fn sha256_file(path: &str) -> Result<String, String> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let mut file = std::fs::File::open(path).map_err(|e| format!("Cannot open {path}: {e}"))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1 << 20];
    loop {
        let n = file.read(&mut buffer).map_err(|e| format!("Cannot read {path}: {e}"))?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    Ok(hasher.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_formatting_matches_known_instants() {
        assert_eq!(format_utc(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(format_utc(951_782_400), "2000-02-29 00:00:00 UTC");
        assert_eq!(format_utc(1_793_646_600), "2026-11-02 19:10:00 UTC");
    }

    #[test]
    fn file_hash_matches_memory_hash() {
        let path = std::env::temp_dir().join(format!("ntsentry-hash-{}.bin", std::process::id()));
        std::fs::write(&path, b"abc").unwrap();
        assert_eq!(sha256_file(&path.to_string_lossy()).unwrap(), sha256_hex(b"abc"));
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn hex_and_sha256() {
        assert_eq!(hex(&[0x4c, 0x8b, 0xd1]), "4C 8B D1");
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
