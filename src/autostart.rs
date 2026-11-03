//! Opt-in "run at Windows sign-in" for the current user only, via
//! `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`. Nothing is registered
//! unless the user ticks the setting; unticking removes the value.

use crate::winutil::{from_wide, wide};
use std::path::Path;
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, KEY_QUERY_VALUE, KEY_SET_VALUE, REG_SZ, RegCloseKey, RegDeleteValueW, RegOpenKeyExW,
    RegQueryValueExW, RegSetValueExW,
};

const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
pub const VALUE_NAME: &str = "NtSentry";
/// Command-line flag used by the sign-in entry.
pub const MINIMIZED_FLAG: &str = "--minimized";

pub fn command_for(exe: &Path) -> String {
    format!("\"{}\" {MINIMIZED_FLAG}", exe.display())
}

struct Key(HKEY);

impl Drop for Key {
    fn drop(&mut self) {
        unsafe { RegCloseKey(self.0) };
    }
}

fn open(access: u32) -> Result<Key, String> {
    let path = wide(RUN_KEY);
    let mut key: HKEY = null_mut();
    let status = unsafe { RegOpenKeyExW(HKEY_CURRENT_USER, path.as_ptr(), 0, access, &mut key) };
    if status != ERROR_SUCCESS {
        return Err(format!("Cannot open HKCU\\{RUN_KEY} (error {status})"));
    }
    Ok(Key(key))
}

/// The registered command line, if the dashboard is set to run at sign-in.
pub fn registered_command() -> Result<Option<String>, String> {
    let key = open(KEY_QUERY_VALUE)?;
    let name = wide(VALUE_NAME);
    let mut buffer = vec![0u16; 2048];
    let mut bytes = (buffer.len() * 2) as u32;
    let mut kind = 0u32;
    let status = unsafe {
        RegQueryValueExW(key.0, name.as_ptr(), null(), &mut kind, buffer.as_mut_ptr() as *mut u8, &mut bytes)
    };
    match status {
        ERROR_SUCCESS => Ok(Some(from_wide(&buffer[..(bytes as usize / 2).min(buffer.len())]))),
        ERROR_FILE_NOT_FOUND => Ok(None),
        other => Err(format!("Cannot read the {VALUE_NAME} sign-in entry (error {other})")),
    }
}

pub fn enable(exe: &Path) -> Result<(), String> {
    let key = open(KEY_SET_VALUE)?;
    let name = wide(VALUE_NAME);
    let data = wide(&command_for(exe));
    let status = unsafe {
        RegSetValueExW(key.0, name.as_ptr(), 0, REG_SZ, data.as_ptr() as *const u8, (data.len() * 2) as u32)
    };
    if status == ERROR_SUCCESS { Ok(()) } else { Err(format!("Cannot create the sign-in entry (error {status})")) }
}

pub fn disable() -> Result<(), String> {
    let key = open(KEY_SET_VALUE)?;
    let name = wide(VALUE_NAME);
    match unsafe { RegDeleteValueW(key.0, name.as_ptr()) } {
        ERROR_SUCCESS | ERROR_FILE_NOT_FOUND => Ok(()),
        other => Err(format!("Cannot remove the sign-in entry (error {other})")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_quotes_the_path() {
        assert_eq!(
            command_for(Path::new(r"C:\My Tools\ntsentry.exe")),
            r#""C:\My Tools\ntsentry.exe" --minimized"#
        );
    }
}
