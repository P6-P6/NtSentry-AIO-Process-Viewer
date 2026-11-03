//! Native Save As dialog. Call it from a helper thread so the dashboard keeps
//! repainting while the dialog is open.

use crate::winutil::{from_wide, wide};
use std::mem::size_of;
use std::path::PathBuf;
use windows_sys::Win32::UI::Controls::Dialogs::{
    GetSaveFileNameW, OFN_NOCHANGEDIR, OFN_OVERWRITEPROMPT, OFN_PATHMUSTEXIST, OPENFILENAMEW,
};

/// `filter` is a description and a pattern, e.g. ("CSV files", "*.csv").
/// Windows asks before replacing an existing file. `None` means cancelled.
pub fn save_file(title: &str, default_name: &str, filter: (&str, &str), extension: &str) -> Option<PathBuf> {
    let mut filename = vec![0u16; 4096];
    let name = wide(default_name);
    let n = (name.len() - 1).min(filename.len() - 1);
    filename[..n].copy_from_slice(&name[..n]);
    let filter: Vec<u16> = format!("{}\0{}\0All files\0*.*\0\0", filter.0, filter.1).encode_utf16().collect();
    let title = wide(title);
    let extension = wide(extension);
    let mut dialog: OPENFILENAMEW = unsafe { std::mem::zeroed() };
    dialog.lStructSize = size_of::<OPENFILENAMEW>() as u32;
    dialog.lpstrFilter = filter.as_ptr();
    dialog.lpstrFile = filename.as_mut_ptr();
    dialog.nMaxFile = filename.len() as u32;
    dialog.lpstrDefExt = extension.as_ptr();
    dialog.lpstrTitle = title.as_ptr();
    dialog.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
    (unsafe { GetSaveFileNameW(&mut dialog) } != 0).then(|| PathBuf::from(from_wide(&filename)))
}
