//! Small icons for the files behind inventory rows.
//!
//! An icon is read from the file's resources with `ExtractIconExW`, which maps
//! the file as data, so nothing from a possibly hostile program runs. Files with
//! no icon of their own get the generic icon for their type; that lookup names
//! only the extension and never opens the file.

use crate::winutil::wide;
use std::mem::{size_of, zeroed};
use std::ptr::null_mut;
use windows_sys::Win32::Graphics::Gdi::{
    BITMAP, BITMAPINFO, BITMAPINFOHEADER, DIB_RGB_COLORS, DeleteObject, GetDC, GetDIBits, GetObjectW, HBITMAP, HDC,
    ReleaseDC,
};
use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_NORMAL;
use windows_sys::Win32::UI::Shell::{
    ExtractIconExW, SHFILEINFOW, SHGFI_ICON, SHGFI_SMALLICON, SHGFI_USEFILEATTRIBUTES, SHGetFileInfoW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{DestroyIcon, GetIconInfo, HICON, ICONINFO};

/// Decoded icon pixels: `[width, height]` and straight-alpha RGBA, top row first.
#[derive(Clone, Debug)]
pub struct IconImage {
    pub size: [usize; 2],
    pub rgba: Vec<u8>,
}

const MAX_ICON_SIDE: i32 = 256;
const MAX_EXTENSION_LEN: usize = 16;

struct OwnedIcon(HICON);

impl Drop for OwnedIcon {
    fn drop(&mut self) {
        unsafe { DestroyIcon(self.0) };
    }
}

struct OwnedBitmap(HBITMAP);

impl Drop for OwnedBitmap {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { DeleteObject(self.0) };
        }
    }
}

struct ScreenDc(HDC);

impl Drop for ScreenDc {
    fn drop(&mut self) {
        unsafe { ReleaseDC(null_mut(), self.0) };
    }
}

/// The small icon for `file`, or the generic icon for its type when it has none
/// of its own or does not exist. With no `file`, the generic program icon.
pub fn small_icon(file: Option<&str>) -> Option<IconImage> {
    file.filter(|f| std::path::Path::new(f).is_file())
        .and_then(embedded_icon)
        .or_else(|| generic_icon(file.and_then(extension).unwrap_or("exe")))
}

fn embedded_icon(file: &str) -> Option<IconImage> {
    let path = wide(file);
    let mut icon: HICON = null_mut();
    let count = unsafe { ExtractIconExW(path.as_ptr(), 0, null_mut(), &mut icon, 1) };
    // A failed call returns u32::MAX and leaves the handle null.
    if count == 0 || icon.is_null() {
        return None;
    }
    icon_image(&OwnedIcon(icon))
}

fn generic_icon(extension: &str) -> Option<IconImage> {
    let name = wide(&format!("x.{extension}"));
    let mut info: SHFILEINFOW = unsafe { zeroed() };
    let flags = SHGFI_ICON | SHGFI_SMALLICON | SHGFI_USEFILEATTRIBUTES;
    let found = unsafe { SHGetFileInfoW(name.as_ptr(), FILE_ATTRIBUTE_NORMAL, &mut info, size_of::<SHFILEINFOW>() as u32, flags) };
    if found == 0 || info.hIcon.is_null() {
        return None;
    }
    icon_image(&OwnedIcon(info.hIcon))
}

/// A file's extension if it is plain enough to pass to the shell.
fn extension(file: &str) -> Option<&str> {
    let name = file.rsplit('\\').next()?;
    let (_, extension) = name.rsplit_once('.')?;
    let plain = !extension.is_empty() && extension.len() <= MAX_EXTENSION_LEN && extension.bytes().all(|b| b.is_ascii_alphanumeric());
    plain.then_some(extension)
}

fn icon_image(icon: &OwnedIcon) -> Option<IconImage> {
    let mut info: ICONINFO = unsafe { zeroed() };
    if unsafe { GetIconInfo(icon.0, &mut info) } == 0 {
        return None;
    }
    let (color, mask) = (OwnedBitmap(info.hbmColor), OwnedBitmap(info.hbmMask));
    // Monochrome icons have no color bitmap; the row falls back to the generic icon.
    if color.0.is_null() {
        return None;
    }
    let mut bitmap: BITMAP = unsafe { zeroed() };
    let written = unsafe { GetObjectW(color.0, size_of::<BITMAP>() as i32, (&raw mut bitmap).cast()) };
    let (width, height) = (bitmap.bmWidth, bitmap.bmHeight);
    if written == 0 || !(1..=MAX_ICON_SIDE).contains(&width) || !(1..=MAX_ICON_SIDE).contains(&height) {
        return None;
    }
    let dc = ScreenDc(unsafe { GetDC(null_mut()) });
    if dc.0.is_null() {
        return None;
    }
    let pixels = read_bgra(dc.0, color.0, width, height)?;
    // Older icons leave alpha empty and describe transparency in the mask.
    let mask_pixels = if pixels.chunks_exact(4).any(|p| p[3] != 0) { None } else { Some(read_bgra(dc.0, mask.0, width, height)?) };
    Some(IconImage { size: [width as usize, height as usize], rgba: to_rgba(pixels, mask_pixels.as_deref()) })
}

fn read_bgra(dc: HDC, bitmap: HBITMAP, width: i32, height: i32) -> Option<Vec<u8>> {
    // Zeroed biCompression is BI_RGB.
    let mut request: BITMAPINFO = unsafe { zeroed() };
    request.bmiHeader.biSize = size_of::<BITMAPINFOHEADER>() as u32;
    request.bmiHeader.biWidth = width;
    request.bmiHeader.biHeight = -height; // Negative asks for the top row first.
    request.bmiHeader.biPlanes = 1;
    request.bmiHeader.biBitCount = 32;
    let mut pixels = vec![0u8; width as usize * height as usize * 4];
    let lines = unsafe { GetDIBits(dc, bitmap, 0, height as u32, pixels.as_mut_ptr().cast(), &mut request, DIB_RGB_COLORS) };
    (lines == height).then_some(pixels)
}

/// BGRA to RGBA. With a `mask`, a set mask pixel is transparent and the rest opaque.
fn to_rgba(mut bgra: Vec<u8>, mask: Option<&[u8]>) -> Vec<u8> {
    for (index, pixel) in bgra.chunks_exact_mut(4).enumerate() {
        pixel.swap(0, 2);
        if let Some(mask) = mask {
            pixel[3] = if mask[index * 4] == 0 { 255 } else { 0 };
        }
    }
    bgra
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_drawable(image: &IconImage) {
        let [width, height] = image.size;
        assert!(width > 0 && height > 0, "{:?}", image.size);
        assert_eq!(image.rgba.len(), width * height * 4);
        assert!(image.rgba.chunks_exact(4).any(|p| p[3] != 0), "the icon has visible pixels");
    }

    #[test]
    fn swaps_channels_and_keeps_alpha() {
        assert_eq!(to_rgba(vec![1, 2, 3, 200], None), [3, 2, 1, 200]);
    }

    #[test]
    fn mask_supplies_alpha_for_older_icons() {
        let mask = [0, 0, 0, 0, 255, 255, 255, 0];
        assert_eq!(to_rgba(vec![1, 2, 3, 0, 4, 5, 6, 0], Some(&mask)), [3, 2, 1, 255, 6, 5, 4, 0]);
    }

    #[test]
    fn only_plain_extensions_reach_the_shell() {
        assert_eq!(extension(r"C:\App\run.ps1"), Some("ps1"));
        assert_eq!(extension(r"C:\My.App\run"), None);
        assert_eq!(extension(r"C:\App\run."), None);
        assert_eq!(extension(r"C:\App\run.a b"), None);
    }

    #[test]
    fn reads_the_icon_of_a_real_program() {
        let explorer = format!(r"{}\explorer.exe", crate::winutil::windows_directory().unwrap());
        assert_drawable(&embedded_icon(&explorer).expect("explorer.exe has an icon"));
    }

    #[test]
    fn missing_files_and_unknown_targets_get_a_generic_icon() {
        assert_drawable(&small_icon(Some(r"C:\no\such\folder\program.exe")).expect("generic program icon"));
        assert_drawable(&small_icon(None).expect("generic program icon"));
    }
}
