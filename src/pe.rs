//! Minimal, bounds-checked PE reader over a byte slice in *file* layout.
//!
//! Only what the integrity monitor needs: headers, sections, base relocations,
//! function-override fixups and named exports. Malformed input yields `Err`, never a panic.

pub const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const DIR_EXPORT: usize = 0;
const DIR_BASERELOC: usize = 5;
const DIR_LOAD_CONFIG: usize = 10;
/// IMAGE_LOAD_CONFIG_DIRECTORY64.DynamicValueRelocTableOffset / ...Section.
const LC64_DVRT_OFFSET: usize = 0xE0;
const LC64_DVRT_SECTION: usize = 0xE4;
/// IMAGE_DYNAMIC_RELOCATION_FUNCTION_OVERRIDE.
const DVRT_FUNCTION_OVERRIDE: u64 = 7;
/// IMAGE_FUNCTION_OVERRIDE_X64_REL32.
const OVERRIDE_X64_REL32: u16 = 1;

/// A rel32 displacement (at `site_rva`) that Windows may retarget at map time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OverrideSite {
    pub site_rva: u32,
    pub original_rva: u32,
    /// Alternative implementations declared by the file.
    pub targets: Vec<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Section {
    pub name: String,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub raw_offset: u32,
    pub raw_size: u32,
    pub characteristics: u32,
}

impl Section {
    pub fn is_executable(&self) -> bool {
        self.characteristics & IMAGE_SCN_MEM_EXECUTE != 0
    }

    /// Bytes that exist both on disk and in the mapped image.
    pub fn comparable_len(&self) -> u32 {
        self.virtual_size.min(self.raw_size)
    }
}

/// Identity fields that distinguish one build of an image from another.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ImageIdentity {
    pub machine: u16,
    pub time_date_stamp: u32,
    pub size_of_image: u32,
    pub checksum: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Relocation {
    pub rva: u32,
    /// 4 (HIGHLOW) or 8 (DIR64).
    pub width: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Export {
    pub name: String,
    pub rva: u32,
}

#[derive(Clone, Debug)]
pub struct PeImage<'a> {
    data: &'a [u8],
    /// True when `data` is a mapped image (offset == RVA) rather than a file.
    mapped: bool,
    pub identity: ImageIdentity,
    pub is_64: bool,
    pub image_base: u64,
    pub size_of_headers: u32,
    pub sections: Vec<Section>,
    directories: Vec<(u32, u32)>,
}

fn u16_at(data: &[u8], offset: usize) -> Result<u16, String> {
    data.get(offset..offset + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .ok_or_else(|| format!("truncated PE: u16 at 0x{offset:X}"))
}

fn u32_at(data: &[u8], offset: usize) -> Result<u32, String> {
    data.get(offset..offset + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        .ok_or_else(|| format!("truncated PE: u32 at 0x{offset:X}"))
}

fn u64_at(data: &[u8], offset: usize) -> Result<u64, String> {
    data.get(offset..offset + 8)
        .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
        .ok_or_else(|| format!("truncated PE: u64 at 0x{offset:X}"))
}

impl<'a> PeImage<'a> {
    /// Parses a PE file as stored on disk.
    pub fn parse(data: &'a [u8]) -> Result<Self, String> {
        Self::parse_layout(data, false)
    }

    /// Parses an image copied out of memory as the loader mapped it (offset == RVA).
    /// Headers are identical in both layouts; only section access differs.
    pub fn parse_mapped(data: &'a [u8]) -> Result<Self, String> {
        Self::parse_layout(data, true)
    }

    fn parse_layout(data: &'a [u8], mapped: bool) -> Result<Self, String> {
        if u16_at(data, 0)? != 0x5A4D {
            return Err("missing MZ signature".into());
        }
        let pe = u32_at(data, 0x3C)? as usize;
        if u32_at(data, pe)? != 0x0000_4550 {
            return Err("missing PE signature".into());
        }
        let file_header = pe + 4;
        let machine = u16_at(data, file_header)?;
        let section_count = u16_at(data, file_header + 2)? as usize;
        let time_date_stamp = u32_at(data, file_header + 4)?;
        let optional_size = u16_at(data, file_header + 16)? as usize;
        let opt = file_header + 20;
        let (is_64, image_base, dir_count_at, dirs_at) = match u16_at(data, opt)? {
            0x20B => (true, u64_at(data, opt + 24)?, opt + 108, opt + 112),
            0x10B => (false, u64::from(u32_at(data, opt + 28)?), opt + 92, opt + 96),
            other => return Err(format!("unknown optional header magic 0x{other:X}")),
        };
        let size_of_image = u32_at(data, opt + 56)?;
        let size_of_headers = u32_at(data, opt + 60)?;
        let checksum = u32_at(data, opt + 64)?;
        let dir_count = (u32_at(data, dir_count_at)? as usize).min(16);
        let mut directories = Vec::with_capacity(dir_count);
        for i in 0..dir_count {
            directories.push((u32_at(data, dirs_at + i * 8)?, u32_at(data, dirs_at + i * 8 + 4)?));
        }
        if section_count > 96 {
            return Err(format!("implausible section count {section_count}"));
        }
        let table = opt + optional_size;
        let mut sections = Vec::with_capacity(section_count);
        for i in 0..section_count {
            let s = table + i * 40;
            let raw_name = data.get(s..s + 8).ok_or("truncated section table")?;
            let end = raw_name.iter().position(|b| *b == 0).unwrap_or(8);
            sections.push(Section {
                name: String::from_utf8_lossy(&raw_name[..end]).into_owned(),
                virtual_size: u32_at(data, s + 8)?,
                virtual_address: u32_at(data, s + 12)?,
                raw_size: u32_at(data, s + 16)?,
                raw_offset: u32_at(data, s + 20)?,
                characteristics: u32_at(data, s + 36)?,
            });
        }
        Ok(PeImage {
            data,
            mapped,
            identity: ImageIdentity { machine, time_date_stamp, size_of_image, checksum },
            is_64,
            image_base,
            size_of_headers,
            sections,
            directories,
        })
    }

    pub fn executable_sections(&self) -> impl Iterator<Item = &Section> {
        self.sections.iter().filter(|s| s.is_executable())
    }

    /// File offset of an RVA, if it lies in headers or a section's raw data.
    pub fn rva_to_offset(&self, rva: u32) -> Option<usize> {
        if self.mapped {
            return ((rva as usize) < self.data.len()).then_some(rva as usize);
        }
        if rva < self.size_of_headers {
            return Some(rva as usize);
        }
        self.sections.iter().find_map(|s| {
            let delta = rva.checked_sub(s.virtual_address)?;
            (delta < s.raw_size).then(|| s.raw_offset as usize + delta as usize)
        })
    }

    pub fn read_rva(&self, rva: u32, len: usize) -> Option<&'a [u8]> {
        let start = self.rva_to_offset(rva)?;
        self.data.get(start..start.checked_add(len)?)
    }

    /// A section's comparable range: raw file bytes, or mapped bytes at its RVA.
    pub fn section_bytes(&self, section: &Section) -> Result<&'a [u8], String> {
        let start = if self.mapped { section.virtual_address } else { section.raw_offset } as usize;
        self.data
            .get(start..start + section.comparable_len() as usize)
            .ok_or_else(|| format!("section {} extends past end of file", section.name))
    }

    fn directory(&self, index: usize) -> Option<(u32, u32)> {
        self.directories.get(index).copied().filter(|(rva, size)| *rva != 0 && *size != 0)
    }

    /// Base relocation sites. Returns (sites, count of entry types not understood).
    pub fn relocations(&self) -> Result<(Vec<Relocation>, usize), String> {
        let Some((dir_rva, dir_size)) = self.directory(DIR_BASERELOC) else {
            return Ok((Vec::new(), 0));
        };
        let table = self.read_rva(dir_rva, dir_size as usize).ok_or("relocation directory outside file")?;
        let mut sites = Vec::new();
        let mut unknown = 0;
        relocation_blocks(table, |rva, kind| match kind {
            0 => {}
            3 => sites.push(Relocation { rva, width: 4 }),
            10 => sites.push(Relocation { rva, width: 8 }),
            _ => unknown += 1,
        })?;
        sites.sort_by_key(|r| r.rva);
        Ok((sites, unknown))
    }

    /// Function-override sites from the load config's dynamic value relocation table:
    /// rel32 displacements that Windows may legitimately retarget when it maps the
    /// image. Returns (sites, count of DVRT entries or fixup types not understood).
    pub fn function_overrides(&self) -> Result<(Vec<OverrideSite>, usize), String> {
        let none = Ok((Vec::new(), 0));
        let Some((lc_rva, _)) = self.directory(DIR_LOAD_CONFIG) else { return none };
        if !self.is_64 {
            return none;
        }
        let lc_size = self.read_rva(lc_rva, 4).map(|b| u32_at(b, 0)).ok_or("load config outside file")?? as usize;
        if lc_size < LC64_DVRT_SECTION + 2 {
            return none;
        }
        let lc = self.read_rva(lc_rva, LC64_DVRT_SECTION + 2).ok_or("load config outside file")?;
        let offset = u32_at(lc, LC64_DVRT_OFFSET)?;
        let section = u16_at(lc, LC64_DVRT_SECTION)? as usize;
        if section == 0 {
            return none;
        }
        let sec = self.sections.get(section - 1).ok_or("DVRT section index out of range")?;
        let table_rva = sec.virtual_address.checked_add(offset).ok_or("DVRT offset overflows")?;
        let header = self.read_rva(table_rva, 8).ok_or("DVRT header outside image")?;
        let version = u32_at(header, 0)?;
        let size = u32_at(header, 4)? as usize;
        let table = self.read_rva(table_rva + 8, size).ok_or("DVRT outside image")?;
        let mut sites = Vec::new();
        let mut unsupported = 0;
        let mut at = 0usize;
        while at < table.len() {
            let (symbol, body_at, body_len) = match version {
                1 => (u64_at(table, at)?, at + 12, u32_at(table, at + 8)? as usize),
                2 => {
                    let header_size = u32_at(table, at)? as usize;
                    if header_size < 24 {
                        return Err(format!("malformed DVRT v2 header at +0x{at:X}"));
                    }
                    (u64_at(table, at + 8)?, at + header_size, u32_at(table, at + 4)? as usize)
                }
                v => return Err(format!("unsupported DVRT version {v}")),
            };
            let body = table.get(body_at..body_at + body_len).ok_or("DVRT entry exceeds table")?;
            if symbol == DVRT_FUNCTION_OVERRIDE {
                parse_function_override(body, &mut sites, &mut unsupported)?;
            } else {
                unsupported += 1;
            }
            at = body_at + body_len;
        }
        sites.sort_by_key(|s| s.site_rva);
        Ok((sites, unsupported))
    }

    /// Named, non-forwarded exports sorted by RVA.
    pub fn exports(&self) -> Result<Vec<Export>, String> {
        let Some((dir_rva, dir_size)) = self.directory(DIR_EXPORT) else {
            return Ok(Vec::new());
        };
        let dir = self.read_rva(dir_rva, 40).ok_or("export directory outside file")?;
        let function_count = u32_at(dir, 20)?;
        let name_count = u32_at(dir, 24)? as usize;
        let functions = u32_at(dir, 28)?;
        let names = u32_at(dir, 32)?;
        let ordinals = u32_at(dir, 36)?;
        if name_count > 100_000 {
            return Err("implausible export name count".into());
        }
        let name_table = self.read_rva(names, name_count * 4).ok_or("export name table outside file")?;
        let ordinal_table = self.read_rva(ordinals, name_count * 2).ok_or("export ordinal table outside file")?;
        let mut exports = Vec::with_capacity(name_count);
        for i in 0..name_count {
            let ordinal = u32::from(u16_at(ordinal_table, i * 2)?);
            if ordinal >= function_count {
                continue;
            }
            let Some(rva) = self.read_rva(functions + ordinal * 4, 4).map(|b| u32_at(b, 0).unwrap()) else {
                continue;
            };
            // Forwarders point back into the export directory as strings.
            if rva >= dir_rva && rva < dir_rva + dir_size {
                continue;
            }
            let name_rva = u32_at(name_table, i * 4)?;
            let Some(start) = self.rva_to_offset(name_rva) else { continue };
            let tail = &self.data[start.min(self.data.len())..];
            let end = tail.iter().take(512).position(|b| *b == 0).unwrap_or(0);
            exports.push(Export { name: String::from_utf8_lossy(&tail[..end]).into_owned(), rva });
        }
        exports.sort_by_key(|e| e.rva);
        Ok(exports)
    }
}

/// Walks base-relocation-format blocks, calling `f(rva, type)` for every entry.
fn relocation_blocks(table: &[u8], mut f: impl FnMut(u32, u16)) -> Result<(), String> {
    let mut at = 0usize;
    while at + 8 <= table.len() {
        let page = u32_at(table, at)?;
        let block = u32_at(table, at + 4)? as usize;
        if block < 8 || at + block > table.len() {
            return Err(format!("malformed relocation block at +0x{at:X}"));
        }
        for entry in table[at + 8..at + block].chunks_exact(2) {
            let entry = u16::from_le_bytes([entry[0], entry[1]]);
            f(page.wrapping_add(u32::from(entry & 0x0FFF)), entry >> 12);
        }
        at += block;
    }
    Ok(())
}

/// IMAGE_FUNCTION_OVERRIDE_HEADER followed by IMAGE_FUNCTION_OVERRIDE_DYNAMIC_RELOCATION
/// records: {OriginalRva, BDDOffset, RvaSize, BaseRelocSize}, the alternative target
/// RVAs, then base-relocation-format blocks naming the sites to patch.
fn parse_function_override(body: &[u8], sites: &mut Vec<OverrideSite>, unsupported: &mut usize) -> Result<(), String> {
    let size = u32_at(body, 0)? as usize;
    let list = body.get(4..4 + size).ok_or("function override list exceeds entry")?;
    let mut q = 0usize;
    while q + 16 <= list.len() {
        let original_rva = u32_at(list, q)?;
        let rva_size = u32_at(list, q + 8)? as usize;
        let reloc_size = u32_at(list, q + 12)? as usize;
        q += 16;
        let targets = list.get(q..q + rva_size).ok_or("override target list exceeds entry")?;
        let targets: Vec<u32> =
            targets.chunks_exact(4).map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]])).collect();
        q += rva_size;
        let blocks = list.get(q..q + reloc_size).ok_or("override fixups exceed entry")?;
        relocation_blocks(blocks, |rva, kind| match kind {
            0 => {}
            OVERRIDE_X64_REL32 => {
                sites.push(OverrideSite { site_rva: rva, original_rva, targets: targets.clone() })
            }
            _ => *unsupported += 1,
        })?;
        q += reloc_size;
    }
    Ok(())
}

/// Undo the loader's base relocation on a copy of mapped section bytes, so they can
/// be compared with the file and with baselines captured at a different load address.
/// Sites that straddle the section boundary are left alone and counted.
pub fn unrelocate(bytes: &mut [u8], section_rva: u32, relocations: &[Relocation], delta: u64) -> usize {
    let mut straddling = 0;
    if delta == 0 {
        return 0;
    }
    let end = u64::from(section_rva) + bytes.len() as u64;
    let first = relocations.partition_point(|r| r.rva < section_rva);
    for r in &relocations[first..] {
        if u64::from(r.rva) >= end {
            break;
        }
        let at = (r.rva - section_rva) as usize;
        let width = r.width as usize;
        let Some(site) = bytes.get_mut(at..at + width) else {
            straddling += 1;
            continue;
        };
        if width == 8 {
            let v = u64::from_le_bytes(site[..8].try_into().unwrap()).wrapping_sub(delta);
            site.copy_from_slice(&v.to_le_bytes());
        } else {
            let v = u32::from_le_bytes(site[..4].try_into().unwrap()).wrapping_sub(delta as u32);
            site.copy_from_slice(&v.to_le_bytes());
        }
    }
    straddling
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A tiny PE32+ image: one executable `.text` section with a DIR64 relocation
    /// site at RVA 0x1010, a `jmp rel32` override thunk at 0x1020, one export `Fn`
    /// at 0x1000, and a `.rdata` holding the export directory, relocation block,
    /// load config and a function-override dynamic relocation table.
    pub(crate) fn sample_pe() -> Vec<u8> {
        let mut f = vec![0u8; 0x800];
        f[0..2].copy_from_slice(b"MZ");
        f[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        f[0x80..0x84].copy_from_slice(b"PE\0\0");
        let fh = 0x84;
        f[fh..fh + 2].copy_from_slice(&0x8664u16.to_le_bytes());
        f[fh + 2..fh + 4].copy_from_slice(&2u16.to_le_bytes());
        f[fh + 4..fh + 8].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        f[fh + 16..fh + 18].copy_from_slice(&240u16.to_le_bytes());
        let opt = fh + 20;
        f[opt..opt + 2].copy_from_slice(&0x20Bu16.to_le_bytes());
        f[opt + 24..opt + 32].copy_from_slice(&0x1_8000_0000u64.to_le_bytes());
        f[opt + 56..opt + 60].copy_from_slice(&0x3000u32.to_le_bytes());
        f[opt + 60..opt + 64].copy_from_slice(&0x200u32.to_le_bytes());
        f[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes());
        let dirs = opt + 112;
        // Export directory at 0x2000 (file 0x400), reloc block at 0x2100 (file 0x500).
        f[dirs..dirs + 4].copy_from_slice(&0x2000u32.to_le_bytes());
        f[dirs + 4..dirs + 8].copy_from_slice(&0x60u32.to_le_bytes());
        f[dirs + 40..dirs + 44].copy_from_slice(&0x2100u32.to_le_bytes());
        f[dirs + 44..dirs + 48].copy_from_slice(&12u32.to_le_bytes());
        // Load config at 0x2200 (file 0x600).
        f[dirs + 80..dirs + 84].copy_from_slice(&0x2200u32.to_le_bytes());
        f[dirs + 84..dirs + 88].copy_from_slice(&0x100u32.to_le_bytes());
        let mut section = |i: usize, name: &[u8], va: u32, vsize: u32, raw: u32, rsize: u32, ch: u32| {
            let s = opt + 240 + i * 40;
            f[s..s + name.len()].copy_from_slice(name);
            f[s + 8..s + 12].copy_from_slice(&vsize.to_le_bytes());
            f[s + 12..s + 16].copy_from_slice(&va.to_le_bytes());
            f[s + 16..s + 20].copy_from_slice(&rsize.to_le_bytes());
            f[s + 20..s + 24].copy_from_slice(&raw.to_le_bytes());
            f[s + 36..s + 40].copy_from_slice(&ch.to_le_bytes());
        };
        section(0, b".text", 0x1000, 0x40, 0x200, 0x200, 0x6000_0020);
        section(1, b".rdata", 0x2000, 0x400, 0x400, 0x400, 0x4000_0040);
        // .text: a prologue, then an absolute pointer at +0x10 to 0x1_8000_1000.
        f[0x200..0x204].copy_from_slice(&[0x4C, 0x8B, 0xD1, 0xB8]);
        f[0x210..0x218].copy_from_slice(&0x1_8000_1000u64.to_le_bytes());
        // Override thunk at 0x1020: jmp Fn (0x1000).
        f[0x220] = 0xE9;
        f[0x221..0x225].copy_from_slice(&(0x1000i32 - 0x1025).to_le_bytes());
        // Export directory: 1 function, 1 name.
        let e = 0x400;
        f[e + 20..e + 24].copy_from_slice(&1u32.to_le_bytes());
        f[e + 24..e + 28].copy_from_slice(&1u32.to_le_bytes());
        f[e + 28..e + 32].copy_from_slice(&0x2040u32.to_le_bytes());
        f[e + 32..e + 36].copy_from_slice(&0x2044u32.to_le_bytes());
        f[e + 36..e + 40].copy_from_slice(&0x2048u32.to_le_bytes());
        f[0x440..0x444].copy_from_slice(&0x1000u32.to_le_bytes());
        f[0x444..0x448].copy_from_slice(&0x2050u32.to_le_bytes());
        f[0x448..0x44A].copy_from_slice(&0u16.to_le_bytes());
        f[0x450..0x453].copy_from_slice(b"Fn\0");
        // Relocation block: page 0x1000, one DIR64 at +0x10, one ABSOLUTE pad.
        let r = 0x500;
        f[r..r + 4].copy_from_slice(&0x1000u32.to_le_bytes());
        f[r + 4..r + 8].copy_from_slice(&12u32.to_le_bytes());
        f[r + 8..r + 10].copy_from_slice(&((10u16 << 12) | 0x010).to_le_bytes());
        // Load config: size, DVRT at section 2 (.rdata) offset 0x300 (RVA 0x2300, file 0x700).
        f[0x600..0x604].copy_from_slice(&0x100u32.to_le_bytes());
        f[0x6E0..0x6E4].copy_from_slice(&0x300u32.to_le_bytes());
        f[0x6E4..0x6E6].copy_from_slice(&2u16.to_le_bytes());
        // DVRT v1: one FUNCTION_OVERRIDE entry with one record: original 0x1000,
        // one alternative 0x1030, one REL32 site at 0x1021.
        let words: [u32; 14] = [
            1, 48, // version, size
            7, 0, 36, // symbol (u64), fixup size
            32, // FuncOverrideSize
            0x1000, 0, 4, 12, // OriginalRva, BDDOffset, RvaSize, BaseRelocSize
            0x1030, // alternative target
            0x1000, 12, (1 << 12) | 0x021, // block: page, size, one u16 entry + u16 pad
        ];
        for (i, w) in words.iter().enumerate() {
            f[0x700 + i * 4..0x704 + i * 4].copy_from_slice(&w.to_le_bytes());
        }
        f
    }

    #[test]
    fn parses_headers_sections_and_identity() {
        let bytes = sample_pe();
        let pe = PeImage::parse(&bytes).unwrap();
        assert!(pe.is_64);
        assert_eq!(pe.image_base, 0x1_8000_0000);
        assert_eq!(pe.identity.time_date_stamp, 0x1234_5678);
        assert_eq!(pe.sections.len(), 2);
        let text: Vec<_> = pe.executable_sections().collect();
        assert_eq!(text.len(), 1);
        assert_eq!(text[0].name, ".text");
        assert_eq!(text[0].comparable_len(), 0x40);
        assert_eq!(pe.rva_to_offset(0x1010), Some(0x210));
        assert_eq!(pe.rva_to_offset(0x5000), None);
    }

    #[test]
    fn reads_relocations_and_exports() {
        let bytes = sample_pe();
        let pe = PeImage::parse(&bytes).unwrap();
        let (relocs, unknown) = pe.relocations().unwrap();
        assert_eq!(relocs, vec![Relocation { rva: 0x1010, width: 8 }]);
        assert_eq!(unknown, 0);
        assert_eq!(pe.exports().unwrap(), vec![Export { name: "Fn".into(), rva: 0x1000 }]);
    }

    #[test]
    fn reads_function_override_sites() {
        let bytes = sample_pe();
        let pe = PeImage::parse(&bytes).unwrap();
        let (sites, unsupported) = pe.function_overrides().unwrap();
        assert_eq!(unsupported, 0);
        assert_eq!(sites, vec![OverrideSite { site_rva: 0x1021, original_rva: 0x1000, targets: vec![0x1030] }]);
    }

    #[test]
    fn unrelocate_restores_file_bytes() {
        let bytes = sample_pe();
        let pe = PeImage::parse(&bytes).unwrap();
        let text = pe.sections[0].clone();
        let disk = pe.section_bytes(&text).unwrap();
        let (relocs, _) = pe.relocations().unwrap();
        // Simulate the loader placing the image 0x7FF0_0000_0000 higher.
        let delta = 0x7FF0_0000_0000u64;
        let mut mapped = disk.to_vec();
        let v = u64::from_le_bytes(mapped[0x10..0x18].try_into().unwrap()) + delta;
        mapped[0x10..0x18].copy_from_slice(&v.to_le_bytes());
        assert_ne!(mapped, disk);
        assert_eq!(unrelocate(&mut mapped, text.virtual_address, &relocs, delta), 0);
        assert_eq!(mapped, disk);
    }

    #[test]
    fn mapped_layout_reads_sections_at_their_rva() {
        let file = sample_pe();
        let pe = PeImage::parse(&file).unwrap();
        let mut image = vec![0u8; pe.identity.size_of_image as usize];
        image[..0x200].copy_from_slice(&file[..0x200]);
        for s in &pe.sections {
            let raw = &file[s.raw_offset as usize..(s.raw_offset + s.raw_size) as usize];
            let n = raw.len().min(s.virtual_size as usize);
            image[s.virtual_address as usize..][..n].copy_from_slice(&raw[..n]);
        }
        let mapped = PeImage::parse_mapped(&image).unwrap();
        assert_eq!(mapped.identity, pe.identity);
        let text = &mapped.sections[0];
        assert_eq!(mapped.section_bytes(text).unwrap(), pe.section_bytes(&pe.sections[0]).unwrap());
        assert_eq!(mapped.relocations().unwrap(), pe.relocations().unwrap());
        assert_eq!(mapped.exports().unwrap(), pe.exports().unwrap());
        assert_eq!(mapped.function_overrides().unwrap(), pe.function_overrides().unwrap());
    }

    #[test]
    fn malformed_input_is_an_error_not_a_panic() {
        assert!(PeImage::parse(&[]).is_err());
        assert!(PeImage::parse(b"MZ").is_err());
        let mut bytes = sample_pe();
        bytes.truncate(0x100);
        assert!(PeImage::parse(&bytes).is_err());
        let mut bytes = sample_pe();
        bytes[0x504..0x508].copy_from_slice(&4u32.to_le_bytes());
        assert!(PeImage::parse(&bytes).unwrap().relocations().is_err());
    }
}
