//! PE32+ reader: headers, sections, imports, exports, base relocations.

use a64x_core::Result;

use crate::bad;

/// x86-64 machine id.
pub const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
/// ARM64 machine id (what A64X executes).
pub const IMAGE_FILE_MACHINE_ARM64: u16 = 0xAA64;
/// ARM64EC hybrid machine id (ABI compatible with ARM64 at the API level).
pub const IMAGE_FILE_MACHINE_ARM64EC: u16 = 0xA641;

const DOS_MAGIC: u16 = 0x5A4D; // "MZ"
const PE_MAGIC: u32 = 0x0000_4550; // "PE\0\0"
const OPT_MAGIC_PE32P: u16 = 0x20B;
const PE_HEADER_OFF: usize = 0x80; // conventional e_lfanew we also write

/// Data-directory indices.
pub mod dir {
    /// Export table.
    pub const EXPORT: usize = 0;
    /// Import table.
    pub const IMPORT: usize = 1;
    /// Resource table.
    pub const RESOURCE: usize = 2;
    /// Exception (.pdata).
    pub const EXCEPTION: usize = 3;
    /// Security / certificates.
    pub const SECURITY: usize = 4;
    /// Base relocation table.
    pub const BASERELOC: usize = 5;
    /// Debug.
    pub const DEBUG: usize = 6;
    /// TLS.
    pub const TLS: usize = 9;
    /// Import Address Table.
    pub const IAT: usize = 12;
    /// Number of directory slots we track.
    pub const COUNT: usize = 16;
}

/// Re-export alias for docs.
pub use dir::COUNT as DIRECTORY_COUNT;
/// An index into the data-directory array.
pub type DataDirIdx = usize;

/// One section of the image.
#[derive(Debug, Clone)]
pub struct Section {
    /// Human name (NUL-trimmed).
    pub name: String,
    /// RVA where the loader maps it.
    pub vaddr: u32,
    /// In-memory size (may exceed raw_size — tail is zero-filled).
    pub vsize: u32,
    /// File offset of raw contents (0 for pure-bss sections).
    pub raw_ptr: u32,
    /// Raw byte count in the file.
    pub raw_size: u32,
    /// Characteristics flags (0x20000000 exec, 0x40000000 read, 0x80000000 write).
    pub flags: u32,
}

impl Section {
    /// True for executable sections (`.text`).
    pub fn is_code(&self) -> bool {
        self.flags & 0x0000_0020 != 0 || self.flags & 0x2000_0000 != 0
    }
    /// True for sections containing initialized data.
    pub fn is_initialized_data(&self) -> bool {
        self.flags & 0x0000_0040 != 0
    }
}

/// Base-relocation block (one 4KiB page).
#[derive(Debug)]
pub struct RelocBlock {
    /// Page RVA.
    pub page_rva: u32,
    /// `(type, offset)` entries (type 10 = DIR64 on ARM64).
    pub entries: Vec<(u16, u16)>,
}

/// One imported symbol.
#[derive(Debug, Clone)]
pub struct Import {
    /// DLL name (e.g. "KERNEL32.dll").
    pub dll: String,
    /// What is imported.
    pub symbol: ImportSymbol,
    /// RVA of the IAT slot the loader patches.
    pub iat_rva: u32,
}

/// Imported symbol flavor.
#[derive(Debug, Clone)]
pub enum ImportSymbol {
    /// By name (hint/name table lookup).
    Name(String),
    /// By ordinal.
    Ordinal(u16),
}

impl std::fmt::Display for ImportSymbol {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ImportSymbol::Name(n) => write!(f, "{n}"),
            ImportSymbol::Ordinal(o) => write!(f, "#{o}"),
        }
    }
}

/// One exported symbol.
#[derive(Debug, Clone)]
pub struct Export {
    /// Exported name, if named.
    pub name: Option<String>,
    /// Export ordinal (including the base).
    pub ordinal: u32,
    /// RVA of the target.
    pub rva: u32,
    /// True when this entry is a forwarder (rva points into the export dir).
    pub is_forwarder: bool,
}

/// Parsed image view over the original bytes.
pub struct PeImage<'a> {
    bytes: &'a [u8],
    /// Machine id (COFF header).
    pub machine: u16,
    /// Number of sections.
    pub n_sections: u16,
    /// COFF characteristics.
    pub characteristics: u16,
    /// AddressOfEntryPoint (RVA).
    pub entry_point: u32,
    /// Preferred load base.
    pub image_base: u64,
    /// Total mapped size.
    pub size_of_image: u32,
    /// Size of all headers (DOS+PE+section headers), aligned.
    pub size_of_headers: u32,
    /// Subsystem id (3 = console).
    pub subsystem: u16,
    /// DLL characteristics.
    pub dll_characteristics: u16,
    /// Section table.
    pub sections: Vec<Section>,
    /// Data directories `(rva, size)`.
    pub directories: [(u32, u32); dir::COUNT],
    /// Offset of the section table within the file.
    sec_table_off: usize,
}

impl<'a> PeImage<'a> {
    /// Parse an image, validating all structural bounds leniently (list-y
    /// data like imports is read on demand, so deeply corrupt images that
    /// still parse are fine to *inspect*).
    pub fn parse(bytes: &'a [u8]) -> Result<PeImage<'a>> {
        if bytes.len() < 0x40 {
            return Err(bad("file too small for DOS header"));
        }
        if rd16(bytes, 0)? != DOS_MAGIC {
            return Err(bad("missing MZ magic"));
        }
        let lfanew = rd32(bytes, 0x3C)? as usize;
        if bytes.len() < lfanew + 24 || rd32(bytes, lfanew)? != PE_MAGIC {
            return Err(bad("missing PE\\0\\0 signature"));
        }
        let coff = lfanew + 4;
        let machine = rd16(bytes, coff)?;
        let n_sections = rd16(bytes, coff + 2)?;
        let opt_size = rd16(bytes, coff + 16)? as usize;
        let characteristics = rd16(bytes, coff + 18)?;
        let opt = coff + 20;
        if bytes.len() < opt + opt_size {
            return Err(bad("truncated optional header"));
        }
        if rd16(bytes, opt)? != OPT_MAGIC_PE32P {
            return Err(bad("not a PE32+ (64-bit) image"));
        }
        let entry_point = rd32(bytes, opt + 16)?;
        let image_base = rd64(bytes, opt + 24)?;
        let size_of_image = rd32(bytes, opt + 56)?;
        let size_of_headers = rd32(bytes, opt + 60)?;
        let subsystem = rd16(bytes, opt + 68)?;
        let dll_characteristics = rd16(bytes, opt + 70)?;
        let n_dirs = rd32(bytes, opt + 108)? as usize;

        let mut directories = [(0u32, 0u32); dir::COUNT];
        let known = n_dirs.min(dir::COUNT);
        for i in 0..known {
            directories[i] = (rd32(bytes, opt + 112 + i * 8)?, rd32(bytes, opt + 112 + i * 8 + 4)?);
        }

        let sec_table_off = opt + opt_size;
        let mut sections = Vec::with_capacity(n_sections as usize);
        for i in 0..n_sections as usize {
            let s = sec_table_off + i * 40;
            if bytes.len() < s + 40 {
                return Err(bad("truncated section table"));
            }
            let name_bytes = &bytes[s..s + 8];
            let name = match name_bytes.iter().position(|b| *b == 0) {
                Some(0) => String::new(),
                Some(n) => String::from_utf8_lossy(&name_bytes[..n]).into_owned(),
                None => String::from_utf8_lossy(name_bytes).into_owned(),
            };
            let vsize = rd32(bytes, s + 8)?;
            let vaddr = rd32(bytes, s + 12)?;
            let raw_size = rd32(bytes, s + 16)?;
            let raw_ptr = rd32(bytes, s + 20)?;
            let flags = rd32(bytes, s + 36)?;
            sections.push(Section { name, vaddr, vsize, raw_ptr, raw_size, flags });
        }

        Ok(PeImage {
            bytes,
            machine,
            n_sections,
            characteristics,
            entry_point,
            image_base,
            size_of_image,
            size_of_headers,
            subsystem,
            dll_characteristics,
            sections,
            directories,
            sec_table_off,
        })
    }

    /// Machine id as a name for display.
    pub fn machine_name(&self) -> &'static str {
        match self.machine {
            IMAGE_FILE_MACHINE_AMD64 => "x86-64",
            IMAGE_FILE_MACHINE_ARM64 => "ARM64",
            IMAGE_FILE_MACHINE_ARM64EC => "ARM64EC",
            _ => "unknown",
        }
    }

    /// Is this an ARM64-family image (i.e. A64X-runnable)?
    pub fn is_arm64_family(&self) -> bool {
        matches!(self.machine, IMAGE_FILE_MACHINE_ARM64 | IMAGE_FILE_MACHINE_ARM64EC)
    }

    /// Map an RVA to a file offset (no section-table translation: RVAs
    /// below `size_of_headers` map directly; all section content shares
    /// `raw_ptr` mapping produced by the tool that wrote the image, and
    /// our builder keeps them identical).
    pub fn rva_to_off(&self, rva: u32, size: u32) -> Result<usize> {
        for s in &self.sections {
            let span = s.raw_size.max(s.vsize);
            if rva >= s.vaddr && rva < s.vaddr + span {
                let off = s.raw_ptr as usize + (rva - s.vaddr) as usize;
                if off + size as usize <= self.bytes.len() {
                    return Ok(off);
                }
                return Err(bad("rva inside section but beyond file"));
            }
        }
        if (rva as usize) < self.size_of_headers as usize && (rva + size) as usize <= self.bytes.len() {
            return Ok(rva as usize);
        }
        Err(bad(format!("rva {rva:#x} not covered by any section")))
    }

    /// Read `T`-ish fixed bytes at an RVA.
    fn rd_rva(&self, rva: u32, size: u32) -> Result<&'a [u8]> {
        let off = self.rva_to_off(rva, size)?;
        Ok(&self.bytes[off..off + size as usize])
    }

    fn rd_rva32(&self, rva: u32) -> Result<u32> {
        Ok(u32::from_le_bytes(self.rd_rva(rva, 4)?.try_into().unwrap()))
    }
    fn rd_rva16(&self, rva: u32) -> Result<u16> {
        Ok(u16::from_le_bytes(self.rd_rva(rva, 2)?.try_into().unwrap()))
    }
    fn rd_rva64(&self, rva: u32) -> Result<u64> {
        Ok(u64::from_le_bytes(self.rd_rva(rva, 8)?.try_into().unwrap()))
    }

    fn read_cstr_at(&self, off: usize, max: usize) -> String {
        let end = self.bytes.len().min(off + max);
        let slice = &self.bytes[off..end];
        let n = slice.iter().position(|b| *b == 0).unwrap_or(slice.len());
        String::from_utf8_lossy(&slice[..n]).into_owned()
    }

    /// Iterate imports (dll + symbol).
    pub fn imports(&self) -> Result<Vec<Import>> {
        let mut out = Vec::new();
        let (mut rva, _size) = self.directories[dir::IMPORT];
        if rva == 0 {
            return Ok(out);
        }
        loop {
            let ilt = self.rd_rva32(rva)?;
            let name_rva = self.rd_rva32(rva + 12)?;
            let iat = self.rd_rva32(rva + 16)?;
            if ilt == 0 && name_rva == 0 && iat == 0 {
                break;
            }
            let name_off = self.rva_to_off(name_rva, 1)?;
            let dll = self.read_cstr_at(name_off, 256);
            // Prefer the ILT (OriginalFirstThunk); fall back to the IAT.
            let thunk_rva = if ilt != 0 { ilt } else { iat };
            let mut t = 0u32;
            loop {
                let v = self.rd_rva64(thunk_rva + t * 8)?;
                if v == 0 {
                    break;
                }
                let slot = iat + t * 8;
                if v & (1 << 63) != 0 {
                    out.push(Import { dll: dll.clone(), symbol: ImportSymbol::Ordinal((v & 0xFFFF) as u16), iat_rva: slot });
                } else {
                    let hn_off = self.rva_to_off((v & 0x7FFF_FFFF) as u32, 1)?;
                    let name = self.read_cstr_at(hn_off + 2, 512);
                    out.push(Import { dll: dll.clone(), symbol: ImportSymbol::Name(name), iat_rva: slot });
                }
                t += 1;
                if t > 65536 {
                    return Err(bad("unterminated import thunk table"));
                }
            }
            rva += 20;
        }
        Ok(out)
    }

    /// Iterate exports.
    pub fn exports(&self) -> Result<Vec<Export>> {
        let mut out = Vec::new();
        let (rva, edir_size) = self.directories[dir::EXPORT];
        if rva == 0 {
            return Ok(out);
        }
        let ord_base = self.rd_rva32(rva + 16)?;
        let n_funcs = self.rd_rva32(rva + 20)?;
        let n_names = self.rd_rva32(rva + 24)?;
        let funcs_rva = self.rd_rva32(rva + 28)?;
        let names_rva = self.rd_rva32(rva + 32)?;
        let ords_rva = self.rd_rva32(rva + 36)?;

        let mut func_rvas = Vec::with_capacity(n_funcs as usize);
        for i in 0..n_funcs {
            func_rvas.push(self.rd_rva32(funcs_rva + i * 4)?);
        }
        let mut by_idx: Vec<Option<String>> = vec![None; n_funcs as usize];
        for i in 0..n_names {
            let noff = self.rva_to_off(self.rd_rva32(names_rva + i * 4)?, 1)?;
            let name = self.read_cstr_at(noff, 512);
            let ord_idx = self.rd_rva16(ords_rva + i * 2)? as usize;
            if ord_idx < by_idx.len() {
                by_idx[ord_idx] = Some(name);
            }
        }
        for (i, r) in func_rvas.iter().enumerate() {
            if *r == 0 {
                continue;
            }
            let is_fwd = *r >= rva && *r < rva + edir_size;
            let name = by_idx[i].clone();
            out.push(Export { name, ordinal: ord_base + i as u32, rva: *r, is_forwarder: is_fwd });
        }
        Ok(out)
    }

    /// Iterate base-relocation blocks.
    pub fn relocations(&self) -> Result<Vec<RelocBlock>> {
        let mut out = Vec::new();
        let (mut rva, size) = self.directories[dir::BASERELOC];
        let end = rva + size;
        while rva < end && self.directories[dir::BASERELOC].1 != 0 {
            let page = self.rd_rva32(rva)?;
            let block_size = self.rd_rva32(rva + 4)?;
            if block_size < 8 || rva + block_size > end {
                return Err(bad("malformed relocation block"));
            }
            let n = (block_size - 8) / 2;
            let mut entries = Vec::with_capacity(n as usize);
            for i in 0..n {
                let e = self.rd_rva16(rva + 8 + i * 2)?;
                entries.push((e >> 12, e & 0xFFF));
            }
            out.push(RelocBlock { page_rva: page, entries });
            rva += block_size;
        }
        Ok(out)
    }

    /// True if the image looks like a DLL.
    pub fn is_dll(&self) -> bool {
        self.characteristics & 0x2000 != 0
    }

    /// True when the entry point lies inside an executable section.
    pub fn entry_is_executable(&self) -> bool {
        self.sections.iter().any(|s| {
            s.is_code() && self.entry_point >= s.vaddr && self.entry_point < s.vaddr + s.vsize
        })
    }

    /// Raw access for CLI hex-dumps.
    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Section by name (`.text` etc.).
    pub fn section(&self, name: &str) -> Option<&Section> {
        self.sections.iter().find(|s| s.name == name)
    }

    /// Offset of the section table (for `info`, diagnostic).
    pub fn section_table_offset(&self) -> usize {
        self.sec_table_off
    }
}

// ---- little-endian readers ----

fn rd16(b: &[u8], off: usize) -> Result<u16> {
    if b.len() < off + 2 {
        return Err(bad("u16 read beyond image"));
    }
    Ok(u16::from_le_bytes([b[off], b[off + 1]]))
}
fn rd32(b: &[u8], off: usize) -> Result<u32> {
    if b.len() < off + 4 {
        return Err(bad("u32 read beyond image"));
    }
    Ok(u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]]))
}
fn rd64(b: &[u8], off: usize) -> Result<u64> {
    if b.len() < off + 8 {
        return Err(bad("u64 read beyond image"));
    }
    Ok(u64::from_le_bytes(b[off..off + 8].try_into().unwrap()))
}

#[allow(dead_code)]
const _: usize = PE_HEADER_OFF; // referenced by builder/tests
