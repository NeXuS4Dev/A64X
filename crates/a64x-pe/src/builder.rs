//! Minimal PE32+ (ARM64) image writer.
//!
//! Used to synthesize demo guests and test fixtures *in memory* — no
//! hand-assembled hex anywhere. Layout: DOS stub (e_lfanew = 0x80), PE
//! headers, then sections, with `.rdata` data synthesized for imports /
//! exports / relocations / exception data as needed.

use std::collections::BTreeMap;

use a64x_core::Result;

use crate::{bad, dir, parse::IMAGE_FILE_MACHINE_ARM64};

/// Section flags (subset).
pub mod flags {
    /// IMAGE_SCN_CNT_CODE.
    pub const CODE: u32 = 0x20;
    /// IMAGE_SCN_CNT_INITIALIZED_DATA.
    pub const IDATA: u32 = 0x40;
    /// IMAGE_SCN_CNT_UNINITIALIZED_DATA.
    pub const UDATA: u32 = 0x80;
    /// IMAGE_SCN_MEM_EXECUTE.
    pub const EXEC: u32 = 0x2000_0000;
    /// IMAGE_SCN_MEM_READ.
    pub const READ: u32 = 0x4000_0000;
    /// IMAGE_SCN_MEM_WRITE.
    pub const WRITE: u32 = 0x8000_0000;
}

/// A content section (`.text`, real data).
#[derive(Debug, Clone)]
pub struct SectionBuild {
    /// Name (max 8 chars).
    pub name: String,
    /// Characteristics.
    pub flags: u32,
    /// Raw contents.
    pub data: Vec<u8>,
    /// Virtual size (>= data.len(); zero-padded tail).
    pub vsize: u32,
}

impl SectionBuild {
    /// Executable `.text` section.
    pub fn text(data: &[u8]) -> SectionBuild {
        SectionBuild::new(".text", flags::CODE | flags::EXEC | flags::READ, data, false)
    }
    /// Initialized data section (`.data`); `writable` adds MEM_WRITE.
    pub fn data(name: &str, data: &[u8], writable: bool) -> SectionBuild {
        let f = flags::IDATA | flags::READ | if writable { flags::WRITE } else { 0 };
        SectionBuild::new(name, f, data, false)
    }

    fn new(name: &str, flags: u32, data: &[u8], pad: bool) -> SectionBuild {
        SectionBuild {
            name: name.into(),
            flags,
            data: data.to_vec(),
            vsize: if pad { 0 } else { data.len() as u32 },
        }
    }
}

/// An import the image should reference.
#[derive(Debug, Clone)]
pub struct ImportSpec {
    /// DLL name — kept case-exactly for the sections header.
    pub dll: String,
    /// Function name.
    pub name: String,
}

/// An export the image should contain.
#[derive(Debug, Clone)]
pub struct ExportSpec {
    /// Exported name (None = ordinal-only).
    pub name: Option<String>,
    /// Ordinal (base is 1).
    pub ordinal: u16,
    /// Target RVA.
    pub rva: u32,
}

/// One DIR64 relocation location.
#[derive(Debug, Clone, Copy)]
pub struct RelocSpec {
    /// Page RVA (4KiB-aligned).
    pub page_rva: u32,
    /// Offset within the page (4KiB).
    pub offset: u16,
}

/// Builder: fill in fields, then [`ImageBuilder::build`].
pub struct ImageBuilder {
    /// Machine id (default ARM64).
    pub machine: u16,
    /// True for DLL images.
    pub is_dll: bool,
    /// Preferred load address.
    pub image_base: u64,
    /// RVA of the entry point (index 0 of `entry_in` section by default).
    pub entry_rva: u32,
    /// Subsystem id (3 = console).
    pub subsystem: u16,
    /// Section alignment (default 0x1000).
    pub sect_align: u32,
    /// File alignment (default 0x200).
    pub file_align: u32,

    /// Content sections (in build order → rva order).
    pub sections: Vec<SectionBuild>,
    /// Imports to synthesize in `.rdata` (groups by dll on build).
    pub imports: Vec<ImportSpec>,
    /// Exports to synthesize.
    pub exports: Vec<ExportSpec>,
    /// DIR64 relocations to synthesize.
    pub relocs: Vec<RelocSpec>,
    /// `.pdata`-style exception entries `(begin_rva, end_rva, unwind_rva)`.
    pub pdata: Vec<(u32, u32, u32)>,
    /// SizeOfImage padding (extra pages after the last section).
    pub tail_pad: u32,
    /// Section index holding the entry point (rva computed at build time).
    entry_section: Option<usize>,
    /// Byte offset of the entry inside `entry_section`.
    entry_offset: u32,
}

impl Default for ImageBuilder {
    fn default() -> Self {
        ImageBuilder {
            machine: IMAGE_FILE_MACHINE_ARM64,
            is_dll: false,
            image_base: 0x0040_0000,
            entry_rva: 0x1000,
            subsystem: 3,
            sect_align: 0x1000,
            file_align: 0x200,
            sections: Vec::new(),
            imports: Vec::new(),
            exports: Vec::new(),
            relocs: Vec::new(),
            pdata: Vec::new(),
            tail_pad: 0,
            entry_section: None,
            entry_offset: 0,
        }
    }
}

impl ImageBuilder {
    /// Add a content section; data is its raw bytes (vsize = data len).
    pub fn add_section(&mut self, name: &str, flags: u32, data: &[u8]) -> &mut Self {
        self.sections.push(SectionBuild::new(name, flags, data, false));
        self
    }

    /// Push a pre-built section; returns its index (for [`ImageBuilder::entry`]).
    pub fn section(&mut self, s: SectionBuild) -> usize {
        self.sections.push(s);
        self.sections.len() - 1
    }

    /// Mark `section_idx` (+`offset` bytes) as the image entry point.
    pub fn entry(&mut self, section_idx: usize) -> &mut Self {
        self.entry_section = Some(section_idx);
        self.entry_offset = 0;
        self
    }

    /// Set the preferred load address.
    pub fn image_base(&mut self, base: u64) -> &mut Self {
        self.image_base = base;
        self
    }

    /// Import several functions from one DLL (`dll` then its symbols).
    pub fn imports(&mut self, dll_and_syms: &[&str]) -> &mut Self {
        let (dll, syms) = dll_and_syms.split_first().expect("imports needs a dll name");
        for s in syms {
            self.add_import(dll, s);
        }
        self
    }

    /// Add a raw content section with extra zeroed vsize tail.
    pub fn add_section_bss(&mut self, name: &str, flags: u32, data: &[u8], extra_bss: u32) -> &mut Self {
        let mut s = SectionBuild::new(name, flags, data, false);
        s.vsize = s.data.len() as u32 + extra_bss;
        self.sections.push(s);
        self
    }

    /// Import one function from a dll.
    pub fn add_import(&mut self, dll: &str, name: &str) -> &mut Self {
        self.imports.push(ImportSpec { dll: dll.into(), name: name.into() });
        self
    }

    /// Export one function.
    pub fn add_export(&mut self, name: Option<&str>, ordinal: u16, rva: u32) -> &mut Self {
        self.exports.push(ExportSpec { name: name.map(|s| s.into()), ordinal, rva });
        self
    }

    /// Relocate one 64-bit slot.
    pub fn add_reloc(&mut self, page_rva: u32, offset: u16) -> &mut Self {
        self.relocs.push(RelocSpec { page_rva, offset });
        self
    }

    // -----------------------------------------------------------------

    /// Synthesize the `.rdata` content (imports ILT/IAT + hint strings +
    /// export table + reloc blocks + pdata) as one blob and update our
    /// own directory info. Returns (blob, dirs_extra: dir → (rva_offset_in_blob, size)).
    fn synthesize_rdata(&self) -> (Vec<u8>, BTreeMap<usize, (u32, u32)>) {
        let mut data: Vec<u8> = Vec::new();
        let mut dirs_extra: BTreeMap<usize, (u32, u32)> = BTreeMap::new();

        // ---- imports ----
        if !self.imports.is_empty() {
            // group by dll preserving first-seen order
            let mut groups: Vec<(&str, Vec<&str>)> = Vec::new();
            for imp in &self.imports {
                match groups.iter_mut().find(|(d, _)| *d == imp.dll) {
                    Some((_, v)) => v.push(&imp.name),
                    None => groups.push((&imp.dll, vec![&imp.name])),
                }
            }
            let ndesc = groups.len() + 1;
            let descs_off = data.len();
            data.resize(descs_off + ndesc * 20, 0);

            let iat_start = data.len();
            let nthunks: usize = groups.iter().map(|(_, v)| v.len() + 1).sum();
            data.resize(iat_start + nthunks * 8, 0);
            let ilt_start = data.len();
            data.resize(ilt_start + nthunks * 8, 0);

            let string_start = data.len();
            // Plan string positions up-front so thunks can reference them.
            let mut strings: Vec<u8> = Vec::new();
            struct DllLayout {
                ilt_off: u32,
                iat_off: u32,
                name_rel: u32,
            }
            let mut layouts = Vec::with_capacity(groups.len());
            let mut ilt_cursor = ilt_start as u32;
            let mut iat_cursor = iat_start as u32;
            for (dll, syms) in &groups {
                let name_rel = (string_start + strings.len()) as u32;
                strings.extend_from_slice(dll.as_bytes());
                strings.push(0);
                if strings.len() % 2 != 0 {
                    strings.push(0);
                }
                layouts.push(DllLayout { ilt_off: ilt_cursor, iat_off: iat_cursor, name_rel });
                for _ in syms {
                    ilt_cursor += 8;
                    iat_cursor += 8;
                }
                ilt_cursor += 8;
                iat_cursor += 8;
            }
            let mut thunk_rel: Vec<u32> = Vec::new(); // hint/name rva per symbol, in order
            for (_, syms) in &groups {
                for sym in syms {
                    let rel = (string_start + strings.len()) as u32;
                    strings.extend_from_slice(&0u16.to_le_bytes()); // hint
                    strings.extend_from_slice(sym.as_bytes());
                    strings.push(0);
                    if strings.len() % 2 != 0 {
                        strings.push(0);
                    }
                    thunk_rel.push(rel);
                }
                thunk_rel.push(0);
            }
            data.extend_from_slice(&strings);

            // write descriptors + thunk copies
            let mut desc_cursor = descs_off as u32;
            let mut sym_idx = 0usize;
            let mut ilt_cursor = ilt_start as u32;
            let mut iat_cursor = iat_start as u32;
            for lay in &layouts {
                put32(&mut data, desc_cursor as usize, lay.ilt_off);
                put32(&mut data, desc_cursor as usize + 4, 0);
                put32(&mut data, desc_cursor as usize + 8, 0);
                put32(&mut data, desc_cursor as usize + 12, lay.name_rel);
                put32(&mut data, desc_cursor as usize + 16, lay.iat_off);
                desc_cursor += 20;
                for _ in 0.. {
                    if sym_idx >= thunk_rel.len() {
                        break;
                    }
                    let v = thunk_rel[sym_idx];
                    sym_idx += 1;
                    put64(&mut data, ilt_cursor as usize, v as u64);
                    put64(&mut data, iat_cursor as usize, v as u64);
                    ilt_cursor += 8;
                    iat_cursor += 8;
                    if v == 0 {
                        break;
                    }
                }
            }
            dirs_extra.insert(dir::IMPORT, (descs_off as u32, (ndesc * 20) as u32));
            dirs_extra.insert(dir::IAT, (iat_start as u32, (nthunks * 8) as u32));
        }

        // ---- exports ----
        if !self.exports.is_empty() {
            let n = self.exports.len();
            let export_dir = data.len();
            data.resize(export_dir + 40, 0); // IMAGE_EXPORT_DIRECTORY
            let name_base = data.len(); // n * 4 rvas
            data.resize(name_base + n * 4, 0);
            let ord_base = data.len(); // n * 2
            data.resize(ord_base + n * 2, 0);
            let strings: Vec<u8> = Vec::new();
            let mut strings = strings;
            let mut name_rel: Vec<u32> = Vec::with_capacity(n);
            for e in &self.exports {
                let rel = (data.len() + strings.len()) as u32;
                if let Some(nm) = &e.name {
                    strings.extend_from_slice(nm.as_bytes());
                }
                strings.push(0);
                name_rel.push(rel);
            }
            data.extend_from_slice(&strings);
            // ordinals sorted: by ordinal index
            let mut order: Vec<usize> = (0..n).collect();
            order.sort_by_key(|i| self.exports[*i].ordinal);
            let func_base = data.len();
            let max_ord = self.exports.iter().map(|e| e.ordinal).max().unwrap_or(0) as usize;
            data.resize(func_base + (max_ord.max(n)) * 4, 0);
            let n_func_slots = max_ord.max(n);
            // exports are laid out ordinal-major in the func table.
            let mut slot: Vec<u32> = vec![0; n_func_slots];
            let mut ord_lookup: Vec<u16> = vec![0; n_func_slots];
            for (i, e) in self.exports.iter().enumerate() {
                let o = (e.ordinal as usize).saturating_sub(1);
                if o >= slot.len() {
                    slot.resize(o + 1, 0);
                    ord_lookup.resize(o + 1, 0);
                }
                slot[o] = e.rva;
                ord_lookup[o] = i as u16;
            }
            for (i, e) in self.exports.iter().enumerate() {
                put32(&mut data, func_base + ((e.ordinal as usize).saturating_sub(1)) * 4, e.rva);
                put32(&mut data, name_base + i * 4, name_rel[i]);
                put16(&mut data, ord_base + i * 2, (e.ordinal as usize).saturating_sub(1) as u16);
            }
            // header (IMAGE_EXPORT_DIRECTORY field offsets)
            put32(&mut data, export_dir + 0, 0); // Characteristics
            put32(&mut data, export_dir + 4, 0); // TimeDateStamp
            put32(&mut data, export_dir + 8, 0); // Major/Minor version
            put32(&mut data, export_dir + 12, 0); // Name rva
            put32(&mut data, export_dir + 16, 1); // Base
            put32(&mut data, export_dir + 20, n as u32); // NumberOfFunctions
            put32(&mut data, export_dir + 24, n as u32); // NumberOfNames
            put32(&mut data, export_dir + 28, func_base as u32);
            put32(&mut data, export_dir + 32, name_base as u32);
            put32(&mut data, export_dir + 36, ord_base as u32);
            dirs_extra.insert(dir::EXPORT, (export_dir as u32, 40 + (data.len() - export_dir) as u32));
        }

        // ---- relocs ----
        if !self.relocs.is_empty() {
            let mut by_page: BTreeMap<u32, Vec<u16>> = BTreeMap::new();
            for r in &self.relocs {
                by_page.entry(r.page_rva).or_default().push(r.offset);
            }
            let reloc_start = data.len();
            let mut cur_page: Option<u32> = None;
            let mut block_start = 0usize;
            let mut entries: Vec<u16> = Vec::new();
            let flush = |data: &mut Vec<u8>, page: u32, start: usize, entries: &mut Vec<u16>| {
                let cnt = entries.len() as u32;
                let total = align_up_static(8 + cnt * 2, 4);
                // header was reserved at `start`; make room for entries
                data.resize(start + total as usize, 0);
                put32(data, start, page);
                put32(data, start + 4, total);
                for (i, off) in entries.iter().enumerate() {
                    put16(data, start + 8 + i * 2, (10 << 12) | (off & 0xFFF));
                }
                entries.clear();
            };
            for (page, offs) in &by_page {
                if cur_page != Some(*page) && cur_page.is_some() {
                    flush(&mut data, cur_page.unwrap(), block_start, &mut entries);
                }
                if cur_page != Some(*page) {
                    cur_page = Some(*page);
                    block_start = data.len();
                    data.resize(data.len() + 8, 0);
                }
                entries.extend_from_slice(offs);
            }
            if cur_page.is_some() {
                flush(&mut data, cur_page.unwrap(), block_start, &mut entries);
            }
            dirs_extra.insert(dir::BASERELOC, (reloc_start as u32, (data.len() - reloc_start) as u32));
        }

        // ---- pdata ----
        if !self.pdata.is_empty() {
            let start = data.len();
            for (b, e, u) in &self.pdata {
                data.extend_from_slice(&b.to_le_bytes());
                data.extend_from_slice(&e.to_le_bytes());
                data.extend_from_slice(&u.to_le_bytes());
            }
            dirs_extra.insert(dir::EXCEPTION, (start as u32, (data.len() - start) as u32));
        }

        (data, dirs_extra)
    }

    /// Build the final image.
    pub fn build(&self) -> Result<Vec<u8>> {
        if self.sections.is_empty() {
            return Err(bad("builder needs at least one section"));
        }
        for s in &self.sections {
            if s.name.as_bytes().len() > 8 {
                return Err(bad(format!("section name {:?} longer than 8 bytes", s.name)));
            }
        }

        let (mut rdata, dirs_extra) = self.synthesize_rdata();

        let use_rdata = !rdata.is_empty();
        let n_secs = (self.sections.len() + use_rdata as usize) as u16;
        let align_up = |v: u32, a: u32| -> u32 { (v + a - 1) & !(a - 1) };

        // headers: dos 0x80 + sig/coff 24 + optional 0xF0 + n*40
        let opt_size: u16 = 0xF0;
        let headers_size = align_up((0x80 + 24 + opt_size as u32 + n_secs as u32 * 40) as u32, self.file_align);

        // Lay out the user sections first so the .rdata rva is known and
        // the synthesized directory blob can be patched to absolute rvas.
        let mut rva = 0x1000u32;
        let mut raw = headers_size;
        let mut sec_meta: Vec<(u32, u32, u32, u32)> = Vec::with_capacity(n_secs as usize); // (vaddr, vsize, raw_ptr, raw_size)
        for s in &self.sections {
            let vsize = if s.vsize == 0 { s.data.len() as u32 } else { s.vsize };
            let raw_size = align_up(s.data.len() as u32, self.file_align);
            sec_meta.push((rva, vsize, raw, raw_size));
            rva += align_up(vsize, self.sect_align);
            raw += raw_size;
        }
        let rd_opt: Option<SectionBuild> = if use_rdata {
            let rdata_rva = rva;
            patch_rdata_rvas(&mut rdata, &dirs_extra, rdata_rva);
            let rd = SectionBuild {
                name: ".rdata".into(),
                flags: flags::IDATA | flags::READ,
                data: rdata,
                vsize: 0,
            };
            let vsize = rd.data.len() as u32;
            let raw_size = align_up(vsize, self.file_align);
            sec_meta.push((rva, vsize, raw, raw_size));
            rva += align_up(vsize, self.sect_align);
            raw += raw_size;
            Some(rd)
        } else {
            None
        };
        let mut all: Vec<&SectionBuild> = self.sections.iter().collect();
        if let Some(rd) = rd_opt.as_ref() {
            all.push(rd);
        }
        let size_of_image = rva + self.tail_pad;

        // ---- write ----
        let mut out: Vec<u8> = vec![0u8; raw as usize];
        // DOS
        out[0..2].copy_from_slice(&b"MZ"[..]);
        put32(&mut out, 0x3C, 0x80);
        // PE sig + COFF
        out[0x80..0x84].copy_from_slice(b"PE\0\0");
        put16(&mut out, 0x84, self.machine);
        put16(&mut out, 0x86, n_secs);
        put32(&mut out, 0x88, 0); // TimeDateStamp
        put16(&mut out, 0x94, opt_size);
        let mut chars: u16 = 0x0022; // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
        if self.is_dll {
            chars |= 0x2000;
        }
        put16(&mut out, 0x96, chars);
        // Optional (PE32+)
        let opt = 0x98usize;
        put16(&mut out, opt, 0x20B);
        out[opt + 2] = 14; // linker version major
        let mut code_sz = 0u32;
        let mut data_sz = 0u32;
        for (s, _) in all.iter().zip(sec_meta.iter()) {
            if s.flags & flags::CODE != 0 {
                code_sz += s.data.len() as u32;
            } else {
                data_sz += s.data.len() as u32;
            }
        }
        put32(&mut out, opt + 4, code_sz);
        put32(&mut out, opt + 8, data_sz);
        let effective_entry = match self.entry_section {
            Some(i) => sec_meta[i].0 + self.entry_offset,
            None => self.entry_rva,
        };
        put32(&mut out, opt + 16, effective_entry);
        put32(&mut out, opt + 20, sec_meta[0].0); // BaseOfCode
        put64(&mut out, opt + 24, self.image_base);
        put32(&mut out, opt + 32, self.sect_align);
        put32(&mut out, opt + 36, self.file_align);
        put16(&mut out, opt + 40, 10); // OS major
        put16(&mut out, opt + 48, 10); // subsystem version major
        put32(&mut out, opt + 56, size_of_image);
        put32(&mut out, opt + 60, headers_size);
        put16(&mut out, opt + 68, self.subsystem);
        put16(&mut out, opt + 70, 0x8160); // dll characteristics: high-entropy va / nx / dynamic base / seh
        put64(&mut out, opt + 72, 0x10_0000); // stack reserve
        put64(&mut out, opt + 80, 0x1000); // stack commit
        put64(&mut out, opt + 88, 0x10_0000); // heap reserve
        put64(&mut out, opt + 96, 0x1000); // heap commit
        put32(&mut out, opt + 108, dir::COUNT as u32); // dirs

        // directories (rdata ones reference the rdata section rva)
        let dir_slot = |out: &mut Vec<u8>, i: usize, rva: u32, size: u32| {
            put32(out, opt + 112 + i * 8, rva);
            put32(out, opt + 112 + i * 8 + 4, size);
        };
        if use_rdata {
            let rdata_rva = sec_meta.last().unwrap().0;
            for (i, (rel_rva, size)) in &dirs_extra {
                dir_slot(&mut out, *i, rdata_rva + rel_rva, *size);
            }
        }

        // section headers + data
        let sec_tab = opt + opt_size as usize;
        for (i, (s, (vaddr, vsize, raw_ptr, raw_size))) in all.iter().zip(sec_meta.iter()).enumerate() {
            let s_off = sec_tab + i * 40;
            let nb = s.name.as_bytes();
            out[s_off..s_off + nb.len()].copy_from_slice(nb);
            put32(&mut out, s_off + 8, *vsize);
            put32(&mut out, s_off + 12, *vaddr);
            put32(&mut out, s_off + 16, *raw_size);
            put32(&mut out, s_off + 20, *raw_ptr);
            put32(&mut out, s_off + 36, s.flags);
            out[*raw_ptr as usize..*raw_ptr as usize + s.data.len()].copy_from_slice(&s.data);
        }

        Ok(out)
    }
}

fn align_up_static(v: u32, a: u32) -> u32 {
    (v + a - 1) & !(a - 1)
}

/// Patch blob-relative rvas in the synthesized .rdata once the section's
/// absolute rva is known.
fn patch_rdata_rvas(data: &mut Vec<u8>, dirs: &BTreeMap<usize, (u32, u32)>, base: u32) {
    let rd32r = |d: &[u8], off: usize| u32::from_le_bytes(d[off..off + 4].try_into().unwrap());
    let rd64r = |d: &[u8], off: usize| u64::from_le_bytes(d[off..off + 8].try_into().unwrap());

    if let Some((imp_off, _)) = dirs.get(&dir::IMPORT) {
        let mut d = *imp_off as usize;
        loop {
            let ilt = rd32r(data, d);
            let name = rd32r(data, d + 12);
            let iat = rd32r(data, d + 16);
            if ilt == 0 && name == 0 && iat == 0 {
                break;
            }
            put32(data, d, ilt + base);
            put32(data, d + 12, name + base);
            put32(data, d + 16, iat + base);
            // thunk arrays end with a zero entry
            for start in [ilt as usize, iat as usize] {
                let mut t = start;
                loop {
                    let v = rd64r(data, t);
                    if v == 0 {
                        break;
                    }
                    put64(data, t, v + base as u64);
                    t += 8;
                }
            }
            d += 20;
        }
    }
    if let Some((exp_off, _)) = dirs.get(&dir::EXPORT) {
        let e = *exp_off as usize;
        let n_names = rd32r(data, e + 24);
        let funcs = rd32r(data, e + 28) as usize;
        let names = rd32r(data, e + 32) as usize;
        let ords = rd32r(data, e + 36) as usize;
        put32(data, e + 28, funcs as u32 + base);
        put32(data, e + 32, names as u32 + base);
        put32(data, e + 36, ords as u32 + base);
        for i in 0..n_names as usize {
            let v = rd32r(data, names + i * 4);
            put32(data, names + i * 4, v + base);
        }
    }
    // reloc blocks hold page RVAs only; pdata entries are absolute already.
}

fn put16(b: &mut [u8], off: usize, v: u16) {
    b[off..off + 2].copy_from_slice(&v.to_le_bytes());
}
fn put32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
}
fn put64(b: &mut [u8], off: usize, v: u64) {
    b[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::{ImportSymbol, PeImage, IMAGE_FILE_MACHINE_ARM64, IMAGE_FILE_MACHINE_AMD64};

    #[test]
    fn roundtrip_headers_and_sections() {
        let mut b = ImageBuilder::default();
        b.add_section(".text", flags::CODE | flags::EXEC | flags::READ, &[0xAA; 64]);
        b.add_section_bss(".data", flags::IDATA | flags::READ | flags::WRITE, &[1, 2, 3, 4, 5, 6, 7, 8], 0x100);
        let img = b.build().unwrap();
        let pe = PeImage::parse(&img).unwrap();
        assert_eq!(pe.machine, IMAGE_FILE_MACHINE_ARM64);
        assert!(!pe.is_dll());
        assert_eq!(pe.machine_name(), "ARM64");
        assert!(pe.is_arm64_family());
        assert_eq!(pe.n_sections, 2);
        assert_eq!(pe.subsystem, 3);
        assert_eq!(pe.sections[0].name, ".text");
        assert_eq!(pe.sections[0].vaddr, 0x1000);
        assert_eq!(pe.sections[0].vsize, 64);
        assert!(pe.sections[0].is_code());
        assert_eq!(pe.sections[1].vsize, 0x108);
        assert!(pe.entry_is_executable());
        assert_eq!(pe.image_base, 0x40_0000);
        assert_eq!(pe.entry_point, 0x1000);
        assert_eq!(pe.size_of_image, 0x3000);
        // headers map 1:1
        assert_eq!(pe.rva_to_off(0x10, 2).unwrap(), 0x10);
        // section rva maps to raw
        let off = pe.rva_to_off(0x1000, 2).unwrap();
        assert_eq!(img[off], 0xAA);
    }

    #[test]
    fn roundtrip_imports_exports_relocs() {
        let mut b = ImageBuilder::default();
        b.add_section(".text", flags::CODE | flags::EXEC | flags::READ, &[0xAA; 128]);
        b.add_import("KERNEL32.dll", "ExitProcess");
        b.add_import("KERNEL32.dll", "GetStdHandle");
        b.add_import("msvcrt.dll", "puts");
        b.add_export(Some("RunThing"), 1, 0x1010);
        b.add_export(Some("other_name"), 2, 0x1000);
        b.add_reloc(0x1000, 0x20);
        b.add_reloc(0x1000, 0x30);
        b.pdata.push((0x1000, 0x1080, 0x1400));

        let img = b.build().unwrap();
        let pe = PeImage::parse(&img).unwrap();
        assert_eq!(pe.n_sections, 2);

        let mut imps = pe.imports().unwrap();
        imps.sort_by(|a, b| (a.dll.clone(), format!("{:?}", a.symbol)).cmp(&(b.dll.clone(), format!("{:?}", b.symbol))));
        assert_eq!(imps.len(), 3);
        assert!(imps.iter().any(|i| i.dll == "KERNEL32.dll" && matches!(&i.symbol, ImportSymbol::Name(n) if n == "ExitProcess")));
        assert!(imps.iter().any(|i| i.dll == "msvcrt.dll" && matches!(&i.symbol, ImportSymbol::Name(n) if n == "puts")));

        let mut exps = pe.exports().unwrap();
        exps.sort_by_key(|e| e.ordinal);
        assert_eq!(exps.len(), 2);
        assert_eq!(exps[0].name.as_deref(), Some("RunThing"));
        assert_eq!(exps[0].ordinal, 1);
        assert_eq!(exps[0].rva, 0x1010);
        assert_eq!(exps[1].name.as_deref(), Some("other_name"));

        let rels = pe.relocations().unwrap();
        assert_eq!(rels.len(), 1);
        assert_eq!(rels[0].page_rva, 0x1000);
        assert_eq!(rels[0].entries, vec![(10, 0x20), (10, 0x30)]);

        assert_eq!(pe.directories[dir::EXCEPTION].0, pe.directories[dir::BASERELOC].0 + 0xC); // after one block
    }

    #[test]
    fn rejects_amd64_as_guest_but_parses() {
        let mut b = ImageBuilder::default();
        b.machine = IMAGE_FILE_MACHINE_AMD64;
        b.add_section(".text", flags::CODE | flags::EXEC | flags::READ, &[0xCC; 32]);
        let img = b.build().unwrap();
        let pe = PeImage::parse(&img).unwrap();
        assert_eq!(pe.machine_name(), "x86-64");
        assert!(!pe.is_arm64_family());
    }

    #[test]
    fn malformed_inputs_rejected() {
        assert!(PeImage::parse(&[0u8; 8]).is_err());
        let mut b = ImageBuilder::default();
        b.add_section(".text", flags::CODE | flags::EXEC | flags::READ, &[0x90; 8]);
        let mut img = b.build().unwrap();
        img[0] = b'X'; // break MZ
        assert!(PeImage::parse(&img).is_err());
        let mut b2 = ImageBuilder::default();
        b2.add_section(".text", flags::CODE | flags::EXEC | flags::READ, &[0x90; 8]);
        let mut img2 = b2.build().unwrap();
        img2[0x80] = b'X'; // break PE sig
        assert!(PeImage::parse(&img2).is_err());
        // empty PE image (no sections) rejected by builder
        let b3 = ImageBuilder::default();
        assert!(b3.build().is_err());
    }
}
