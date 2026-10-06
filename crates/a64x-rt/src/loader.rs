//! PE32+ (ARM64) loader: sections, base relocations, import binding.
//!
//! Imports are the hinge of "API Translation": every named import is
//! resolved through the [`ApiLayer`] registry and its IAT slot is patched
//! with the adapter's **gateway address**. Calls through the IAT then
//! leave translated code and land in the dispatcher's API branch.

use a64x_api::gateway;
use a64x_api::ApiLayer;
use a64x_core::{Error, Memory, Result};
use a64x_pe::{ImportSymbol, PeImage, IMAGE_FILE_MACHINE_ARM64};

/// Result of loading a PE image into guest memory.
#[derive(Debug)]
pub struct LoadedImage {
    /// Guest VA of the entry point.
    pub entry: u64,
    /// Load base used.
    pub image_base: u64,
    /// Total bytes mapped.
    pub size_of_image: u32,
    /// Import binding results `(dll, symbol, gateway? )`.
    pub imports: Vec<BoundImport>,
    /// Machine of the image.
    pub machine_name: &'static str,
    /// Sections mapped: (name, guest va, raw size).
    pub sections: Vec<(String, u64, u32)>,
}

/// How one import resolved.
#[derive(Debug)]
pub struct BoundImport {
    /// DLL name.
    pub dll: String,
    /// Symbol description.
    pub symbol: String,
    /// Gateway VA written to the IAT slot (None = unresolved).
    pub gateway: Option<u64>,
}

/// Check that the image targets ARM64 Windows.
pub fn validate(pe: &PeImage) -> Result<()> {
    if pe.machine != IMAGE_FILE_MACHINE_ARM64 {
        return Err(Error::BadImage(format!(
            "expected an ARM64 (aarch64) PE32+ image, got machine {}",
            pe.machine_name()
        )));
    }
    if pe.is_dll() {
        return Err(Error::BadImage("DLL loading is not supported in v1 (load an .exe)".into()));
    }
    Ok(())
}

/// Load `pe` into `mem` at `image_base`, binding imports via `api`.
///
/// The whole image is written host-side before any execution starts, so
/// sections are plain bytes at `image_base + rva`. Base relocations are
/// applied when the preferred load address is unavailable (the loader is
/// free to pick the base; 0x400000 is the default).
pub fn load(mem: &mut Memory, pe: &PeImage, bytes: &[u8], image_base: u64, api: &ApiLayer) -> Result<LoadedImage> {
    validate(pe)?;

    // --- map sections
    let mut sections = Vec::with_capacity(pe.sections.len());
    for s in &pe.sections {
        let dst = image_base + s.vaddr as u64;
        let n = s.raw_size.min(s.vsize.max(s.raw_size)) as usize;
        let src_start = s.raw_ptr as usize;
        let src_end = src_start.saturating_add(s.raw_size as usize).min(bytes.len());
        if src_start > src_end {
            continue;
        }
        let raw = &bytes[src_start..src_end];
        let n = n.min(raw.len());
        if n > 0 {
            mem.write(dst, &raw[..n])?;
        }
        // zero-fill virtual tail beyond raw data
        if s.vsize as usize > s.raw_size as usize {
            mem.zero(dst + s.raw_size as u64, (s.vsize - s.raw_size) as u64)?;
        }
        sections.push((s.name.clone(), dst, s.raw_size));
    }

    // --- base relocations (we load at a base the image may not expect)
    let delta = image_base as i64 - pe.image_base as i64;
    if delta != 0 {
        for block in pe.relocations()? {
            for (kind, off) in &block.entries {
                if *kind != 10 {
                    continue; // ABSOLUTE etc. — skip
                }
                let loc = image_base + block.page_rva as u64 + *off as u64;
                let cur = mem.read_int(loc, 8)?;
                mem.write_int(loc, 8, (cur as i64).wrapping_add(delta) as u64)?;
            }
        }
    }

    // --- bind imports to gateway addresses
    let mut imports = Vec::new();
    let mut missing: Vec<String> = Vec::new();
    for imp in pe.imports()? {
        let gateway_addr = match &imp.symbol {
            ImportSymbol::Name(name) => api.resolve(&imp.dll, name).map(gateway::addr_of),
            ImportSymbol::Ordinal(_) => None,
        };
        match gateway_addr {
            Some(addr) => {
                mem.write_int(image_base + imp.iat_rva as u64, 8, addr)?;
                imports.push(BoundImport { dll: imp.dll.clone(), symbol: imp.symbol.to_string(), gateway: Some(addr) });
            }
            None => {
                imports.push(BoundImport { dll: imp.dll.clone(), symbol: imp.symbol.to_string(), gateway: None });
                missing.push(format!("{}!{}", imp.dll, imp.symbol));
            }
        }
    }
    if !missing.is_empty() {
        return Err(Error::BadImage(format!(
            "unimplemented API imports (add adapters or stub them): {}",
            missing.join(", ")
        )));
    }

    Ok(LoadedImage {
        entry: image_base + pe.entry_point as u64,
        image_base,
        size_of_image: pe.size_of_image,
        imports,
        machine_name: pe.machine_name(),
        sections,
    })
}

/// Guest pointer of the initial stack top.
pub fn initial_sp(mem_size: u64) -> u64 {
    mem_size - a64x_core::memory::STACK_SIZE / 2
}
