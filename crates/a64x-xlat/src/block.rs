//! Translated blocks, the code cache, block chaining and the persistent
//! on-disk cache.
//!
//! # Chaining
//!
//! When a block ends in a direct control transfer to an address A that
//! already has a translation, its exit is a *chain*: a tail jump to A's
//! machine code. The dispatcher trampoline is left entirely out of hot
//! loops. Chain exits live in a fixed-size 12-byte slot at the end of the
//! block's independently relocatable exit stub so they can be (a) patched
//! in later, when the target block gets translated and (b) serialized as
//! "return form" for the persistent cache and re-linked on load.

use a64x_core::{Error, ExecBuffer, Memory, Result};
use std::collections::HashMap;

/// Length in bytes of a chain/return exit slot.
pub const SLOT_LEN: usize = 12;

/// Persistent cache magic + format version.
pub const CACHE_MAGIC: &[u8; 8] = b"A64XC001";

/// A recorded direct-transfer exit belonging to a block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Link {
    /// Offset of the exit slot inside the block's machine code.
    pub code_off: u32,
    /// Guest PC this exit continues to.
    pub target: u64,
}

/// One translated basic block.
pub struct TranslatedBlock {
    /// Guest PC of the first instruction.
    pub guest_pc: u64,
    /// Guest bytes covered by this block.
    pub guest_len: u32,
    /// Number of guest instructions.
    pub n_insns: u32,
    /// Direct-transfer exits.
    pub links: Vec<Link>,
    /// The host machine code.
    pub exec: ExecBuffer,
}

impl TranslatedBlock {
    /// Start of the machine code.
    pub fn entry(&self) -> *const u8 {
        self.exec.entry()
    }
}

/// Write the *return* form into an exit slot (`ret` + padding).
pub fn write_ret_slot(bytes: &mut [u8], off: usize) {
    let slot = &mut bytes[off..off + SLOT_LEN];
    slot[0] = 0xC3; // ret
    slot[1..].fill(0x90); // nop pad
}

/// Write the *chain* form into an exit slot (`movabs rax, entry ; jmp rax`).
pub fn write_chain_slot(bytes: &mut [u8], off: usize, entry: u64) {
    let slot = &mut bytes[off..off + SLOT_LEN];
    slot[0] = 0x48;
    slot[1] = 0xB8;
    slot[2..10].copy_from_slice(&entry.to_le_bytes());
    slot[10] = 0xFF;
    slot[11] = 0xE0;
}

/// Translator/cache configuration.
#[derive(Debug, Clone, Copy)]
pub struct XlatConfig {
    /// Bounds-check every guest memory access (a fault exits to the
    /// dispatcher with a MemoryFault). When false, accesses are masked into
    /// the guest space instead (faster, less exact diagnostics).
    pub checked_mem: bool,
    /// Count retired guest instructions / blocks in CpuState
    /// (tiny per-block overhead; useful numbers).
    pub count_stats: bool,
}

impl Default for XlatConfig {
    fn default() -> Self {
        XlatConfig { checked_mem: true, count_stats: true }
    }
}

impl XlatConfig {
    /// Config fingerprint for the persistent cache.
    fn tag(self) -> u16 {
        (self.checked_mem as u16) | ((self.count_stats as u16) << 1)
    }
}

/// Cache performance/coverage statistics.
#[derive(Debug, Default, Clone, Copy)]
pub struct CacheStats {
    /// Number of blocks translated.
    pub blocks_translated: u64,
    /// Number of guest instructions translated.
    pub insns_translated: u64,
    /// Host machine-code bytes emitted.
    pub code_bytes: u64,
    /// Chain links resolved.
    pub links_resolved: u64,
    /// Dispatcher lookups that found a block.
    pub hits: u64,
}

/// In-memory code cache. Blocks are owned for the lifetime of the cache.
pub struct CodeCache {
    /// Configuration in use.
    pub cfg: XlatConfig,
    blocks: HashMap<u64, Box<TranslatedBlock>>,
    /// Unresolved chain slots, patched as soon as their target appears.
    pending: Vec<(u64, Link)>, // (owner guest_pc, link)
    /// Statistics.
    pub stats: CacheStats,
}

impl CodeCache {
    /// Empty cache with the given config.
    pub fn new(cfg: XlatConfig) -> CodeCache {
        CodeCache { cfg, blocks: HashMap::new(), pending: Vec::new(), stats: CacheStats::default() }
    }

    /// Look up the machine code entry for a guest PC.
    pub fn lookup(&self, pc: u64) -> Option<*const u8> {
        self.blocks.get(&pc).map(|b| b.entry())
    }

    /// Number of cached blocks.
    pub fn len(&self) -> usize {
        self.blocks.len()
    }

    /// Fetch a block descriptor by guest PC.
    pub fn get(&self, pc: u64) -> Option<&TranslatedBlock> {
        self.blocks.get(&pc).map(|b| &**b)
    }

    /// True if `pc` has a translation.
    pub fn contains(&self, pc: u64) -> bool {
        self.blocks.contains_key(&pc)
    }

    /// Insert a freshly translated block:
    ///
    /// * self-loops chain immediately (hot-loop back-edges then never
    ///   leave native code),
    /// * other unresolved links pend until their target is translated,
    /// * pending links targeting *this* block are patched in place.
    pub fn insert(&mut self, block: TranslatedBlock) {
        let guest_pc = block.guest_pc;
        let entry = block.entry();
        self.stats.blocks_translated += 1;
        self.stats.insns_translated += block.n_insns as u64;
        self.stats.code_bytes += block.exec.code_len() as u64;

        // Self-links resolve right now; other links pend.
        for link in &block.links {
            if link.target == guest_pc {
                unsafe {
                    let p = block.exec.entry() as *mut u8;
                    let slot = core::slice::from_raw_parts_mut(p.add(link.code_off as usize), SLOT_LEN);
                    write_chain_slot(slot, 0, entry as u64);
                }
                self.stats.links_resolved += 1;
            } else if !self.blocks.contains_key(&link.target) {
                self.pending.push((guest_pc, *link));
            }
        }
        self.blocks.insert(guest_pc, Box::new(block));

        // Resolve pending links targeting this block.
        let mut i = 0;
        while i < self.pending.len() {
            let (owner_pc, link) = self.pending[i];
            if link.target == guest_pc {
                if let Some(owner) = self.blocks.get(&owner_pc) {
                    // SAFETY: we exclusively own the block; the slot region
                    // is inside its code and currently in "ret" form.
                    unsafe {
                        let p = owner.exec.entry() as *mut u8;
                        let slot = core::slice::from_raw_parts_mut(p.add(link.code_off as usize), SLOT_LEN);
                        write_chain_slot(slot, 0, entry as u64);
                    }
                    self.stats.links_resolved += 1;
                }
                self.pending.swap_remove(i);
            } else {
                i += 1;
            }
        }
    }

    /// Resolve `pc` to a block entry, translating first if necessary.
    pub fn get_or_translate(&mut self, mem: &Memory, pc: u64) -> Result<*const u8> {
        if let Some(e) = self.lookup(pc) {
            self.stats.hits += 1;
            return Ok(e);
        }
        let block = crate::codegen::translate_block(self, mem, pc)?;
        let entry = block.entry();
        self.insert(block);
        Ok(entry)
    }

    /// Iterate the cached blocks (guest PC → block). Diagnostics/tests.
    pub fn blocks(&self) -> impl Iterator<Item = (u64, &TranslatedBlock)> {
        self.blocks.iter().map(|(k, v)| (*k, &**v))
    }

    /// Number of pending (unresolved) chain links — diagnostics.
    pub fn pending_links(&self) -> usize {
        self.pending.len()
    }

    // ---------------------------------------------------------------------
    // Persistent cache
    // ---------------------------------------------------------------------

    /// Serialize the whole cache for the persistent on-disk cache.
    ///
    /// All exit slots are written in *return* form; links are stored in the
    /// header of each block and re-resolved on load (machine addresses are
    /// not portable across processes).
    pub fn save(&self, guest_hash: u64) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(CACHE_MAGIC);
        out.extend_from_slice(&guest_hash.to_le_bytes());
        out.extend_from_slice(&self.cfg.tag().to_le_bytes());
        out.extend_from_slice(&(self.blocks.len() as u32).to_le_bytes());
        for block in self.blocks.values() {
            out.extend_from_slice(&block.guest_pc.to_le_bytes());
            out.extend_from_slice(&block.guest_len.to_le_bytes());
            out.extend_from_slice(&block.n_insns.to_le_bytes());
            out.extend_from_slice(&(block.links.len() as u32).to_le_bytes());
            let code = block.exec.bytes();
            out.extend_from_slice(&(code.len() as u32).to_le_bytes());
            for l in &block.links {
                out.extend_from_slice(&l.code_off.to_le_bytes());
                out.extend_from_slice(&l.target.to_le_bytes());
            }
            let mut code_vec = code.to_vec();
            for l in &block.links {
                write_ret_slot(&mut code_vec, l.code_off as usize);
            }
            out.extend_from_slice(&code_vec);
        }
        out
    }

    /// Load a persistent cache, translating nothing: machine code is loaded
    /// verbatim, then all links are re-linked against the loaded block set.
    pub fn load(cfg: XlatConfig, bytes: &[u8], guest_hash: u64) -> Result<CodeCache> {
        let mut cur = Cursor { b: bytes, p: 0 };
        if cur.take(8)? != CACHE_MAGIC {
            return Err(Error::Host("bad cache magic".into()));
        }
        let hash = cur.u64()?;
        if hash != guest_hash {
            return Err(Error::Host("cache guest hash mismatch".into()));
        }
        let tag = cur.u16()?;
        if tag != cfg.tag() {
            return Err(Error::Host("cache config mismatch".into()));
        }
        let count = cur.u32()?;
        let mut cache = CodeCache::new(cfg);
        let mut raw: Vec<(u64, u32, u32, Vec<Link>, Vec<u8>)> = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let guest_pc = cur.u64()?;
            let guest_len = cur.u32()?;
            let n_insns = cur.u32()?;
            let n_links = cur.u32()?;
            let code_len = cur.u32()?;
            let mut links = Vec::with_capacity(n_links as usize);
            for _ in 0..n_links {
                links.push(Link { code_off: cur.u32()?, target: cur.u64()? });
            }
            let code = cur.take(code_len as usize)?.to_vec();
            raw.push((guest_pc, guest_len, n_insns, links, code));
        }
        for (guest_pc, guest_len, n_insns, links, code) in raw {
            // Links are fixed up below once all blocks are known.
            let exec = ExecBuffer::from_bytes(&code)?;
            let nb = TranslatedBlock { guest_pc, guest_len, n_insns, links, exec };
            let links = nb.links.clone();
            cache.blocks.insert(guest_pc, Box::new(nb));
            for link in links {
                cache.pending.push((guest_pc, link));
            }
            cache.stats.blocks_translated += 1;
            cache.stats.insns_translated += n_insns as u64;
        }
        // Re-link everything that is present.
        let targets: Vec<u64> = cache.blocks.keys().copied().collect();
        for target in targets {
            let entry = match cache.blocks.get(&target) {
                Some(b) => b.entry() as u64,
                None => continue,
            };
            let mut i = 0;
            while i < cache.pending.len() {
                let (owner_pc, link) = cache.pending[i];
                if link.target == target {
                    if let Some(owner) = cache.blocks.get(&owner_pc) {
                        unsafe {
                            let p = owner.exec.entry() as *mut u8;
                            let slot = core::slice::from_raw_parts_mut(p.add(link.code_off as usize), SLOT_LEN);
                            write_chain_slot(slot, 0, entry);
                        }
                        cache.stats.links_resolved += 1;
                    }
                    cache.pending.swap_remove(i);
                } else {
                    i += 1;
                }
            }
        }
        Ok(cache)
    }
}

struct Cursor<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.p + n > self.b.len() {
            return Err(Error::Host("cache file truncated".into()));
        }
        let s = &self.b[self.p..self.p + n];
        self.p += n;
        Ok(s)
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
}
