//! # a64x-rt — the runtime
//!
//! Ties everything together:
//!
//! * [`loader`] — map a PE32+ ARM64 image into guest memory, apply base
//!   relocations, bind imports to API gateways
//! * [`dispatch`] — the host-side driver around the translated-code
//!   machine (gateway/API marshaling, trap reporting, statistics)
//! * [`demo`] — a self-contained ARM64 demo image built up by the
//!   [`a64x_pe::builder`] — useful when no third-party ARM64 PE is handy

#![warn(missing_docs)]

pub mod demo;
pub mod dispatch;
pub mod loader;

pub use dispatch::{run, RunOutcome};
pub use loader::{load, validate, BoundImport, LoadedImage};

use a64x_api::ApiLayer;
use a64x_core::{Memory, Result};
use a64x_pe::PeImage;
use a64x_xlat::{Machine, XlatConfig};

/// Convenience wrapper: memory + machine + api for one guest program.
pub struct Guest {
    /// The executing universe.
    pub machine: Machine,
    /// The API layer.
    pub api: ApiLayer,
    /// Loaded image info.
    pub image: LoadedImage,
}

impl Guest {
    /// Load `pe_bytes` into fresh guest memory at the default image base.
    pub fn load(pe_bytes: &[u8], cfg: XlatConfig) -> Result<Guest> {
        Guest::load_at(pe_bytes, a64x_core::memory::DEFAULT_IMAGE_BASE, cfg, a64x_core::GUEST_DEFAULT_SIZE)
    }

    /// Load `pe_bytes` at an explicit base/size.
    pub fn load_at(pe_bytes: &[u8], image_base: u64, cfg: XlatConfig, mem_size: u64) -> Result<Guest> {
        let pe = PeImage::parse(pe_bytes)?;
        let mem = Memory::new(mem_size)?;
        let mut machine = Machine::new(mem, cfg)?;
        let api = ApiLayer::new();
        let image = load(&mut machine.mem, &pe, pe_bytes, image_base, &api)?;
        Ok(Guest { machine, api, image })
    }

    /// Run the loaded image to completion, marshaling API calls.
    pub fn run(&mut self) -> RunOutcome {
        self.run_with(false)
    }

    /// Run with per-round tracing.
    pub fn run_traced(&mut self) -> RunOutcome {
        self.run_with(true)
    }

    fn run_with(&mut self, trace: bool) -> RunOutcome {
        let entry = self.image.entry;
        let image_base = self.image.image_base;
        dispatch::run(&mut self.machine, &self.api, entry, &[], image_base, trace)
    }

    /// Convenience: set the guest command line string (available to the
    /// program via GetCommandLineA-style adapters).
    pub fn run_with_args(&mut self, args: &[u8]) -> RunOutcome {
        let entry = self.image.entry;
        let image_base = self.image.image_base;
        dispatch::run(&mut self.machine, &self.api, entry, args, image_base, false)
    }
}
