//! # a64x-pe
//!
//! PE32+ (Portable Executable, 64-bit) support for A64X:
//!
//! * [`parse`] — header, section, import, export and base-relocation
//!   readers for `machine == 0xAA64` ARM64 images (and anything else for
//!   `info`-style inspection).
//! * [`builder`] — a tiny PE32+ writer used to synthesize real ARM64 PE
//!   images in-memory (demo guest + test fixtures). Not part of the
//!   execution pipeline, but it means nothing in the test-suite is
//!   hand-rolled bytes.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod builder;
pub mod parse;

pub use parse::{
    dir, DataDirIdx, Import, ImportSymbol, PeImage, RelocBlock, Section, Export,
    IMAGE_FILE_MACHINE_ARM64, IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_ARM64EC,
};
pub use builder::ImageBuilder;

use a64x_core::Error;

/// Turn an a64x-core error into a PE-flavored one (context helper).
pub(crate) fn bad(msg: impl Into<String>) -> Error {
    Error::BadImage(msg.into())
}
