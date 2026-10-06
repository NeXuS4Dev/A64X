//! # a64x-core
//!
//! Core primitives shared by every A64X crate:
//!
//! * [`CpuState`] — the complete architectural state of the ARM64 guest.
//!   It has a stable, `#[repr(C)]` layout because translated machine code
//!   reads and writes it directly.
//! * [`Memory`] — the guest's virtual address space.
//! * [`ExecBuffer`] — host memory marked executable, used for translated code.
//!
//! A64X is a *binary translator*, not an emulator: guest instructions are
//! converted ahead-of-execution into native x86-64 machine code which then
//! runs directly on the host CPU. The structures in this crate are the
//! interface between generated code and the Rust runtime.

#![forbid(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

pub mod error;
pub mod exec;
pub mod memory;
pub mod platform;
pub mod state;

pub use error::{Error, Result};
pub use exec::ExecBuffer;
pub use memory::{Memory, GUEST_DEFAULT_SIZE};
pub use state::{CpuState, ExitReason, N_OFF, XZR, SP};

/// A guest virtual address (as seen by the ARM64 Windows program).
pub type GAddr = u64;

/// The guest address block translation begins from when a program's
/// entry point returns (it "returns to the kernel").
///
/// This address lives in the API-gateway range and is intercepted by the
/// dispatcher, ending the process the way `mainCRTStartup` returning to
/// the OS loader would.
pub const EXIT_SENTINEL: GAddr = crate::memory::GATEWAY_BASE - 0x10;
