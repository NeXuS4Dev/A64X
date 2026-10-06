//! Unified error type for A64X.

use core::fmt;

/// Everything that can go wrong while loading, translating or running a
/// guest ARM64 program.
#[derive(Debug)]
pub enum Error {
    /// The input was not a valid PE32+ image (bad magic, truncated, ...).
    BadImage(String),
    /// The image is valid but its machine type is not ARM64.
    WrongMachine(u16),
    /// A memory access outside the mapped guest address space.
    OutOfBounds {
        /// Address that was accessed.
        addr: u64,
        /// Size of the access.
        len: u64,
    },
    /// Guest instruction that the translator does not (yet) support.
    UnimplementedInsn {
        /// Guest PC of the instruction.
        pc: u64,
        /// The raw 32-bit instruction word.
        word: u32,
    },
    /// An import could not be resolved against the API translation layer.
    UnresolvedImport {
        /// DLL the symbol was imported from.
        dll: String,
        /// Symbol name (or ordinal as string).
        name: String,
    },
    /// The guest executed an SVC (Windows syscall stub).
    ///
    /// Translated programs are supposed to call Win32 APIs; raw syscalls hit
    /// the OS kernel directly and their numbering differs between
    /// architectures, so they need dedicated translation.
    UnsupportedSyscall {
        /// Guest PC of the SVC.
        pc: u64,
        /// SVC immediate.
        imm: u32,
    },
    /// The guest hit a BRK breakpoint.
    GuestBreakpoint(u64),
    /// The guest asked for a fixed load address that is not available.
    BaseAddressUnavailable {
        /// Requested base address.
        base: u64,
    },
    /// Host OS failure (allocation, protection, I/O).
    Host(String),
    /// Execution stopped because an execution limit was reached.
    ExecutionLimit(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::BadImage(m) => write!(f, "bad PE image: {m}"),
            Error::WrongMachine(m) => write!(f, "not an ARM64 image (machine type 0x{m:04x})"),
            Error::OutOfBounds { addr, len } => {
                write!(f, "guest memory access out of bounds: 0x{addr:x} (+{len})")
            }
            Error::UnimplementedInsn { pc, word } => {
                write!(f, "unimplemented ARM64 instruction 0x{word:08x} at 0x{pc:x}")
            }
            Error::UnresolvedImport { dll, name } => {
                write!(f, "unresolved import: {dll}!{name}")
            }
            Error::UnsupportedSyscall { pc, imm } => {
                write!(f, "unsupported SVC #{imm} at 0x{pc:x} (syscall translation not enabled)")
            }
            Error::GuestBreakpoint(pc) => write!(f, "guest breakpoint at 0x{pc:x}"),
            Error::BaseAddressUnavailable { base } => {
                write!(f, "image requires fixed base 0x{base:x} which is unavailable")
            }
            Error::Host(m) => write!(f, "host error: {m}"),
            Error::ExecutionLimit(m) => write!(f, "execution limit reached: {m}"),
        }
    }
}

impl std::error::Error for Error {}

/// Convenience alias.
pub type Result<T> = core::result::Result<T, Error>;
