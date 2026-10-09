//! Win32 handle table with typed, shareable kernel objects.
//!
//! Every object lives behind `Rc<RefCell<Obj>>`, so several handles (from
//! DuplicateHandle or from opening a named object) can refer to one object,
//! and the object is dropped when its last handle is closed.

use crate::win_shared::{H_STDERR, H_STDIN, H_STDOUT};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

/// A disk file (CreateFile, or the file behind a file mapping).
pub(crate) struct FileObj {
    /// Host file.
    pub file: std::fs::File,
    /// Path as given to CreateFile.
    pub path: String,
    /// GENERIC_READ was requested.
    pub readable: bool,
    /// GENERIC_WRITE was requested.
    pub writable: bool,
}

/// An event (manual- or auto-reset).
pub(crate) struct EventObj {
    /// Manual-reset: stays signaled until ResetEvent.
    pub manual: bool,
    /// Signaled state.
    pub signaled: bool,
    /// Incremented by PulseEvent; waiters that started earlier are released.
    pub pulse_gen: u64,
}

/// A mutex: owned by at most one thread, recursive for its owner.
pub(crate) struct MutexObj {
    /// Owning thread id (0 = free).
    pub owner: u32,
    /// Recursion count while owned.
    pub count: u32,
    /// The previous owner exited while holding it.
    pub abandoned: bool,
}

/// A counting semaphore.
pub(crate) struct SemObj {
    /// Current count.
    pub count: i64,
    /// Maximum count.
    pub max: i64,
}

/// A kernel object behind a handle value.
pub(crate) enum Obj {
    /// Console stream: 0 = stdin, 1 = stdout, 2 = stderr.
    Console(u8),
    /// Disk file.
    File(FileObj),
    /// Thread (by thread id).
    Thread(u32),
    /// Event.
    Event(EventObj),
    /// Mutex.
    Mutex(MutexObj),
    /// Semaphore.
    Semaphore(SemObj),
    /// File mapping (index into the mapping table).
    Mapping(usize),
    /// Heap (index into the heap table).
    Heap(usize),
    /// Directory enumeration state (FindFirstFile).
    Find {
        dir: String,
        entries: Vec<String>,
        next: usize,
    },
}

/// Shared reference to a kernel object.
pub(crate) type ObjRef = Rc<RefCell<Obj>>;

/// The handle table of one process.
pub(crate) struct Handles {
    map: BTreeMap<u64, ObjRef>,
    next: u64,
    std: [u64; 3],
}

impl Handles {
    /// A table with the three console handles installed.
    pub(crate) fn new() -> Handles {
        let mut map = BTreeMap::new();
        map.insert(H_STDIN, Rc::new(RefCell::new(Obj::Console(0))));
        map.insert(H_STDOUT, Rc::new(RefCell::new(Obj::Console(1))));
        map.insert(H_STDERR, Rc::new(RefCell::new(Obj::Console(2))));
        Handles {
            map,
            next: 0x10,
            std: [H_STDIN, H_STDOUT, H_STDERR],
        }
    }

    /// Install `o` under a fresh handle value (multiples of four, as on Windows).
    pub(crate) fn insert(&mut self, o: Obj) -> u64 {
        self.insert_ref(Rc::new(RefCell::new(o)))
    }

    /// Install an existing object under a fresh handle value.
    pub(crate) fn insert_ref(&mut self, r: ObjRef) -> u64 {
        let h = self.next;
        self.next += 4;
        self.map.insert(h, r);
        h
    }

    /// Object behind `h` (a new reference to the same object).
    pub(crate) fn get(&self, h: u64) -> Option<ObjRef> {
        self.map.get(&h).cloned()
    }

    /// Remove the handle `h`; the object lives on while other handles refer to it.
    pub(crate) fn close(&mut self, h: u64) -> Option<ObjRef> {
        self.map.remove(&h)
    }

    /// Current standard handle `n` (0 = input, 1 = output, 2 = error).
    pub(crate) fn std_handle(&self, n: usize) -> u64 {
        self.std[n]
    }

    /// Replace standard handle `n` (SetStdHandle).
    pub(crate) fn set_std_handle(&mut self, n: usize, h: u64) {
        self.std[n] = h;
    }

    /// Every `(handle, object)` pair.
    pub(crate) fn iter(&self) -> impl Iterator<Item = (&u64, &ObjRef)> {
        self.map.iter()
    }
}
