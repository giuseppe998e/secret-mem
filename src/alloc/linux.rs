use core::{alloc::Layout, ptr::NonNull};
use std::io;

use super::SecretAllocator;

// FIXME Current implementation wastes memory
/// Provides an implementation of the `SecretAllocator` trait for Linux systems.
///
/// This implementation relies on Linux `SYS_memfd_secret` and Unix system calls
/// to manage memory in a way that limits its visibility to other processes and
/// prevents sensitive data from being leaked.
pub struct LinuxSecretAllocator(());

impl LinuxSecretAllocator {
    pub fn new() -> Self {
        Self(())
    }
}

impl SecretAllocator for LinuxSecretAllocator {
    fn alloc(&self, layout: Layout) -> io::Result<NonNull<u8>> {
        todo!()
    }

    // NOTE Protection acts on an entire page, not a section.
    fn make_read_only(&self, ptr: NonNull<u8>, layout: Layout) -> io::Result<()> {
        todo!()
    }

    // NOTE Protection acts on an entire page, not a section.
    fn make_writable(&self, ptr: NonNull<u8>, layout: Layout) -> io::Result<()> {
        todo!()
    }

    fn dealloc(&self, ptr: NonNull<u8>, layout: Layout) -> io::Result<()> {
        todo!()
    }
}
