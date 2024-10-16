use core::{alloc::Layout, ptr::NonNull};
use std::io;

use super::SecretAllocator;

/// Provides an implementation of the `SecretAllocator` trait for Unix-based systems.
///
/// This implementation relies on Unix system calls to manage memory in a way that
/// limits its visibility to other processes and prevents sensitive data from being
/// leaked.
pub struct UnixSecretAllocator;

impl SecretAllocator for UnixSecretAllocator {
    fn alloc(layout: Layout) -> io::Result<NonNull<u8>> {
        todo!()
    }

    fn make_read_only(ptr: NonNull<u8>, layout: Layout) -> io::Result<()> {
        todo!()
    }

    fn make_writable(ptr: NonNull<u8>, layout: Layout) -> io::Result<()> {
        todo!()
    }

    fn dealloc(ptr: NonNull<u8>, layout: Layout) -> io::Result<()> {
        todo!()
    }
}
