use core::{alloc::Layout, ptr};
use std::io;

use libc::{SYS_memfd_secret, MAP_FAILED, MAP_SHARED, PROT_READ, PROT_WRITE};
use zeroize::Zeroize;

use super::{util, SecretAllocator};

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
    fn alloc(&self, layout: Layout) -> io::Result<*mut u8> {
        let size = util::aligned_layout_size(&layout);

        let fd = match unsafe { libc::syscall(SYS_memfd_secret, 0) } {
            -1 => return Err(io::Error::last_os_error()),
            fd => {
                unsafe { libc::ftruncate(fd as libc::c_int, size as libc::c_long) };
                fd as libc::c_int
            }
        };

        let mmap = unsafe {
            libc::mmap(
                ptr::null_mut(),
                size,
                PROT_WRITE | PROT_READ,
                MAP_SHARED,
                fd,
                0,
            )
        };

        let result = match mmap {
            MAP_FAILED => Err(io::Error::last_os_error()),
            ptr => Ok(ptr as _),
        };

        unsafe { libc::close(fd) };
        result
    }

    // NOTE Protection acts on an entire page, not a section.
    fn make_read_only(&self, ptr: *mut u8, layout: Layout) -> io::Result<()> {
        let size = util::aligned_layout_size(&layout);
        match unsafe { libc::mprotect(ptr as _, size, PROT_READ) } {
            -1 => Err(io::Error::last_os_error()),
            _ => Ok(()),
        }
    }

    // NOTE Protection acts on an entire page, not a section.
    fn make_writable(&self, ptr: *mut u8, layout: Layout) -> io::Result<()> {
        let size = util::aligned_layout_size(&layout);
        match unsafe { libc::mprotect(ptr as _, size, PROT_WRITE | PROT_READ) } {
            -1 => Err(io::Error::last_os_error()),
            _ => Ok(()),
        }
    }

    fn dealloc(&self, ptr: *mut u8, layout: Layout) -> io::Result<()> {
        self.make_writable(ptr, layout)?;
        let size = util::aligned_layout_size(&layout);

        Zeroize::zeroize({
            let bytes_slice = ptr::slice_from_raw_parts_mut(ptr, size);
            unsafe { &mut *bytes_slice }
        });

        match unsafe { libc::munmap(ptr as _, size) } {
            -1 => Err(io::Error::last_os_error()),
            _ => Ok(()),
        }
    }
}

// NOTE The test cannot be started via `cargo test` due to the nature of the `SYS_MEMFD_SECRET'
//      call, which results in a `SIGBUS' error.
//
// #[cfg(test)]
// mod tests {
//     use core::{alloc::Layout, ptr, str};
//     use std::io::Write as _;
//
//     use super::*;
//
//     #[test]
//     fn test_linux_implementation() {
//         let allocator = LinuxSecretAllocator::new();
//         let layout = unsafe { Layout::from_size_align_unchecked(1024, 8) }; // Allocate 1KB with 8-byte alignment
//
//         // Assert that allocation was successful
//         let result = allocator.alloc(layout);
//         assert!(result.is_ok());
//
//         let ptr = unsafe { result.unwrap_unchecked() };
//
//         // Attempt to write into the allocation
//         let result = {
//             let mut slice_mut = unsafe { &mut *ptr::slice_from_raw_parts_mut(ptr, layout.size()) };
//             write!(slice_mut, "Hello, World!")
//         };
//         assert!(result.is_ok());
//
//         // Assert that make_readonly was successful
//         let result = allocator.make_read_only(ptr, layout);
//         assert!(result.is_ok());
//
//         // Attempt to read from the allocation
//         let result = {
//             let slice_mut = unsafe { &*ptr::slice_from_raw_parts(ptr, layout.size()) };
//             str::from_utf8(slice_mut)
//         };
//         assert!(result.is_ok_and(|s| &s[..13] == "Hello, World!"));
//
//         // Assert that deallocation was successful
//         let result = allocator.dealloc(ptr, layout);
//         assert!(result.is_ok());
//     }
// }
