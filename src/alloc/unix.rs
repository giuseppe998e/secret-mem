use core::{alloc::Layout, ptr};
use std::io;

use libc::{MAP_ANON, MAP_FAILED, MAP_PRIVATE, PROT_READ, PROT_WRITE};
use zeroize::Zeroize;

use super::{util, SecretAllocator};

// FIXME Current implementation wastes memory
/// Provides an implementation of the `SecretAllocator` trait for Unix-based systems.
///
/// This implementation relies on Unix system calls to manage memory in a way that
/// limits its visibility to other processes and prevents sensitive data from being
/// leaked.
pub struct UnixSecretAllocator(());

impl UnixSecretAllocator {
    pub fn new() -> Self {
        Self(())
    }
}

impl SecretAllocator for UnixSecretAllocator {
    fn alloc(&self, layout: Layout) -> io::Result<*mut u8> {
        let size = util::aligned_layout_size(&layout);

        let mmap = unsafe {
            libc::mmap(
                ptr::null_mut(),
                size,
                PROT_WRITE | PROT_READ,
                MAP_PRIVATE | MAP_ANON,
                -1,
                0,
            )
        };

        if mmap == MAP_FAILED {
            return Err(io::Error::last_os_error());
        }

        if unsafe { libc::mlock(mmap, size) } < 0 {
            let last_os_error = io::Error::last_os_error();
            unsafe { libc::munmap(mmap, size) };
            return Err(last_os_error);
        }

        #[cfg(any(target_os = "freebsd", target_os = "dragonfly"))]
        let madvise_result = unsafe { libc::madvise(mmap, size, libc::MADV_NOCORE) };
        #[cfg(not(any(target_os = "freebsd", target_os = "dragonfly")))]
        let madvise_result = unsafe { libc::madvise(mmap, size, libc::MADV_DONTDUMP) };

        if madvise_result < 0 {
            let last_os_error = io::Error::last_os_error();

            unsafe {
                libc::munlock(mmap, size);
                libc::munmap(mmap, size);
            }

            return Err(last_os_error);
        }

        Ok(mmap as _)
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

        // May fail (unchecked)
        unsafe {
            #[cfg(any(target_os = "freebsd", target_os = "dragonfly"))]
            libc::madvise(ptr.as_ptr() as *mut _, self.len, libc::MADV_CORE);
            #[cfg(not(any(target_os = "freebsd", target_os = "dragonfly")))]
            libc::madvise(ptr as _, size, libc::MADV_DODUMP);

            libc::munlock(ptr as _, size);
        }

        match unsafe { libc::munmap(ptr as _, size) } {
            -1 => Err(io::Error::last_os_error()),
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use core::{alloc::Layout, ptr, str};
    use std::io::Write as _;

    use super::*;

    #[test]
    fn test_unix_implementation() {
        let allocator = UnixSecretAllocator::new();
        let layout = unsafe { Layout::from_size_align_unchecked(1024, 8) }; // Allocate 1KB with 8-byte alignment

        let ptr = {
            // Assert that allocation was successful
            let result = allocator.alloc(layout);
            assert!(result.is_ok());

            unsafe { result.unwrap_unchecked() }
        };

        // Attempt to write into the allocation
        let result = {
            let mut slice_mut = unsafe { &mut *ptr::slice_from_raw_parts_mut(ptr, layout.size()) };
            write!(slice_mut, "Hello, World!")
        };
        assert!(result.is_ok());

        // Assert that make_readonly was successful
        let result = allocator.make_read_only(ptr, layout);
        assert!(result.is_ok());

        // Attempt to read from the allocation
        let result = {
            let slice_mut = unsafe { &*ptr::slice_from_raw_parts(ptr, layout.size()) };
            str::from_utf8(slice_mut)
        };
        assert!(result.is_ok_and(|s| &s[..13] == "Hello, World!"));

        // Assert that deallocation was successful
        let result = allocator.dealloc(ptr, layout);
        assert!(result.is_ok());
    }
}
