use core::{
    alloc::Layout,
    ptr::{self, NonNull},
};
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
    fn alloc(&self, layout: Layout) -> io::Result<NonNull<u8>> {
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

        let ptr = unsafe { NonNull::new_unchecked(mmap as *mut _) };
        Ok(ptr)
    }

    // NOTE Protection acts on an entire page, not a section.
    fn make_read_only(&self, ptr: NonNull<u8>, layout: Layout) -> io::Result<()> {
        let size = util::aligned_layout_size(&layout);
        match unsafe { libc::mprotect(ptr.as_ptr() as *mut _, size, PROT_READ) } {
            -1 => Err(io::Error::last_os_error()),
            _ => Ok(()),
        }
    }

    // NOTE Protection acts on an entire page, not a section.
    fn make_writable(&self, ptr: NonNull<u8>, layout: Layout) -> io::Result<()> {
        let size = util::aligned_layout_size(&layout);
        match unsafe { libc::mprotect(ptr.as_ptr() as *mut _, size, PROT_WRITE | PROT_READ) } {
            -1 => Err(io::Error::last_os_error()),
            _ => Ok(()),
        }
    }

    fn dealloc(&self, ptr: NonNull<u8>, layout: Layout) -> io::Result<()> {
        self.make_writable(ptr, layout)?;
        let size = util::aligned_layout_size(&layout);

        Zeroize::zeroize({
            let bytes_slice = ptr::slice_from_raw_parts_mut(ptr.as_ptr(), size);
            unsafe { &mut *bytes_slice }
        });

        // May fail (unchecked)
        unsafe {
            #[cfg(any(target_os = "freebsd", target_os = "dragonfly"))]
            libc::madvise(ptr.as_ptr() as *mut _, self.len, libc::MADV_CORE);
            #[cfg(not(any(target_os = "freebsd", target_os = "dragonfly")))]
            libc::madvise(ptr.as_ptr() as *mut _, size, libc::MADV_DODUMP);

            libc::munlock(ptr.as_ptr() as *mut _, size);
        }

        match unsafe { libc::munmap(ptr.as_ptr() as *mut _, size) } {
            -1 => Err(io::Error::last_os_error()),
            _ => Ok(()),
        }
    }
}
