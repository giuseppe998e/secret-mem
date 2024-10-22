use core::{
    alloc::Layout,
    ptr::{self, NonNull},
};
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
    fn alloc(&self, layout: Layout) -> io::Result<NonNull<u8>> {
        let size = util::aligned_layout_size(&layout);

        let mmap = match unsafe { libc::syscall(SYS_memfd_secret, 0) } as libc::c_int {
            -1 => return Err(io::Error::last_os_error()),
            fd => {
                if unsafe { libc::ftruncate(fd, size as libc::off_t) } < 0 {
                    unsafe { libc::close(fd) };
                    return Err(io::Error::last_os_error());
                }

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

                unsafe { libc::close(fd) };
                mmap
            }
        };

        match mmap {
            MAP_FAILED => Err(io::Error::last_os_error()),
            ptr => {
                let ptr = unsafe { NonNull::new_unchecked(ptr as *mut _) };
                Ok(ptr)
            }
        }
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

        match unsafe { libc::munmap(ptr.as_ptr() as *mut _, size) } {
            -1 => Err(io::Error::last_os_error()),
            _ => Ok(()),
        }
    }
}
