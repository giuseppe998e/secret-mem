#[cfg(target_family = "unix")]
pub mod unix {
    use core::ptr::{self, NonNull};
    use std::io;

    /// Creates a memory-mapped region with secret properties on Linux.
    ///
    /// Wraps the `SYS_memfd_secret` and `mmap` system calls.
    ///
    /// # Arguments
    ///
    /// * `len` - The length of the memory region.
    /// * `prot` - Memory protection flags.
    /// * `flags` - Mapping flags.
    ///
    /// # Returns
    ///
    /// * A result containing a non-null pointer to the memory region on success,
    ///   or an I/O error on failure.
    #[cfg(target_os = "linux")]
    pub fn mmap_memfd_secret(len: usize, prot: i32, flags: i32) -> io::Result<NonNull<[u8]>> {
        let fd = match unsafe { libc::syscall(libc::SYS_memfd_secret, 0) } {
            -1 => return Err(io::Error::last_os_error()),
            fd => fd as i32,
        };

        let result = match unsafe { libc::ftruncate(fd, len as i64) } {
            -1 => Err(io::Error::last_os_error()),
            _ => self::mmap_impl(len, prot, flags, fd),
        };

        unsafe { libc::close(fd) };
        result
    }

    /// Maps a memory region into the process's address space.
    ///
    /// Wraps the `mmap` system call.
    ///
    /// # Arguments
    ///
    /// * `len` - The length of the memory region.
    /// * `prot` - Memory protection flags.
    /// * `flags` - Mapping flags.
    ///
    /// # Returns
    ///
    /// * A result containing a non-null pointer to the memory region on success,
    ///   or an I/O error on failure.
    pub fn mmap(len: usize, prot: i32, flags: i32) -> io::Result<NonNull<[u8]>> {
        self::mmap_impl(len, prot, flags, 0)
    }

    /// Remaps a memory region to a new size.
    ///
    /// Wraps the `mremap` system call.
    ///
    /// # Arguments
    ///
    /// * `ptr` - A non-null pointer to the existing memory region.
    /// * `old_len` - The current length of the memory region.
    /// * `new_len` - The new length of the memory region.
    /// * `in_place` - A boolean indicating whether the remapping should be done in place.
    ///
    /// # Returns
    ///
    /// * A result containing a non-null pointer to the new memory region on success,
    ///   or an I/O error on failure.
    pub fn mremap(
        ptr: NonNull<u8>,
        old_len: usize,
        new_len: usize,
        in_place: bool,
    ) -> io::Result<NonNull<[u8]>> {
        let flags = libc::MREMAP_MAYMOVE * (!in_place as i32);
        match unsafe { libc::mremap(ptr.as_ptr() as _, old_len, new_len, flags) } {
            libc::MAP_FAILED => Err(io::Error::last_os_error()),
            ptr => {
                let ptr = unsafe { NonNull::new_unchecked(ptr as *mut u8) };
                Ok(NonNull::slice_from_raw_parts(ptr, new_len))
            }
        }
    }

    /// Provides advice about the use of memory.
    ///
    /// Wraps the `madvise` system call.
    ///
    /// # Arguments
    ///
    /// * `ptr` - A non-null pointer to the memory region.
    /// * `len` - The length of the memory region.
    /// * `advice` - The advice to be given.
    ///
    /// # Returns
    ///
    /// * A result indicating success or an I/O error on failure.
    pub fn madvise(ptr: NonNull<u8>, len: usize, advice: i32) -> io::Result<()> {
        match unsafe { libc::madvise(ptr.as_ptr() as _, len, advice) } {
            -1 => Err(io::Error::last_os_error()),
            _ => Ok(()),
        }
    }

    /// Locks a memory region, preventing it from being paged out to swap.
    ///
    /// Wraps the `mlock` system call.
    ///
    /// # Arguments
    ///
    /// * `ptr` - A non-null pointer to the memory region.
    /// * `len` - The length of the memory region.
    ///
    /// # Returns
    ///
    /// * A result indicating success or an I/O error on failure.
    pub fn mlock(ptr: NonNull<u8>, len: usize) -> io::Result<()> {
        match unsafe { libc::mlock(ptr.as_ptr() as _, len) } {
            -1 => Err(io::Error::last_os_error()),
            _ => Ok(()),
        }
    }

    /// Unlocks a memory region, allowing it to be paged out to swap.
    ///
    /// Wraps the `munlock` system call.
    ///
    /// # Arguments
    ///
    /// * `ptr` - A non-null pointer to the memory region.
    /// * `len` - The length of the memory region.
    ///
    /// # Returns
    ///
    /// * A result indicating success or an I/O error on failure.
    pub fn munlock(ptr: NonNull<u8>, len: usize) -> io::Result<()> {
        match unsafe { libc::munlock(ptr.as_ptr() as _, len) } {
            -1 => Err(io::Error::last_os_error()),
            _ => Ok(()),
        }
    }

    /// Unmaps a memory region.
    ///
    /// Wraps the `munmap` system call.
    ///
    /// # Arguments
    ///
    /// * `ptr` - A non-null pointer to the memory region.
    /// * `len` - The length of the memory region.
    ///
    /// # Returns
    ///
    /// * A result indicating success or an I/O error on failure.
    pub fn munmap(ptr: NonNull<u8>, len: usize) -> io::Result<()> {
        match unsafe { libc::munmap(ptr.as_ptr() as _, len) } {
            -1 => Err(io::Error::last_os_error()),
            _ => Ok(()),
        }
    }

    /// Used by `mmap` and `mmap_memfd_secret` functions
    #[inline]
    fn mmap_impl(len: usize, prot: i32, flags: i32, fd: i32) -> io::Result<NonNull<[u8]>> {
        match unsafe { libc::mmap(ptr::null_mut(), len, prot, flags, fd, 0) } {
            libc::MAP_FAILED => Err(io::Error::last_os_error()),
            ptr => {
                let ptr = unsafe { NonNull::new_unchecked(ptr as *mut u8) };
                Ok(NonNull::slice_from_raw_parts(ptr, len))
            }
        }
    }
}

#[cfg(target_family = "windows")]
pub mod windows {
    // TODO ...
}
