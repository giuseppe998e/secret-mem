use core::{
    mem::ManuallyDrop,
    ptr::{self, NonNull},
};
use std::io;

use libc::{MAP_ANON, MAP_FAILED, MAP_PRIVATE, PROT_READ, PROT_WRITE};
use zeroize::Zeroize;

use super::{SecretMemory, SecretMemoryMut};

/// A structure representing a mutable secret memory allocation on Unix systems.
///
/// The memory is secured using `mmap`, `mlock` and `madvise` to protect sensitive data.
/// Once allocated, it provides read-write access, and can be converted into a read-only
/// version for additional protection when modifications are no longer necessary.
pub struct UnixSecretMemoryMut {
    mmap: NonNull<u8>,
    len: usize,
}

impl SecretMemory for UnixSecretMemoryMut {}

impl SecretMemoryMut for UnixSecretMemoryMut {
    type ReadOnly = UnixSecretMemory;

    fn with_length(len: usize) -> std::io::Result<Self> {
        assert!(len <= libc::off_t::MAX as usize, "Length out of bounds!");

        let mmap = unsafe {
            libc::mmap(
                ptr::null_mut(),
                len,
                PROT_WRITE | PROT_READ,
                MAP_PRIVATE | MAP_ANON,
                -1,
                0,
            )
        };

        if mmap == MAP_FAILED {
            return Err(io::Error::last_os_error());
        }

        if unsafe { libc::mlock(mmap, len) } < 0 {
            unsafe { libc::munmap(mmap, len) };
            return Err(io::Error::last_os_error());
        }

        let madvise_result = unsafe {
            #[cfg(any(target_os = "freebsd", target_os = "dragonfly"))]
            {
                libc::madvise(mmap, len, libc::MADV_NOCORE)
            }
            #[cfg(not(any(target_os = "freebsd", target_os = "dragonfly")))]
            {
                libc::madvise(mmap, len, libc::MADV_DONTDUMP)
            }
        };

        if madvise_result < 0 {
            unsafe {
                libc::munlock(mmap, len);
                libc::munmap(mmap, len);
            }

            return Err(io::Error::last_os_error());
        }

        let mmap = unsafe { NonNull::new_unchecked(mmap as *mut _) };
        Ok(Self { mmap, len })
    }
}

impl AsRef<[u8]> for UnixSecretMemoryMut {
    fn as_ref(&self) -> &[u8] {
        let slice_ptr = ptr::slice_from_raw_parts(self.mmap.as_ptr(), self.len);
        unsafe { &(*slice_ptr) }
    }
}

impl AsMut<[u8]> for UnixSecretMemoryMut {
    fn as_mut(&mut self) -> &mut [u8] {
        let slice_ptr = ptr::slice_from_raw_parts_mut(self.mmap.as_ptr(), self.len);
        unsafe { &mut (*slice_ptr) }
    }
}

impl Drop for UnixSecretMemoryMut {
    fn drop(&mut self) {
        let slice_ptr = ptr::slice_from_raw_parts_mut(self.mmap.as_ptr(), self.len);
        Zeroize::zeroize(unsafe { &mut (*slice_ptr) });

        unsafe {
            #[cfg(any(target_os = "freebsd", target_os = "dragonfly"))]
            libc::madvise(self.mmap.as_ptr() as *mut _, self.len, libc::MADV_CORE);
            #[cfg(not(any(target_os = "freebsd", target_os = "dragonfly")))]
            libc::madvise(self.mmap.as_ptr() as *mut _, self.len, libc::MADV_DODUMP);

            libc::munlock(self.mmap.as_ptr() as *mut _, self.len);
            libc::munmap(self.mmap.as_ptr() as *mut _, self.len);
        }
    }
}

/// A structure representing read-only secret memory on Unix systems.
///
/// The memory is secured using `mmap`, `mlock` and `madvise` to protect sensitive data.
/// Once converted from a mutable version, it allows only read access.
pub struct UnixSecretMemory {
    mmap: NonNull<u8>,
    len: usize,
}

impl SecretMemory for UnixSecretMemory {}

impl AsRef<[u8]> for UnixSecretMemory {
    fn as_ref(&self) -> &[u8] {
        let slice_ptr = ptr::slice_from_raw_parts(self.mmap.as_ptr(), self.len);
        unsafe { &(*slice_ptr) }
    }
}

impl TryFrom<UnixSecretMemoryMut> for UnixSecretMemory {
    type Error = io::Error;

    fn try_from(value: UnixSecretMemoryMut) -> Result<Self, Self::Error> {
        let this = {
            let manually_drop_value = ManuallyDrop::new(value);
            Self {
                mmap: manually_drop_value.mmap,
                len: manually_drop_value.len,
            }
        };

        if unsafe { libc::mprotect(this.mmap.as_ptr() as *mut _, this.len, PROT_READ) } < 0 {
            // Calls the ‘this’ destructor, freeing the mmap
            return Err(io::Error::last_os_error());
        }

        Ok(this)
    }
}

impl Drop for UnixSecretMemory {
    fn drop(&mut self) {
        unsafe { libc::mprotect(self.mmap.as_ptr() as *mut _, self.len, PROT_WRITE) };
        let slice_ptr = ptr::slice_from_raw_parts_mut(self.mmap.as_ptr(), self.len);
        Zeroize::zeroize(unsafe { &mut (*slice_ptr) });

        unsafe {
            #[cfg(any(target_os = "freebsd", target_os = "dragonfly"))]
            libc::madvise(self.mmap.as_ptr() as *mut _, self.len, libc::MADV_CORE);
            #[cfg(not(any(target_os = "freebsd", target_os = "dragonfly")))]
            libc::madvise(self.mmap.as_ptr() as *mut _, self.len, libc::MADV_DODUMP);

            libc::munlock(self.mmap.as_ptr() as *mut _, self.len);
            libc::munmap(self.mmap.as_ptr() as *mut _, self.len);
        }
    }
}

// Tests
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unix_secret_memory_mut() {
        let mut secret_mem =
            UnixSecretMemoryMut::with_length(1024).expect("Failed to allocate memory");

        let data = secret_mem.as_mut();
        data[0] = 42;

        assert_eq!(secret_mem.as_ref().len(), 1024);
        assert_eq!(secret_mem.as_ref()[0], 42);
    }

    #[test]
    fn test_unix_secret_memory_readonly() {
        let mut secret_mem_mut =
            UnixSecretMemoryMut::with_length(1024).expect("Failed to allocate memory");

        let data = secret_mem_mut.as_mut();
        data[0] = 42;

        let secret_mem_read_only = UnixSecretMemory::try_from(secret_mem_mut)
            .expect("Failed to convert to read-only memory");
        assert_eq!(secret_mem_read_only.as_ref().len(), 1024);
        assert_eq!(secret_mem_read_only.as_ref()[0], 42);
    }
}
