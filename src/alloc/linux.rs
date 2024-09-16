use core::{
    mem::ManuallyDrop,
    ptr::{self, NonNull},
};
use std::io;

use libc::{SYS_memfd_secret, MAP_FAILED, MAP_SHARED, PROT_READ, PROT_WRITE};
use zeroize::Zeroize;

use super::{SecretMemory, SecretMemoryMut};

/// A structure representing a mutable secret memory allocation on Linux.
///
/// The memory is secured using `mmap` and `SYS_memfd_secret` to protect sensitive data.
/// Once allocated, it provides read-write access, and can be converted into a read-only
/// version for additional protection when modifications are no longer necessary.
pub struct LinuxSecretMemoryMut {
    mmap: NonNull<u8>,
    len: usize,
}

impl SecretMemory for LinuxSecretMemoryMut {}

impl SecretMemoryMut for LinuxSecretMemoryMut {
    type ReadOnly = LinuxSecretMemory;

    fn with_length(len: usize) -> std::io::Result<Self> {
        assert!(len <= libc::off_t::MAX as usize, "Length out of bounds!");

        let mmap = unsafe {
            match libc::syscall(SYS_memfd_secret, 0) as libc::c_int {
                fd @ 0.. => {
                    if libc::ftruncate(fd, len as libc::off_t) < 0 {
                        libc::close(fd);
                        return Err(io::Error::last_os_error());
                    }

                    let mmap = libc::mmap(
                        ptr::null_mut(),
                        len,
                        PROT_WRITE | PROT_READ,
                        MAP_SHARED,
                        fd,
                        0,
                    );

                    libc::close(fd);
                    mmap
                }
                _ => return Err(io::Error::last_os_error()),
            }
        };

        match mmap {
            MAP_FAILED => Err(io::Error::last_os_error()),
            ptr => {
                let mmap = unsafe { NonNull::new_unchecked(ptr as *mut _) };
                Ok(Self { mmap, len })
            }
        }
    }
}

impl AsRef<[u8]> for LinuxSecretMemoryMut {
    fn as_ref(&self) -> &[u8] {
        let slice_ptr = ptr::slice_from_raw_parts(self.mmap.as_ptr(), self.len);
        unsafe { &(*slice_ptr) }
    }
}

impl AsMut<[u8]> for LinuxSecretMemoryMut {
    fn as_mut(&mut self) -> &mut [u8] {
        let slice_ptr = ptr::slice_from_raw_parts_mut(self.mmap.as_ptr(), self.len);
        unsafe { &mut (*slice_ptr) }
    }
}

impl Drop for LinuxSecretMemoryMut {
    fn drop(&mut self) {
        let slice_ptr = ptr::slice_from_raw_parts_mut(self.mmap.as_ptr(), self.len);
        Zeroize::zeroize(unsafe { &mut (*slice_ptr) });
        unsafe { libc::munmap(self.mmap.as_ptr() as *mut _, self.len) };
    }
}

/// A structure representing read-only secret memory on Linux.
///
/// This memory is secured using `mmap` and `SYS_memfd_secret`, providing protection for sensitive data.
/// Once converted from a mutable version, it allows only read access.
pub struct LinuxSecretMemory {
    mmap: NonNull<u8>,
    len: usize,
}

impl SecretMemory for LinuxSecretMemory {}

impl AsRef<[u8]> for LinuxSecretMemory {
    fn as_ref(&self) -> &[u8] {
        let slice_ptr = ptr::slice_from_raw_parts(self.mmap.as_ptr(), self.len);
        unsafe { &(*slice_ptr) }
    }
}

impl TryFrom<LinuxSecretMemoryMut> for LinuxSecretMemory {
    type Error = io::Error;

    fn try_from(value: LinuxSecretMemoryMut) -> Result<Self, Self::Error> {
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

impl Drop for LinuxSecretMemory {
    fn drop(&mut self) {
        unsafe { libc::mprotect(self.mmap.as_ptr() as *mut _, self.len, PROT_WRITE) };
        let slice_ptr = ptr::slice_from_raw_parts_mut(self.mmap.as_ptr(), self.len);
        Zeroize::zeroize(unsafe { &mut (*slice_ptr) });
        unsafe { libc::munmap(self.mmap.as_ptr() as *mut _, self.len) };
    }
}

// Tests
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_linux_secret_memory_mut() {
        let mut secret_mem =
            LinuxSecretMemoryMut::with_length(1024).expect("Failed to allocate memory");

        let data = secret_mem.as_mut();
        data[0] = 42;

        assert_eq!(secret_mem.as_ref().len(), 1024);
        assert_eq!(secret_mem.as_ref()[0], 42);
    }

    #[test]
    fn test_linux_secret_memory_readonly() {
        let mut secret_mem_mut =
            LinuxSecretMemoryMut::with_length(1024).expect("Failed to allocate memory");

        let data = secret_mem_mut.as_mut();
        data[0] = 42;

        let secret_mem_read_only = LinuxSecretMemory::try_from(secret_mem_mut)
            .expect("Failed to convert to read-only memory");
        assert_eq!(secret_mem_read_only.as_ref().len(), 1024);
        assert_eq!(secret_mem_read_only.as_ref()[0], 42);
    }
}
