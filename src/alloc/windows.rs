use core::{
    mem::ManuallyDrop,
    ptr::{self, NonNull},
};
use std::io;

use windows_sys::Win32::System::Memory::{
    VirtualAlloc, VirtualFree, VirtualLock, VirtualProtect, VirtualUnlock, MEM_COMMIT, MEM_RELEASE,
    MEM_RESERVE, PAGE_NOCACHE, PAGE_READONLY, PAGE_READWRITE,
};
use zeroize::Zeroize;

use super::{SecretMemory, SecretMemoryMut};

/// A structure representing a mutable secret memory allocation on Windows systems.
///
/// The memory is secured using `VirtualAlloc`, `VirtualLock` to protect sensitive data.
/// Once allocated, it provides read-write access, and can be converted into a read-only
/// version for additional protection when modifications are no longer necessary.
pub struct WindowsSecretMemoryMut {
    virt_alloc: NonNull<u8>,
    len: usize,
}

impl SecretMemory for WindowsSecretMemoryMut {}

impl SecretMemoryMut for WindowsSecretMemoryMut {
    type ReadOnly = WindowsSecretMemory;

    fn with_length(len: usize) -> io::Result<Self> {
        if !(len > 0 && len <= isize::MAX as usize) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "length out of bounds",
            ));
        }

        let virt_alloc = unsafe {
            VirtualAlloc(
                ptr::null_mut(),
                len,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE | PAGE_NOCACHE,
            )
        };

        if virt_alloc.is_null() {
            return Err(io::Error::last_os_error());
        }

        if unsafe { VirtualLock(virt_alloc, len) } == 0 {
            unsafe { VirtualFree(virt_alloc, 0, MEM_RELEASE) };
            return Err(io::Error::last_os_error());
        }

        let virt_alloc = unsafe { NonNull::new_unchecked(virt_alloc as *mut _) };
        Ok(Self { virt_alloc, len })
    }
}

impl AsRef<[u8]> for WindowsSecretMemoryMut {
    fn as_ref(&self) -> &[u8] {
        let slice_ptr = ptr::slice_from_raw_parts(self.virt_alloc.as_ptr(), self.len);
        unsafe { &(*slice_ptr) }
    }
}

impl AsMut<[u8]> for WindowsSecretMemoryMut {
    fn as_mut(&mut self) -> &mut [u8] {
        let slice_ptr = ptr::slice_from_raw_parts_mut(self.virt_alloc.as_ptr(), self.len);
        unsafe { &mut (*slice_ptr) }
    }
}

impl Drop for WindowsSecretMemoryMut {
    fn drop(&mut self) {
        let mem_slice = ptr::slice_from_raw_parts_mut(self.virt_alloc.as_ptr(), self.len);
        Zeroize::zeroize(unsafe { &mut (*mem_slice) });

        unsafe {
            VirtualUnlock(self.virt_alloc.as_ptr() as *mut _, self.len);
            VirtualFree(self.virt_alloc.as_ptr() as *mut _, 0, MEM_RELEASE);
        }
    }
}

/// A structure representing read-only secret memory on Windows systems.
///
/// The memory is secured using `VirtualAlloc`, `VirtualLock` to protect sensitive data.
/// Once converted from a mutable version, it allows only read access.
pub struct WindowsSecretMemory {
    virt_alloc: NonNull<u8>,
    len: usize,
}

impl SecretMemory for WindowsSecretMemory {}

impl AsRef<[u8]> for WindowsSecretMemory {
    fn as_ref(&self) -> &[u8] {
        let slice_ptr = ptr::slice_from_raw_parts(self.virt_alloc.as_ptr(), self.len);
        unsafe { &(*slice_ptr) }
    }
}

impl TryFrom<WindowsSecretMemoryMut> for WindowsSecretMemory {
    type Error = io::Error;

    fn try_from(value: WindowsSecretMemoryMut) -> Result<Self, Self::Error> {
        let this = {
            let manually_drop_value = ManuallyDrop::new(value);
            Self {
                virt_alloc: manually_drop_value.virt_alloc,
                len: manually_drop_value.len,
            }
        };

        let mut _old_flags = 0u32;
        let prot_result = unsafe {
            VirtualProtect(
                this.virt_alloc.as_ptr() as *mut _,
                this.len,
                PAGE_READONLY,
                &mut _old_flags as *mut _,
            )
        };

        match prot_result {
            // Calls the ‘this’ destructor, freeing the mmap
            0 => Err(io::Error::last_os_error()),
            _ => Ok(this),
        }
    }
}

impl Drop for WindowsSecretMemory {
    fn drop(&mut self) {
        let mut _old_flags = 0u32;
        unsafe {
            VirtualProtect(
                self.virt_alloc.as_ptr() as *mut _,
                self.len,
                PAGE_READWRITE,
                &mut _old_flags as *mut _,
            )
        };

        let mem_slice = ptr::slice_from_raw_parts_mut(self.virt_alloc.as_ptr(), self.len);
        Zeroize::zeroize(unsafe { &mut (*mem_slice) });

        unsafe {
            VirtualUnlock(self.virt_alloc.as_ptr() as *mut _, self.len);
            VirtualFree(self.virt_alloc.as_ptr() as *mut _, 0, MEM_RELEASE);
        }
    }
}

// Tests
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_windows_secret_memory_mut() {
        let mut secret_mem =
            WindowsSecretMemoryMut::with_length(1024).expect("Failed to allocate memory");

        let data = secret_mem.as_mut();
        data[0] = 42;

        assert_eq!(secret_mem.as_ref().len(), 1024);
        assert_eq!(secret_mem.as_ref()[0], 42);
    }

    #[test]
    fn test_windows_secret_memory_readonly() {
        let mut secret_mem_mut =
            WindowsSecretMemoryMut::with_length(1024).expect("Failed to allocate memory");

        let data = secret_mem_mut.as_mut();
        data[0] = 42;

        let secret_mem_read_only = WindowsSecretMemory::try_from(secret_mem_mut)
            .expect("Failed to convert to read-only memory");
        assert_eq!(secret_mem_read_only.as_ref().len(), 1024);
        assert_eq!(secret_mem_read_only.as_ref()[0], 42);
    }
}
