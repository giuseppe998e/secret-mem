use core::{
    alloc::Layout,
    ptr::{self, NonNull},
};
use std::io;

use windows_sys::Win32::System::Memory::{
    self as windows, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_NOCACHE, PAGE_READONLY,
    PAGE_READWRITE,
};
use zeroize::Zeroize;

use super::{util, SecretAllocator};

// FIXME Current implementation wastes memory
/// Provides an implementation of the `SecretAllocator` trait for Windows systems.
///
/// This implementation relies on Windows system calls to manage memory in a way that
/// limits its visibility to other processes and prevents sensitive data from being
/// leaked.
pub struct WindowsSecretAllocator(());

impl WindowsSecretAllocator {
    pub fn new() -> Self {
        Self(())
    }
}

impl SecretAllocator for WindowsSecretAllocator {
    fn alloc(&self, layout: Layout) -> io::Result<NonNull<u8>> {
        let size = util::aligned_layout_size(&layout);

        let virt_alloc = unsafe {
            windows::VirtualAlloc(
                ptr::null_mut(),
                size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE | PAGE_NOCACHE,
            )
        };

        if virt_alloc.is_null() {
            return Err(io::Error::last_os_error());
        }

        if unsafe { windows::VirtualLock(virt_alloc, size) } == 0 {
            let last_error = io::Error::last_os_error();
            unsafe { windows::VirtualFree(virt_alloc, 0, MEM_RELEASE) };
            return Err(last_error);
        }

        let ptr = unsafe { NonNull::new_unchecked(virt_alloc as *mut _) };
        Ok(ptr)
    }

    // NOTE Protection acts on an entire page, not a section.
    fn make_read_only(&self, ptr: NonNull<u8>, layout: Layout) -> io::Result<()> {
        let size = util::aligned_layout_size(&layout);
        let prot_result = unsafe {
            windows::VirtualProtect(
                ptr.as_ptr() as *mut _,
                size,
                PAGE_READONLY,
                (&mut 0u32) as *mut _,
            )
        };

        match prot_result {
            0 => Err(io::Error::last_os_error()),
            _ => Ok(()),
        }
    }

    // NOTE Protection acts on an entire page, not a section.
    fn make_writable(&self, ptr: NonNull<u8>, layout: Layout) -> io::Result<()> {
        let size = util::aligned_layout_size(&layout);
        let prot_result = unsafe {
            windows::VirtualProtect(
                ptr.as_ptr() as *mut _,
                size,
                PAGE_READWRITE,
                (&mut 0u32) as *mut _,
            )
        };

        match prot_result {
            0 => Err(io::Error::last_os_error()),
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

        unsafe { windows::VirtualUnlock(ptr.as_ptr() as *mut _, size) };
        match unsafe { windows::VirtualFree(ptr.as_ptr() as *mut _, 0, MEM_RELEASE) } {
            0 => Err(io::Error::last_os_error()),
            _ => Ok(()),
        }
    }
}
