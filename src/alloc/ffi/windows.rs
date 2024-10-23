use core::{
    mem::MaybeUninit,
    ptr::{self, NonNull},
};
use std::io;

use windows_sys::Win32::System::{Memory as win, SystemInformation as win_info};

/// Maps a memory region into the process's address space.
///
/// Wraps the `VirtualAlloc` system call.
///
/// # Arguments
///
/// * `len` - The length of the memory region.
/// * `prot` - Memory protection flags.
/// * `flags` - Allocation flags.
///
/// # Returns
///
/// * A result containing a non-null pointer to the memory region on success,
///   or an I/O error on failure.
pub fn virtual_alloc(len: usize, prot: u32, flags: u32) -> io::Result<NonNull<[u8]>> {
    match unsafe { win::VirtualAlloc(ptr::null_mut(), len, flags, prot) } {
        ptr if ptr.is_null() => Err(io::Error::last_os_error()),
        ptr => {
            let ptr = unsafe { NonNull::new_unchecked(ptr as *mut u8) };
            Ok(NonNull::slice_from_raw_parts(ptr, len))
        }
    }
}

/// Changes the protection on a region of committed pages in the virtual
/// address space.
///
/// Wraps the `VirtualProtect` system call.
///
/// # Arguments
///
/// * `ptr` - A non-null pointer to the memory region.
/// * `len` - The length of the memory region.
/// * `prot` - The new protection flags.
///
/// # Returns
///
/// * A result containing the old protection flags on success,
///   or an I/O error on failure.
pub fn virtual_protect(ptr: NonNull<u8>, len: usize, prot: u32) -> io::Result<u32> {
    let mut old_protect = 0u32;
    match unsafe { win::VirtualProtect(ptr.as_ptr() as _, len, prot, &mut old_protect) } {
        0 => Err(io::Error::last_os_error()),
        _ => Ok(old_protect),
    }
}

/// Locks a memory region, preventing it from being paged out.
///
/// Wraps the `VirtualLock` system call.
///
/// # Arguments
///
/// * `ptr` - A non-null pointer to the memory region.
/// * `len` - The length of the memory region.
///
/// # Returns
///
/// * A result indicating success or an I/O error on failure.
pub fn virtual_lock(ptr: NonNull<u8>, len: usize) -> io::Result<()> {
    match unsafe { win::VirtualLock(ptr.as_ptr() as _, len) } {
        0 => Err(io::Error::last_os_error()),
        _ => Ok(()),
    }
}

/// Unlocks a memory region, allowing it to be paged out.
///
/// Wraps the `VirtualUnlock` system call.
///
/// # Arguments
///
/// * `ptr` - A non-null pointer to the memory region.
/// * `len` - The length of the memory region.
///
/// # Returns
///
/// * A result indicating success or an I/O error on failure.
pub fn virtual_unlock(ptr: NonNull<u8>, len: usize) -> io::Result<()> {
    match unsafe { win::VirtualUnlock(ptr.as_ptr() as _, len) } {
        0 => Err(io::Error::last_os_error()),
        _ => Ok(()),
    }
}

/// Frees a region of pages within the virtual address space of the calling process.
///
/// Wraps the `VirtualFree` system call.
///
/// # Arguments
///
/// * `ptr` - A non-null pointer to the memory region.
/// * `len` - The length of the memory region.
///
/// # Returns
///
/// * A result indicating success or an I/O error on failure.
pub fn virtual_free(ptr: NonNull<u8>, len: usize) -> io::Result<()> {
    match unsafe { win::VirtualFree(ptr.as_ptr() as _, len, win::MEM_RELEASE) } {
        0 => Err(io::Error::last_os_error()),
        _ => Ok(()),
    }
}

/// Retrieves the system's page size.
///
/// Wraps the `GetSystemInfo` system call.
///
/// # Returns
///
/// * The size of a memory page in bytes.
#[inline]
pub(super) fn page_size() -> usize {
    let sys_info = {
        let mut sys_info = MaybeUninit::<win_info::SYSTEM_INFO>::uninit();
        unsafe {
            win_info::GetSystemInfo(sys_info.as_mut_ptr());
            sys_info.assume_init()
        }
    };

    sys_info.dwPageSize as usize
}
