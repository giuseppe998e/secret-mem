use core::{alloc::Layout, ptr::NonNull};
use std::io;

pub mod unix;
pub mod windows;

/// Trait provides an interface for working with memory that should remain protected
/// and as invisible as possible. The primary goal is to prevent sensitive data
/// from being exposed to unintended processes or users by leveraging OS-specific
/// mechanisms like `memfd_secret` (on Linux systems), `mmap` (on Unix-like systems),
/// and `VirtualAlloc` (on Windows).
///
/// Implementations of this trait ensure that memory regions are allocated with
/// appropriate permissions (e.g., read-only or writable), and that deallocated memory
/// is securely handled to minimize the risk of sensitive information being leaked.
pub trait SecretAllocator {
    /// Allocates a memory region, according to the specified `layout`, which is
    /// intended to store sensitive data.
    ///
    /// # Parameters:
    /// - `layout`: The layout that defines the size and alignment of the memory block
    ///   to be allocated.
    ///
    /// # Returns:
    /// - On success, returns a `NonNull<u8>` pointer to the beginning of the allocated
    ///   memory block.
    /// - On failure, returns an `io::Result` containing the error.
    fn alloc(layout: Layout) -> io::Result<NonNull<u8>>;

    /// Changes the access permissions of a memory region to make it read-only.
    ///
    /// This function is typically called after sensitive data has been written to the
    /// allocated memory, ensuring that the data can no longer be modified.
    ///
    /// # Parameters:
    /// - `ptr`: A `NonNull<u8>` pointer to the beginning of the memory block.
    /// - `layout`: The layout of the memory block, which defines its size and alignment.
    ///
    /// # Returns:
    /// On success, returns `Ok(())`. On failure, returns an `io::Error`.
    fn make_read_only(ptr: NonNull<u8>, layout: Layout) -> io::Result<()>;

    /// Changes the access permissions of a memory region to make it writable.
    ///
    /// This function reverts a memory block's permissions back to writable, allowing
    /// sensitive data to be modified if needed. After modification, it is recommended
    /// to call `make_read_only` again to protect the data.
    ///
    /// # Parameters:
    /// - `ptr`: A `NonNull<u8>` pointer to the beginning of the memory block.
    /// - `layout`: The layout of the memory block, which defines its size and alignment.
    ///
    /// # Returns:
    /// On success, returns `Ok(())`. On failure, returns an `io::Error`.
    fn make_writable(ptr: NonNull<u8>, layout: Layout) -> io::Result<()>;

    /// Deallocates a previously allocated memory region.
    ///
    /// This function securely deallocates the memory block, ensuring that sensitive data
    /// is properly cleared (if necessary) and the memory is returned to the system.
    /// It is important to ensure that the memory is no longer in use before deallocating.
    ///
    /// # Parameters:
    /// - `ptr`: A `NonNull<u8>` pointer to the beginning of the memory block.
    /// - `layout`: The layout of the memory block, which defines its size and alignment.
    ///
    /// # Returns:
    /// On success, returns `Ok(())`. On failure, returns an `io::Error`.
    fn dealloc(ptr: NonNull<u8>, layout: Layout) -> io::Result<()>;
}

mod util {
    use std::sync::OnceLock;

    /// Returns the system's memory page size in bytes.
    ///
    /// # Platform-specific behavior
    /// - **Unix-based systems (Linux, macOS, etc.):**
    ///   - On macOS, this function uses `libc::vm_page_size` to determine the page size.
    ///   - On other Unix systems, it uses `libc::sysconf` to get the page size.
    ///
    /// - **Windows:** The function retrieves the page size by calling `GetSystemInfo`
    ///   and extracting the `dwPageSize` field from the `SYSTEM_INFO` structure.
    pub fn page_size() -> usize {
        static PAGE_SIZE: OnceLock<usize> = OnceLock::new();

        *PAGE_SIZE.get_or_init(|| {
            #[cfg(target_family = "unix")]
            {
                #[cfg(target_os = "macos")]
                unsafe {
                    libc::vm_page_size as usize
                }
                #[cfg(not(target_os = "macos"))]
                unsafe {
                    libc::sysconf(libc::_SC_PAGESIZE) as usize
                }
            }
            #[cfg(target_family = "windows")]
            {
                use std::mem::MaybeUninit;
                use windows_sys::Win32::System::SystemInformation as Win32;

                let sys_info = {
                    let mut sys_info = MaybeUninit::<Win32::SYSTEM_INFO>::uninit();
                    unsafe {
                        Win32::GetSystemInfo(sys_info.as_mut_ptr());
                        sys_info.assume_init()
                    }
                };

                sys_info.dwPageSize as usize
            }
        })
    }
}
