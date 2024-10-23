use core::alloc::Layout;
use std::{io, sync::OnceLock};

mod ffi;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_family = "unix")]
mod unix;
#[cfg(target_family = "windows")]
mod windows;

#[cfg(target_os = "linux")]
pub use self::linux::LinuxSecretAllocator;
#[cfg(target_family = "unix")]
pub use self::unix::UnixSecretAllocator;
#[cfg(target_family = "windows")]
pub use self::windows::WindowsSecretAllocator;

/// Trait provides an interface for working with memory that should remain protected
/// and as invisible as possible. The primary goal is to prevent sensitive data
/// from being exposed to unintended processes or users by leveraging OS-specific
/// mechanisms like `memfd_secret` (on Linux systems), `mmap` (on Unix-like systems),
/// and `VirtualAlloc` (on Windows).
///
/// Implementations of this trait ensure that memory regions are allocated with
/// appropriate permissions (e.g., read-only or writable), and that deallocated memory
/// is securely handled to minimize the risk of sensitive information being leaked.
pub trait SecretAllocator: Send + Sync {
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
    fn alloc(&self, layout: Layout) -> io::Result<*mut u8>;

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
    fn make_read_only(&self, ptr: *mut u8, layout: Layout) -> io::Result<()>;

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
    fn make_writable(&self, ptr: *mut u8, layout: Layout) -> io::Result<()>;

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
    fn dealloc(&self, ptr: *mut u8, layout: Layout) -> io::Result<()>;
}

/// Returns a reference to the global instance of the platform-specific
/// secret memory allocator.
///
/// # Platform-specific behavior
///
/// - **Unix**: Checks if `memfd_secret` is supported.
///   If not available, it falls back to a more general Unix allocator.
/// - **Windows**: Initializes the general Windows allocator.
pub fn platform_secret_allocator() -> &'static dyn SecretAllocator {
    static INSTANCE: OnceLock<Box<dyn SecretAllocator>> = OnceLock::new();

    &**INSTANCE.get_or_init(|| {
        #[cfg(target_os = "linux")]
        {
            if ffi::unix::memfd_secret_available() {
                Box::new(LinuxSecretAllocator::new())
            } else {
                Box::new(UnixSecretAllocator::new())
            }
        }
        #[cfg(all(target_family = "unix", not(target_os = "linux")))]
        {
            Box::new(UnixSecretAllocator::new())
        }
        #[cfg(target_family = "windows")]
        {
            Box::new(WindowsSecretAllocator::new())
        }
    })
}

mod util {
    use core::{alloc::Layout, cmp};

    use super::ffi;

    pub trait AlignedSize {
        /// Returns the size of a memory layout aligned to the system's page size.
        fn page_aligned_size(&self) -> usize;
    }

    impl AlignedSize for Layout {
        fn page_aligned_size(&self) -> usize {
            let size = self.size();
            let align = cmp::max(self.align(), ffi::page_size());
            size.wrapping_add(align).wrapping_sub(1) & !align.wrapping_sub(1)
        }
    }
}
