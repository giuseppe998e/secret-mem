use std::sync::OnceLock;

#[cfg(target_family = "unix")]
pub mod unix;
#[cfg(target_family = "windows")]
pub mod windows;

/// Retrieves the system's page size.
///
/// # Platform-specific behavior
/// - **Unix-based systems (Linux, macOS, etc.):**
///   - On macOS, this function uses `libc::vm_page_size` to determine the page size.
///   - On other Unix systems, it uses `libc::sysconf` to get the page size.
///
/// - **Windows:** The function retrieves the page size by calling `GetSystemInfo`
///   and extracting the `dwPageSize` field from the `SYSTEM_INFO` structure.
///
/// # Returns
///
/// * The size of a memory page in bytes.
pub fn page_size() -> usize {
    static PAGE_SIZE: OnceLock<usize> = OnceLock::new();

    #[cfg(target_family = "unix")]
    {
        *PAGE_SIZE.get_or_init(self::unix::page_size)
    }
    #[cfg(target_family = "windows")]
    {
        *PAGE_SIZE.get_or_init(self::windows::page_size)
    }
}
