#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_family = "unix")]
pub mod unix;

/// Trait representing secret memory that allows read-only access.
///
/// Implementors of this trait should ensure that the memory is secured
/// and not accessible by unauthorized processes or memory dumps.
pub trait SecretMemory: AsRef<[u8]> {
    /// Provides a byte slice view of the secret memory.
    /// This function is a convenience wrapper around the `AsRef` implementation.
    ///
    /// # Returns
    /// A byte slice (`&[u8]`) representing the contents of the secret memory.
    #[inline]
    fn as_bytes(&self) -> &[u8] {
        self.as_ref()
    }
}

/// Trait representing secret memory that allows mutable access.
///
/// Memory allocated via this trait can later be converted into
/// a read-only form to further protect the data.
///
/// Implementors of this trait should ensure that the memory is secured
/// and not accessible by unauthorized processes or memory dumps.
pub trait SecretMemoryMut: AsMut<[u8]> + SecretMemory + Sized {
    /// Associated immutable memory type to convert
    /// to when read-only access is required.
    type ReadOnly: SecretMemory + TryFrom<Self, Error = std::io::Error>;

    /// Allocates a new memory region with the specified length.
    ///
    /// # Arguments
    /// * `len` - Length of the memory allocation in bytes.
    ///
    /// # Returns
    /// The allocator if successful, or an `io::Error`.
    fn with_length(len: usize) -> std::io::Result<Self>;

    /// Converts the memory allocation to a read-only version, consuming the original mutable allocator.
    ///
    /// # Returns
    /// The immutable allocator if successful, or an `io::Error`.
    #[inline]
    fn into_read_only(self) -> std::io::Result<Self::ReadOnly> {
        Self::ReadOnly::try_from(self)
    }

    /// Provides a mutable byte slice view of the secret memory.
    /// This function is a convenience wrapper around the `AsMut` implementation.
    ///
    /// # Returns
    /// A mutable byte slice (`&mut [u8]`) representing the contents of the secret memory.
    #[inline]
    fn as_bytes_mut(&mut self) -> &mut [u8] {
        self.as_mut()
    }
}
