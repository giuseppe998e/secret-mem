use std::marker::PhantomData;

/// A secure container for storing secret value.
///
/// This structure is designed for scenarios where you need to
/// securely store sensitive information, such as cryptographic keys,
/// passwords, or other sensitive data.
///
/// The underlying memory management is handled using platform-specific
/// features to protect the memory (e.g., making it read-only, preventing
/// it from being swapped to disk, etc.).
pub struct SecretBox<T> {
    // TODO ...
    _phant: PhantomData<T>,
}
