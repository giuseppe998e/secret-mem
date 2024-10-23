//! # Secret Memory Management Library
//!
//! This library provides a secure memory management solution for handling sensitive data
//! such as cryptographic keys, passwords, and other confidential information. It leverages
//! platform-specific features to protect memory regions, ensuring that sensitive data remains
//! protected from unauthorized access and is securely erased when no longer needed.
//!
//! ## Features
//!
//! - **Platform-Specific Allocators**: Implements secure memory allocation using platform-specific
//!   mechanisms:
//!   - **Linux**: Uses `memfd_secret` for secure memory allocation (_when available_).
//!   - **Unix**: Uses `mmap` with `MAP_ANON` and `mlock` to prevent memory from being swapped to disk.
//!   - **Windows**: Uses `VirtualAlloc` with `PAGE_NOCACHE` and `VirtualLock` to secure memory.
//! - **Memory Protection**: Provides functions to change memory access permissions, making memory
//!   regions read-only or writable as needed.
//! - **Secure Deallocation**: Ensures that sensitive data is securely erased before memory is deallocated.
//!
//! ## Safety and Security
//!
//! This library aims to provide a high level of security for managing sensitive data. However, it is
//! important to note that:
//!
//! - The current implementation may waste memory due to alignment and page size constraints.
//! - The library relies on platform-specific features, which may have different security guarantees.
//! - Users should ensure that the library is used in a secure environment and follow best practices
//!   for handling sensitive data.
//!
//! ## License
//!
//! This library is licensed under the MIT/Apache-2.0 license.

mod alloc;
mod boxed;
mod util;

pub mod marker {
    /// Marker type indicating that a secret container is in a locked state,
    /// where the contents are protected from modification.
    pub enum Locked {}

    /// Marker type indicating that a secret container is in an unlocked state,
    /// allowing modification of the contents.
    pub enum Unlocked {}
}

pub use boxed::SecretBox;
