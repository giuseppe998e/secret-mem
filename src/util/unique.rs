use core::{fmt, marker::PhantomData, ptr::NonNull};

/// A wrapper around a raw non-null `*mut T` that indicates that the possessor
/// of this wrapper owns the referent.
///
/// # Note
/// This structure has been copied and adapted from the Rust standard library (std).
/// You can find the original implementation here:
/// [unique.rs](https://github.com/rust-lang/rust/blob/master/library/core/src/ptr/unique.rs).
///
/// **Source**
/// - Project: Rust Standard Library (std)
/// - Repository: https://github.com/rust-lang/rust
/// - License: MIT/Apache-2.0
#[repr(transparent)]
pub struct Unique<T: ?Sized> {
    pointer: NonNull<T>,
    _marker: PhantomData<T>,
}

impl<T: Sized> Unique<T> {
    /// Creates a new `Unique` that is dangling, but well-aligned.
    ///
    /// This is useful for initializing types which lazily allocate, like
    /// `Vec::new` does.
    ///
    /// Note that the pointer value may potentially represent a valid pointer to
    /// a `T`, which means this must not be used as a "not yet initialized"
    /// sentinel value. Types that lazily allocate must track initialization by
    /// some other means.
    #[inline]
    pub const fn dangling() -> Self {
        Unique {
            pointer: NonNull::dangling(),
            _marker: PhantomData,
        }
    }
}

impl<T: ?Sized> Unique<T> {
    /// Creates a new `Unique` if `ptr` is non-null.
    #[inline]
    pub fn new(ptr: *mut T) -> Option<Self> {
        NonNull::new(ptr).map(|pointer| Unique {
            pointer,
            _marker: PhantomData,
        })
    }

    /// Creates a new `Unique` without checking if the pointer is null.
    ///
    /// # Safety
    /// The caller must guarantee that `ptr` is non-null.
    /// If this invariant is violated, undefined behavior may occur.
    #[inline]
    pub const unsafe fn new_unchecked(ptr: *mut T) -> Self {
        Unique {
            pointer: NonNull::new_unchecked(ptr),
            _marker: PhantomData,
        }
    }

    /// Acquires the underlying `*mut` pointer.
    #[inline]
    pub const fn as_ptr(self) -> *mut T {
        self.pointer.as_ptr()
    }

    /// Casts to a pointer of another type.
    ///
    /// The cast is done with the assumption that the underlying
    /// memory is valid for the new type.
    #[inline]
    pub const fn cast<U>(self) -> Unique<U> {
        Unique {
            pointer: self.pointer.cast(),
            _marker: PhantomData,
        }
    }
}

/// `Unique` pointers are `Send` if `T` is `Send` because the data they
/// reference is unaliased. Note that this aliasing invariant is
/// unenforced by the type system; the abstraction using the
/// `Unique` must enforce it.
unsafe impl<T: Send + ?Sized> Send for Unique<T> {}

/// `Unique` pointers are `Sync` if `T` is `Sync` because the data they
/// reference is unaliased. Note that this aliasing invariant is
/// unenforced by the type system; the abstraction using the
/// `Unique` must enforce it.
unsafe impl<T: Sync + ?Sized> Sync for Unique<T> {}

impl<T: ?Sized> Copy for Unique<T> {}

impl<T: ?Sized> Clone for Unique<T> {
    #[inline]
    fn clone(&self) -> Self {
        *self
    }
}

impl<T: ?Sized> fmt::Pointer for Unique<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Pointer::fmt(&self.as_ptr(), f)
    }
}
