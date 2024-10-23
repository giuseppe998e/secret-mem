use core::{
    alloc::Layout,
    cmp, fmt, hash,
    marker::PhantomData,
    mem::ManuallyDrop,
    ops::{Deref, DerefMut},
    ptr,
};

use crate::{
    alloc,
    marker::{Locked, Unlocked},
    util::Unique,
};

/// A secure container for storing secret values.
///
/// This structure is designed for scenarios where you need to
/// securely store sensitive information, such as cryptographic keys,
/// passwords, or other sensitive data.
///
/// The underlying memory management is handled using platform-specific
/// features to protect the memory (e.g., making it read-only, preventing
/// it from being swapped to disk, etc.).
pub struct SecretBox<T, L = Unlocked> {
    pointer: Unique<T>,
    _marker: PhantomData<L>,
}

impl<T> SecretBox<T, Unlocked> {
    /// Creates a new `SecretBox` containing the given value.
    ///
    /// Allocates secure memory using a platform-specific allocator.
    /// Panics if the memory allocation fails.
    pub fn new(value: T) -> Self {
        let pointer = {
            let secret_alloc = alloc::platform_secret_allocator();

            secret_alloc
                .alloc(Layout::new::<T>())
                .map(|p| unsafe {
                    ptr::write(p as *mut T, value);
                    Unique::new_unchecked(p as *mut T)
                })
                .expect("Unable to allocate secret memory")
        };

        Self {
            pointer,
            _marker: PhantomData,
        }
    }

    /// Locks the `SecretBox`, making its contents read-only.
    ///
    /// If successful, returns a `SecretBox` in the `Locked` state,
    /// preventing further modifications.
    /// If it fails, it returns the original `SecretBox`.
    ///
    /// # Errors
    /// Returns an error if the memory cannot be made read-only.
    pub fn lock(self) -> Result<SecretBox<T, Locked>, Self> {
        let secret_alloc = alloc::platform_secret_allocator();

        let pointer = self.pointer.as_ptr() as _;
        let layout = Layout::new::<T>();

        match secret_alloc.make_read_only(pointer, layout) {
            Ok(_) => {
                let this = ManuallyDrop::new(self);

                Ok(SecretBox::<T, Locked> {
                    pointer: this.pointer,
                    _marker: PhantomData,
                })
            }
            Err(_) => Err(self),
        }
    }
}

impl<T> SecretBox<T, Locked> {
    /// Unlocks the `SecretBox`, allowing modifications to its contents.
    ///
    /// If successful, returns a `SecretBox` in the `Unlocked` state.
    /// If it fails, it returns the original `SecretBox`.
    ///
    /// # Errors
    /// Returns an error if the memory cannot be made writable.
    pub fn unlock(self) -> Result<SecretBox<T, Unlocked>, Self> {
        let secret_alloc = alloc::platform_secret_allocator();

        let pointer = self.pointer.as_ptr() as _;
        let layout = Layout::new::<T>();

        match secret_alloc.make_writable(pointer, layout) {
            Ok(_) => {
                let this = ManuallyDrop::new(self);

                Ok(SecretBox::<T, Unlocked> {
                    pointer: this.pointer,
                    _marker: PhantomData,
                })
            }
            Err(_) => Err(self),
        }
    }
}

impl<T: PartialEq, L> PartialEq for SecretBox<T, L> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        PartialEq::eq(&**self, &**other)
    }
}

impl<T: Eq, L> Eq for SecretBox<T, L> {}

impl<T: PartialOrd, L> PartialOrd for SecretBox<T, L> {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        PartialOrd::partial_cmp(&**self, &**other)
    }
}

impl<T: Ord, L> Ord for SecretBox<T, L> {
    #[inline]
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        Ord::cmp(&**self, &**other)
    }
}

impl<T: hash::Hash, L> hash::Hash for SecretBox<T, L> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        (**self).hash(state);
    }
}

impl<T, L> AsRef<T> for SecretBox<T, L> {
    #[inline]
    fn as_ref(&self) -> &T {
        self
    }
}

impl<T> AsMut<T> for SecretBox<T, Unlocked> {
    #[inline]
    fn as_mut(&mut self) -> &mut T {
        self
    }
}

impl<T, L> Deref for SecretBox<T, L> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { &*self.pointer.as_ptr() }
    }
}

impl<T> DerefMut for SecretBox<T, Unlocked> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.pointer.as_ptr() }
    }
}

impl<T, L> fmt::Debug for SecretBox<T, L> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretBox").finish_non_exhaustive()
    }
}

impl<T: Default> Default for SecretBox<T, Unlocked> {
    #[inline]
    fn default() -> Self {
        SecretBox::new(T::default())
    }
}

impl<T, L> Drop for SecretBox<T, L> {
    fn drop(&mut self) {
        let secret_alloc = alloc::platform_secret_allocator();
        let pointer = self.pointer.as_ptr();

        // Safely drop the value in place
        unsafe { ptr::drop_in_place(pointer) };

        // Deallocate the memory
        let _ = secret_alloc.dealloc(pointer as _, Layout::new::<T>());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_secretbox_lock() {
        // Lock the SecretBox
        let secret = SecretBox::new(42);
        let locked_secret = secret.lock().expect("Failed to lock SecretBox");

        // Verify the contents are still accessible
        assert_eq!(
            *locked_secret, 42,
            "Locked SecretBox should return the correct value"
        );

        // Attempt to unlock the SecretBox
        let mut unlocked_secret = locked_secret.unlock().expect("Failed to unlock SecretBox");

        // Check that we can modify the unlocked SecretBox
        *unlocked_secret = 100;

        // Check that we can lock it again
        let re_locked_secret = unlocked_secret.lock().expect("Failed to re-lock SecretBox");
        assert_eq!(
            *re_locked_secret, 100,
            "Re-locked SecretBox should return the correct value"
        );
    }

    #[test]
    fn test_secretbox_eq() {
        let secret1 = SecretBox::new(42);
        let secret2 = SecretBox::new(42);
        let secret3 = SecretBox::new(100);

        assert_eq!(
            secret1, secret2,
            "SecretBoxes with equal values should be equal"
        );
        assert_ne!(
            secret1, secret3,
            "SecretBoxes with different values should not be equal"
        );
    }

    #[test]
    fn test_secretbox_ord() {
        let secret1 = SecretBox::new(30);
        let secret2 = SecretBox::new(40);
        let secret3 = SecretBox::new(30);

        assert!(
            secret1 < secret2,
            "SecretBox should correctly compare values"
        );
        assert!(
            secret1 <= secret3,
            "SecretBox should correctly compare values"
        );
        assert!(
            secret2 > secret1,
            "SecretBox should correctly compare values"
        );
        assert!(
            secret2 >= secret3,
            "SecretBox should correctly compare values"
        );
    }

    #[test]
    fn test_secretbox_hash() {
        let secret1 = SecretBox::new(42);
        let secret2 = SecretBox::new(42);
        let secret3 = SecretBox::new(100);

        let mut set = HashSet::new();
        set.insert(secret1);
        assert!(
            set.contains(&secret2),
            "HashSet should contain equal SecretBox"
        );
        assert!(
            !set.contains(&secret3),
            "HashSet should not contain different SecretBox"
        );
    }

    #[test]
    fn test_secretbox_deref() {
        let secret = SecretBox::new(100);
        assert_eq!(
            *secret, 100,
            "Dereferencing SecretBox should return the stored value"
        );
    }

    #[test]
    fn test_secretbox_deref_mut() {
        let mut secret = SecretBox::new(100);
        *secret = 200;
        assert_eq!(*secret, 200, "SecretBox should allow mutable dereference");
    }
}
