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
