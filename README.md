# Secret Memory

`secret-mem` is a Rust library designed to securely manage sensitive data in memory.
It provides safe abstractions for allocating, managing, and deallocating memory regions
that should remain protected and as invisible as possible using platform-specific features.
The goal of the library is to ensure that sensitive data, such as passwords, cryptographic keys,
or confidential information, are kept secure in memory, reducing the risk of leakage or exposure.

The library will use operating system-specific mechanisms like `memfd_secret`, `mmap`,
and `VirtualAlloc` to provide memory protections, including:

- Preventing memory from being swapped to disk.
- Restricting read/write access to allocated memory regions.
- Ensuring memory is excluded from core dumps.
  <br>

**Important: This project is still under development and is currently non-functional!**

> While the foundation of the library is in place, key functionality, such as memory protections
> and platform-specific implementations, are not yet fully implemented or tested.

## Example (Currently Non-functional)

```rust
use secret_mem::{SecretBox, SecretVec, SecretString};

fn main() {
    // Example: Store a single secret value
    let secret_value: SecretBox<u64> = SecretBox::new(42);

    // Example: Store multiple secret values in a secure vector
    let mut secret_vec: SecretVec<u8> = SecretVec::new();
    secret_vec.push(0x42);
    secret_vec.push(0x43);

    // Example: Store a sensitive string in secure memory
    let secret_password: SecretString = SecretString::from("super_secret_password");

    // NOTE: None of the above functionality is currently working!
}
```

## Development Status

`secret-mem` is an experimental project and is currently incomplete.
The main structures, `SecretBox`, `SecretVec`, and `SecretString`, have been defined,
but they lack proper implementation and memory management features at this time.

### Roadmap

- [ ] Implement platform-specific memory allocation and protection features.
- [ ] Complete functionality for `SecretBox`
- [ ] Complete functionality for `SecretVec`.
- [ ] Complete functionality for `SecretString`.
- [ ] Add tests for memory safety.

## Safety & Security

The library will use unsafe code internally to interact with system memory management functions.
Handle your sensitive data with extreme care.

### License

This project is licensed under either of the following licenses, at your option:

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.
