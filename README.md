# bincode_aes

## Summary
`bincode_aes` is a decorated bincode serializer/deserializer.
Its purpose is to transparently encrypt (and decrypt) data as it is serialized/deserialized.
* A common use case would be encrypting data as it is written to disk.
* For transporting encrypted data over the network, you'd be better off using regular bincode & TLS.

## Example
```rust
extern crate bincode_aes;
fn main() {
    let key = bincode_aes::random_key().unwrap();
    let bc = bincode_aes::with_key(key);
    let target: Option<String>  = Some("hello world".to_string());

    let mut encoded: Vec<u8>    = bc.serialize(&target).unwrap();
    let decoded: Option<String> = bc.deserialize(&mut encoded).unwrap();
    assert_eq!(target, decoded);
}
```

## Notes
* Presently uses AES-256-CBC encryption.
* A new initialization vector gets generated for each value that is encoded.
* The consumer of this crate is responsible for key management.
  * The same key must also be used later, for deserialization.
  * The key is not pinned in memory (i.e. it may be swapped to disk).
  * Another user (or root) can disassemble the executable (if the key is compiled into the binary) or attach a debugger (if executable is running) to acquire the key and decrypt the data.
* There is space overhead associated with each value that is encoded:
  * e.g. An encoded bool value consumes 53 bytes (vs 1 byte with traditional/unencrypted bincode).
  * Encoding a single high-level structure is going to be much more efficient than encoding several lower-level structures or primitives.
* There is also copy overhead associated with each value as it is decoded:
  * e.g. A 10M serialized value will temporarily consume 20M during decryption.
  * The public function signatures used should permit optimization the future. Ciphertext can be directly decrypted back into the same mutable buffer.

## TODO:

What I have now works well-enough in its current state for my own purposes.
Here are some improvements that may be coming in the future.

### Short Term:
* Add more tests

### Long Term:
* Consider using other AES modes (e.g. GCM or OCB) to provide authenticated encryption with associated data.
* Consider using [openssl](https://crates.io/crates/openssl) crate instead of [rust-crypto](https://crates.io/crates/rust-crypto).
* Perform decryption in-place instead of copying plaintext back into the supplied/mutable vector.
* Add key-derivation function to facilitate creation of a key from a password/passphrase.
* Find a way to derive a key from `~/.ssh/id_rsa`, using `ssh-agent` or `keyring` to prompt for password just one time.
* Get the key from a pluggable trait/interface (stdin, yubikey, id_rsa, syscall, ??).
* Create a custom allocator to pin key into memory and wipe memory when the key is disposed.

## License

bincode_aes is dual licensed under the MIT and Apache 2.0 licenses, the same licenses
as the Rust compiler.