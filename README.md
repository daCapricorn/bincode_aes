# bincode_aes

## Summary
`bincode_aes` is a decorated bincode serializer/deserializer.
Its purpose is to transparently encrypt (and decrypt) bytes as they are serialized/deserialized.

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
* Uses AES-256-CBC encryption.
* The consumer of this crate is responsible for key management.
  * The key is not pinned in memory (i.e. it may be swapped to disk).
  * Another user (or root) can disassemble (if key is compiled into binary) or attach a debugger (if executable is running) in order to acquire the key and decrypt the data.
* There is overhead associated each value/structure that is encoded:
  * e.g. An encoded bool value consumes 48 bytes (vs 1 byte with traditional/unencrypted bincode).
* There is also copy overhead associated with each value that is decoded:
  * e.g. A 10M serialized value will consume roughly 20M to decode.

## TODO:

What I have now works well-enough in its current state for my own purposes.
Here are some improvements that may be coming in the future.

### Short Term:
* Wrap Initialization Vector (IV) and EncryptedData in an enum, so additional ciphers/modes/key-lengths can be added without breaking compatibility.
* Add more tests

### Long Term:
* Consider using other AES modes (e.g. GCM or OCB) to provide authenticated encryption with associated data.
* Consider using [openssl](https://crates.io/crates/openssl) crate instead of [rust-crypto](https://crates.io/crates/rust-crypto).
* Perform decryption in-place instead of copying plaintext back to supplied vector.
* Add key-derivation function to facilitate creation of a key from a password/passphrase.
* Get the key from a pluggable trait/interface (stdin, yubikey, syscall, ??).
* Create a custom allocator to pin key in memory and wipe memory when it is disposed.
