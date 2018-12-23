# bincode_aes
## Summary
`bincode_aes` is a decorated bincode serializer/deserializer.  The intent is to transparently encrypt/decrypt bytes as they are serialized/deserialized.

## Example
```rust
something
```

## TODO:
* Consider using [`openssl`] crate instead of rust crypto.
* Decrypt in-place
* Add key-derivation callback functions instead of static key
* use aes-256-cbc or consider authenticated modes
* use interface to get key (pluggable, yubikey, from file, from stdin)
