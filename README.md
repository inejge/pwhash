# pwhash

A collection of password hashing and verification routines.

See the [documentation](https://docs.rs/pwhash/1.0.0/pwhash/) for API reference.

## Getting Started

Add the following to the `[dependencies]` section of your `Cargo.toml`:

```toml
pwhash = "1"
```

## Example

```rust
use pwhash::bcrypt;

// Hash a password with default parameters.
let h_new = bcrypt::hash("password").unwrap();

// Verify a password against an existing hash.
let h = "$2y$05$bvIG6Nmid91Mu9RcmmWZfO\
         5HJIMCT8riNW0hEp8f6/FuA2/mHZFpe";
assert!(bcrypt::verify("password", h));
```

## Summary

The following algorithms are currently implemented (in alphabetical order):

* bcrypt

* bsdi_crypt

* md5_crypt

* sha1_crypt

* sha256_crypt

* sha512_crypt

* unix_crypt

Each algorithm resides in its eponymous module, and provides the following
interface:

* `verify()`: verify a password against a hash.

* `hash()`: hash a password with default algorithm-spacific parameters.

* `hash_with()`: hash a password with customized parameters.

There is also a convenience module `unix` which provides the functions
`unix::crypt`, a __crypt__(3) work-alike, and `unix::verify`.
