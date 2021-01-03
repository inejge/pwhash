//! A collection of password hashing and verification routines.
//
// Copyright (c) 2016 Ivan Nejgebauer <inejge@gmail.com>
//
// Licensed under the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>. This file may not be copied,
// modified, or distributed except according to the terms of this
// license.
//!
//! For the summary of supported algorithms and recommendations, see
//! [Summary](#summary). Every algorithm has its own module; alphabetical list
//! is in the [Modules](#modules) section.
//!
//! # Getting Started
//!
//! Add the following to the `[dependencies]` section of your `Cargo.toml`:
//!
//! ```toml
//! pwhash = "1"
//! ```
//!
//! # Examples
//!
//! To verify a password hashed with a known algorithm:
//!
//! ```
//! use pwhash::bcrypt;
//!
//! let h = "$2y$05$bvIG6Nmid91Mu9RcmmWZfO\
//!          5HJIMCT8riNW0hEp8f6/FuA2/mHZFpe";
//! assert_eq!(bcrypt::verify("password", h), true);
//! ```
//!
//! To hash a password using default parameters:
//!
//! ```
//! use pwhash::bcrypt;
//!
//! let h = bcrypt::hash("password").unwrap();
//! ```
//!
//! To verify a password known to be in one of Unix modular hash formats:
//!
//! ```
//! use pwhash::unix;
//!
//! let h = "$2y$05$bvIG6Nmid91Mu9RcmmWZfO\
//!          5HJIMCT8riNW0hEp8f6/FuA2/mHZFpe";
//! assert_eq!(unix::verify("password", h), true);
//! ```
//!
//! # Summary
//!
//! Currently, there are implementations of seven algorithms, which should
//! cover anything one might find as a system-wide hash on a free Unix-like
//! OS: [bcrypt](bcrypt), [SHA-512](sha512_crypt), [SHA-256](sha256_crypt),
//! [HMAC-SHA1](sha1_crypt), [MD5](md5_crypt), [BSDi crypt](bsdi_crypt), and
//! [DES crypt](unix_crypt). The list is ordered roughly by security, with the
//! most secure algorithms first. The first two are recommended for new
//! passwords.
//!
//! Each algorithm is implemented in its own module, and offers three ways of
//! using it:
//!
//! * The `verify` function checks whether the provided hash corresponds to a
//!   password.
//!
//! * The `hash` function hashes a password using the default parameters for the
//!   algorithm.
//!
//! * The `hash_with` function allows the caller to customize the hashing
//!   parameters.
//!
//! Customization can always be accomplished by passing a `&str` with encoded
//! parameters (in the appropriate hash format) to `hash_with`. All algorithms
//! except DES crypt accept a `HashSetup` struct as a means of customization,
//! while bcrypt also has its own setup structure (see the module documenation.)
//!
//! The [unix](unix) module provides a __crypt__(3)-compatible function and a
//! `verify` which uses it to automatically recognize the algorithm of the
//! provided hash.

#![warn(missing_docs)]

mod enc_dec;
pub mod error;
pub mod unix_crypt;
pub mod bsdi_crypt;
mod des_crypt;
pub mod bcrypt;
pub mod sha1_crypt;
pub mod md5_crypt;
mod sha2_crypt;
pub mod sha256_crypt;
pub mod sha512_crypt;

/// Type alias for the Result type.
pub type Result<T> = std::result::Result<T, error::Error>;

/// Setup struct for basic hashing customization.
///
/// All implemented hash functions accept a custom salt value. If set to `None`,
/// a random salt will be generated. The usage of `rounds` varies with the
/// algorithm; visit the algorithm's module-level documentation for details.
/// It's always safe to initialize `rounds` to `None`, in which case the suitable
/// default value will be used.
pub struct HashSetup<'a> {
    /// Custom salt.
    pub salt: Option<&'a str>,
    /// Number of rounds.
    pub rounds: Option<u32>,
}

/// A trait for converting a type into a `HashSetup` struct.
pub trait IntoHashSetup<'a> {
    /// The conversion function.
    fn into_hash_setup(self, f: fn(&'a str) -> Result<HashSetup<'a>>) -> Result<HashSetup<'a>>;
}

impl<'a> IntoHashSetup<'a> for &'a str {
    fn into_hash_setup(self, f: fn(&'a str) -> Result<HashSetup<'a>>) -> Result<HashSetup<'a>> {
	f(self)
    }
}

impl<'a> IntoHashSetup<'a> for HashSetup<'a> {
    fn into_hash_setup(self, _f: fn(&'a str) -> Result<HashSetup<'a>>) -> Result<HashSetup<'a>> {
	Ok(self)
    }
}

/// A trait for extracting a NUL-terminated subslice from a slice.
///
/// The original Unix hashing functions expect passwords to be NUL-terminated C strings. This
/// allows values which can't be represented by Rust strings, which are constrained to be UTF-8.
/// On the other hand, Rust strings can contain NUL bytes, and C strings can't.
///
/// For maximum flexibility, hashing functions in this crate accept both strings and raw byte
/// vectors as password input. This trait can be used to ensure that any input value will be
/// truncated at the first NUL byte.
pub trait FindNul {
    /// Subslice extraction function.
    ///
    /// Given a slice, find and return the subslice before the first NUL byte, or the original
    /// slice if no NUL byte is found. Before searching, the slice is converted into a byte
    /// slice, if necessary. The returned slice also consists of raw bytes.
    fn nul_terminated_subslice(&self) -> &[u8];
}

impl FindNul for str {
    fn nul_terminated_subslice(&self) -> &[u8] {
        let nul_pos = self.as_bytes().windows(1).position(|window| window == [0u8]).unwrap_or_else(|| self.len());
        self[..nul_pos].as_bytes()
    }
}

impl FindNul for [u8] {
    fn nul_terminated_subslice(&self) -> &[u8] {
        let nul_pos = self.windows(1).position(|window| window == [0u8]).unwrap_or_else(|| self.len());
        self[..nul_pos].as_ref()
    }
}

fn consteq(hash: &str, calchash: Result<String>) -> bool {
    if calchash.is_err() {
	return false;
    }
    let hstr = calchash.unwrap();
    if hash.len() != hstr.len() {
	return false;
    }
    0 == hash.bytes().zip(hstr.bytes()).fold(0, |xs, (h1, h2)| xs | h1 ^ h2)
}

mod random {
    use rand::{Rng, random};
    use rand::rngs::OsRng;
    use rand::distributions::Standard;
    use crate::enc_dec::bcrypt_hash64_encode;

    pub fn gen_salt_str(chars: usize) -> String {
	let bytes = ((chars + 3) / 4) * 3;
	let rv = OsRng.sample_iter(&Standard).take(bytes).collect::<Vec<u8>>();
	let mut sstr = bcrypt_hash64_encode(&rv);
	while sstr.len() > chars {
	    sstr.pop();
	}
	sstr
    }

    pub fn gen_salt_bytes(bytes: &mut [u8]) {
	OsRng.fill(bytes);
    }

    pub fn vary_rounds(ceil: u32) -> u32 {
	ceil - (random::<u32>() % (ceil / 4))
    }
}

mod parse {
    use std::str;

    /// A trait for traversing a hash string.
    ///
    /// Hash strings have internal structure: they consist of a concatenation
    /// of a number of substrings. This trait enables extracting references to
    /// those substrings with the necessary semantics.
    pub trait HashIterator {
	/// The substring that is returned by methods.
	type Elem;

	/// Extract a fixed-size substring.
	///
	/// There must be <i>at least</i> `n` ASCII characters remaining in the
	/// string. If there are less, `None` is returned. If called with a non-zero
	/// `n`, this method drains the string: if there are exactly `n` characters
	/// remaining, subsequent calls will return `None`.
	///
	/// Calling `take` with `n` set to zero returns an empty string if the main
	/// string is not drained.
	fn take(&mut self, n: usize) -> Option<Self::Elem>;

	/// Extract a substring delimited by a byte.
	///
	/// Return a substring from the current position to the next occurrence of the
	/// ASCII delimiter `ac` or the end of the string. If the delimiter is found,
	/// advance the position one byte after it. Drains the string.
	fn take_until(&mut self, ac: u8) -> Option<Self::Elem>;

	/// Returns `true` if the string is not drained.
	fn at_end(&mut self) -> bool;
    }

    pub struct HashSlice<'a> {
	bp: &'a [u8],
	len: usize,
	pos: usize,
    }

    impl<'a> HashSlice<'a> {
	pub fn new(hash: &'a str) -> HashSlice<'a> {
	    HashSlice { bp: hash.as_bytes(), len: hash.len(), pos: 0 }
	}
    }

    impl<'a> HashIterator for HashSlice<'a> {
	type Elem = &'a str;

	fn take(&mut self, n: usize) -> Option<Self::Elem> {
	    if self.pos > self.len {
		return None;
	    }
	    let sp = self.pos;
	    if sp + n > self.len {
		self.pos = self.len + 1;
		None
	    } else {
		let endp = self.pos + n;
		self.pos = endp + if endp == self.len { 1 } else { 0 };
		if let Ok(s) = str::from_utf8(&self.bp[sp..endp]) {
		    Some(s)
		} else {
		    None
		}
	    }
	}

	fn take_until(&mut self, ac: u8) -> Option<Self::Elem> {
	    if self.pos > self.len {
		return None;
	    }
	    let mut sp = self.pos;
	    while sp < self.len {
		if self.bp[sp] == ac {
		    break;
		}
		sp += 1;
	    }
	    let oldp = self.pos;
	    self.pos = sp + 1;
	    if let Ok(s) = str::from_utf8(&self.bp[oldp..sp]) {
		Some(s)
	    } else {
		None
	    }
	}

	fn at_end(&mut self) -> bool {
	    self.take(0).unwrap_or("X") == "X"
	}
    }

    #[cfg(test)]
    mod tests {
	use super::{HashSlice, HashIterator};

	#[test]
	fn drain_string() {
	    let mut hs = HashSlice::new("$2y$05$bvIG6Nmid91Mu9RcmmWZfO5HJIMCT8riNW0hEp8f6/FuA2/mHZFpe");
	    assert_eq!(hs.take_until(b'$').unwrap(), "");
	    assert_eq!(hs.take_until(b'$').unwrap(), "2y");
	    assert_eq!(hs.take_until(b'$').unwrap(), "05");
	    assert_eq!(hs.take(22).unwrap(), "bvIG6Nmid91Mu9RcmmWZfO");
	    let mut hs1 = HashSlice { bp: hs.bp, pos: hs.pos, len: hs.len };
	    assert_eq!(hs.take_until(b'$').unwrap(), "5HJIMCT8riNW0hEp8f6/FuA2/mHZFpe");
	    assert_eq!(hs.at_end(), true);
	    assert_eq!(hs1.take(31).unwrap(), "5HJIMCT8riNW0hEp8f6/FuA2/mHZFpe");
	    assert_eq!(hs1.at_end(), true);
	}

	#[test]
	fn empty_string() {
	    let mut hs = HashSlice::new("");
	    assert_eq!(hs.take_until(b'$').unwrap(), "");
	    assert_eq!(hs.at_end(), true);
	    let mut hs = HashSlice::new("");
	    assert_eq!(hs.at_end(), false);
	}

	#[test]
	fn empty_elements() {
	    let mut hs = HashSlice::new("$");
	    assert_eq!(hs.take_until(b'$').unwrap(), "");
	    assert_eq!(hs.take_until(b'$').unwrap(), "");
	    assert_eq!(hs.at_end(), true);
	}

	#[test]
	fn combined_take() {
	    let mut hs = HashSlice::new("$");
	    let _ = hs.take_until(b'$').unwrap();
	    assert_eq!(hs.take_until(b'$').unwrap(), "");
	    assert_eq!(hs.at_end(), true);
	}
    }
}

pub mod unix {
    //! Convenience functions for Unix modular hashes.
    //!
    //! If it's known that a hash is in one of the supported modular hash formats,
    //! the functions in this module can be used to verify or re-calculate the
    //! hash.
    use super::{Result, consteq};
    use crate::parse::{self, HashIterator};
    use crate::error::Error;
    use crate::{bsdi_crypt, md5_crypt, bcrypt, sha1_crypt, sha256_crypt, sha512_crypt, unix_crypt};

    /// A Unix __crypt__(3) work-alike.
    pub fn crypt<B: AsRef<[u8]>>(pass: B, hash: &str) -> Result<String> {
	let mut hs = parse::HashSlice::new(hash);
	#[allow(deprecated)]
	match hs.take(1).unwrap_or("X") {
	    "_" => bsdi_crypt::hash_with(hash, pass),
	    "$" => match hs.take_until(b'$').unwrap_or("X") {
		"1" => md5_crypt::hash_with(hash, pass),
		"2a" | "2b" | "2y" => bcrypt::hash_with(hash, pass),
		"sha1" => sha1_crypt::hash_with(hash, pass),
		"5" => sha256_crypt::hash_with(hash, pass),
		"6" => sha512_crypt::hash_with(hash, pass),
		_ => Err(Error::InvalidHashString),
	    },
	    _ => unix_crypt::hash_with(hash, pass)
	}
    }

    /// Verify that the hash corresponds to a password, using hash format recognition.
    pub fn verify<B: AsRef<[u8]>>(pass: B, hash: &str) -> bool {
	consteq(hash, crypt(pass, hash))
    }

    #[cfg(test)]
    mod tests {
	#[test]
	fn crypt_recognized() {
	    assert_eq!(super::crypt("password", "$1$5pZSV9va$azfrPr6af3Fc7dLblQXVa0").unwrap(),
		"$1$5pZSV9va$azfrPr6af3Fc7dLblQXVa0");
	    assert_eq!(super::crypt("test", "aZGJuE6EXrjEE").unwrap(), "aZGJuE6EXrjEE");
	}
    }
}
