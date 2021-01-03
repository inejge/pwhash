//! SHA-512 based hash.
//
// Copyright (c) 2016 Ivan Nejgebauer <inejge@gmail.com>
//
// Licensed under the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>. This file may not be copied,
// modified, or distributed except according to the terms of this
// license.
//!
//! This algorithm was developed as an alternative to bcrypt
//! with NIST-approved hashing functions. It is similar to
//! MD5-crypt, but has a variable number of rounds and a larger
//! salt.
//!
//! # Example
//!
//! ```
//! use pwhash::sha512_crypt;
//!
//! let h =
//!     "$6$G/gkPn17kHYo0gTF$xhDFU0QYExdMH2ghOWKrrVtu1BuTpNMSJ\
//!      URCXk43.EYekmK8iwV6RNqftUUC8mqDel1J7m3JEbUkbu4YyqSyv/";
//! assert_eq!(sha512_crypt::hash_with(h, "test").unwrap(), h);
//! ```
//!
//! # Parameters
//!
//! * __Password length__: unlimited.
//!
//! * __Salt length__: 0 to 16 characters. Default is 16.
//!
//! * __Rounds__: 1000 to 999999999. Default is 5000. If a number
//! outside of the range is chosen, it is coerced to the nearest
//! limit.
//!
//! # Hash Format
//!
//! The format of the hash is
//! __`$6$rounds=`__*`{rounds}`*__$__*`{salt}`*__$__*`{checksum}`*, where:
//!
//! * *`{rounds}`* is the number of rounds, encoded as a decimal number
//!   without leading zeroes.
//!
//! * *`{salt}`* is the salt string.
//!
//! * *`{checksum}`* is a 86-character Base64 encoding of the checksum.
//!
//! The format __`$6$`__*`{salt}`*__$__*`{checksum}`* can be used if
//! the default number of rounds is chosen.

use sha2::Sha512;
use super::{Result, HashSetup, IntoHashSetup, consteq};
use crate::random;
use crate::sha2_crypt::{sha2_crypt, parse_sha2_hash, sha2_hash_with};

pub use crate::sha2_crypt::MIN_ROUNDS;
pub use crate::sha2_crypt::MAX_ROUNDS;
pub use crate::sha2_crypt::DEFAULT_ROUNDS;
pub use crate::sha2_crypt::MAX_SALT_LEN;

const SHA512_MAGIC: &str = "$6$";
const SHA512_TRANSPOSE: &[u8] = b"\x2a\x15\x00\x01\x2b\x16\x17\x02\x2c\x2d\x18\x03\x04\x2e\x19\x1a\
				  \x05\x2f\x30\x1b\x06\x07\x31\x1c\x1d\x08\x32\x33\x1e\x09\x0a\x34\
				  \x1f\x20\x0b\x35\x36\x21\x0c\x0d\x37\x22\x23\x0e\x38\x39\x24\x0f\
				  \x10\x3a\x25\x26\x11\x3b\x3c\x27\x12\x13\x3d\x28\x29\x14\x3e\x3f";

fn do_sha512_crypt(pass: &[u8], salt: &str, rounds: Option<u32>) -> Result<String> {
    sha2_crypt(pass, salt, rounds, Sha512::default, SHA512_TRANSPOSE, SHA512_MAGIC)
}

/// Hash a password with a randomly generated salt and the default
/// number of rounds.
///
/// An error is returned if the system random number generator cannot
/// be opened.
pub fn hash<B: AsRef<[u8]>>(pass: B) -> Result<String> {
    let saltstr = random::gen_salt_str(MAX_SALT_LEN);
    do_sha512_crypt(pass.as_ref(), &saltstr, None)
}

fn parse_sha512_hash(hash: &str) -> Result<HashSetup> {
    parse_sha2_hash(hash, SHA512_MAGIC)
}

/// Hash a password with user-provided parameters.
///
/// If the `param` argument is a `&str`, it must be in the final hash
/// format. The number of rounds and the salt are parsed out of that value.
/// If the salt is too long, it is truncated to maximum length. If it contains
/// an invalid character, an error is returned. An out-of-range rounds value
/// will be coerced into the allowed range.
pub fn hash_with<'a, IHS, B>(param: IHS, pass: B) -> Result<String>
    where IHS: IntoHashSetup<'a>, B: AsRef<[u8]>
{
    sha2_hash_with(IHS::into_hash_setup(param, parse_sha512_hash)?, pass.as_ref(), do_sha512_crypt)
}

/// Verify that the hash corresponds to a password.
pub fn verify<B: AsRef<[u8]>>(pass: B, hash: &str) -> bool {
    consteq(hash, hash_with(hash, pass))
}

#[cfg(test)]
mod tests {
    use super::HashSetup;

    #[test]
    fn custom() {
	assert_eq!(super::hash_with(
		   "$6$rounds=11531$G/gkPn17kHYo0gTF$Kq.uZBHlSBXyzsOJXtxJruOOH4yc0Is13\
		    uY7yK0PvAvXxbvc1w8DO1RzREMhKsc82K/Jh8OquV8FZUlreYPJk1", "test").unwrap(),
	    "$6$rounds=11531$G/gkPn17kHYo0gTF$Kq.uZBHlSBXyzsOJXtxJruOOH4yc0Is13\
	     uY7yK0PvAvXxbvc1w8DO1RzREMhKsc82K/Jh8OquV8FZUlreYPJk1");
	assert_eq!(super::hash_with(HashSetup { salt: Some("G/gkPn17kHYo0gTF"), rounds: Some(11531) }, "test").unwrap(),
	    "$6$rounds=11531$G/gkPn17kHYo0gTF$Kq.uZBHlSBXyzsOJXtxJruOOH4yc0Is13\
	     uY7yK0PvAvXxbvc1w8DO1RzREMhKsc82K/Jh8OquV8FZUlreYPJk1");
    }

    #[test]
    fn implicit_dflt_rounds() {
	assert_eq!(super::hash_with(
		   "$6$G/gkPn17kHYo0gTF$xhDFU0QYExdMH2ghOWKrrVtu1BuTpNMSJURCXk43.\
		    EYekmK8iwV6RNqftUUC8mqDel1J7m3JEbUkbu4YyqSyv/", "test").unwrap(),
	    "$6$G/gkPn17kHYo0gTF$xhDFU0QYExdMH2ghOWKrrVtu1BuTpNMSJURCXk43.\
	     EYekmK8iwV6RNqftUUC8mqDel1J7m3JEbUkbu4YyqSyv/");
    }
}
