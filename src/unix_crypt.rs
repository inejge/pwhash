//! Seventh Edition Unix DES-based hash.
//
// Copyright (c) 2016 Ivan Nejgebauer <inejge@gmail.com>
//
// Licensed under the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>. This file may not be copied,
// modified, or distributed except according to the terms of this
// license.
//!
//! The original Unix password-hashing algorithm, extremely weak by
//! today's standards. It should be used for backward compatibility only.
//!
//! # Example
//!
//! ```
//! use pwhash::unix_crypt;
//!
//! assert_eq!(unix_crypt::hash_with("xO",
//!     "password").unwrap(), "xOAFZqRz5RduI");
//! assert_eq!(unix_crypt::verify("password","xOAFZqRz5RduI"),
//!     true);
//!
//! ```
//!
//! # Parameters
//!
//! * __Password length__: effectively eight 7-bit characters; anything
//! longer is ignored.
//!
//! * __Salt length__: 2 characters (12 bits).
//!
//! * __Rounds__: 25 (fixed).
//!
//! # Hash Format
//!
//! The format of the hash is *`{salt}`*_`{checksum}`_, where:
//!
//! * *`{salt}`* is a 2-character Base64 encoding of the salt.
//!
//! * *`{checksum}`* is a 11-character Base64 encoding of the checksum.

use super::{Result, consteq};
use des_crypt::unix_crypt;
use random;

/// Salt length.
pub const SALT_LEN: usize = 2;

/// Hash a password with a randomly generated salt.
///
/// An error is returned if the system random number generator cannot
/// be opened.
pub fn hash(pass: &str) -> Result<String> {
    let saltstr = try!(random::gen_salt_str(SALT_LEN));
    unix_crypt(pass, &saltstr)
}

/// Hash a password with a user-provided salt.
///
/// An error is returned if the salt is too short or contains an invalid
/// character.
pub fn hash_with(salt: &str, pass: &str) -> Result<String> {
    unix_crypt(pass, salt)
}

/// Verify that the hash corresponds to a password.
pub fn verify(pass: &str, hash: &str) -> bool {
    consteq(hash, unix_crypt(pass, hash))
}

#[cfg(test)]
mod tests {
    #[test]
    fn custom() {
        assert_eq!("aZGJuE6EXrjEE", super::hash_with("aZ", "test").unwrap());
        assert_eq!(super::verify("test", "aZGJuE6EXrjEE"), true);
        assert_eq!(super::verify("test", "aZFJuE6EXrjEE"), false);
        assert_eq!(super::verify("test", "!!"), false);
    }

    #[test]
    #[should_panic(expected="value: EncodingError")]
    fn bad_salt_chars() {
        let _ = super::hash_with("!!", "test").unwrap();
    }

    #[test]
    #[should_panic(expected="value: InsufficientLength")]
    fn short_salt() {
        let _ = super::hash_with("Z", "test").unwrap();
    }
}
