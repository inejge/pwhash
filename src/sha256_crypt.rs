//! SHA-256 based hash.
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
//! use pwhash::sha256_crypt;
//!
//! let h = "$5$rounds=11858$WH1ABM5sKhxbkgCK$\
//!          aTQsjPkz0rBsH3lQlJxw9HDTDXPKBxC0LlVeV69P.t1";
//! assert_eq!(sha256_crypt::hash_with(h, "test").unwrap(), h);
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
//! __`$5$rounds=`__*`{rounds}`*__$__*`{salt}`*__$__*`{checksum}`*, where:
//!
//! * *`{rounds}`* is the number of rounds, encoded as a decimal number
//!   without leading zeroes.
//!
//! * *`{salt}`* is the salt string.
//!
//! * *`{checksum}`* is a 43-character Base64 encoding of the checksum.
//!
//! The format __`$5$`__*`{salt}`*__$__*`{checksum}`* can be used if
//! the default number of rounds is chosen.

use crypto::sha2::Sha256;
use super::{Result, HashSetup, IntoHashSetup, consteq};
use random;
use sha2_crypt::{sha2_crypt, parse_sha2_hash, sha2_hash_with};

pub use sha2_crypt::MIN_ROUNDS;
pub use sha2_crypt::MAX_ROUNDS;
pub use sha2_crypt::DEFAULT_ROUNDS;
pub use sha2_crypt::MAX_SALT_LEN;

const SHA256_MAGIC: &'static str = "$5$";
const SHA256_TRANSPOSE: &'static [u8] =
    b"\x14\x0a\x00\x0b\x01\x15\x02\x16\x0c\x17\x0d\x03\x0e\x04\x18\x05\
					  \x19\x0f\x1a\x10\x06\x11\x07\x1b\x08\x1c\x12\x1d\x13\x09\x1e\x1f";

fn do_sha256_crypt(pass: &str, salt: &str, rounds: Option<u32>) -> Result<String> {
    sha2_crypt(pass,
               salt,
               rounds,
               Sha256::new,
               SHA256_TRANSPOSE,
               SHA256_MAGIC)
}

/// Hash a password with a randomly generated salt and the default
/// number of rounds.
///
/// An error is returned if the system random number generator cannot
/// be opened.
pub fn hash(pass: &str) -> Result<String> {
    let saltstr = try!(random::gen_salt_str(MAX_SALT_LEN));
    do_sha256_crypt(pass, &saltstr, None)
}

fn parse_sha256_hash(hash: &str) -> Result<HashSetup> {
    parse_sha2_hash(hash, SHA256_MAGIC)
}

/// Hash a password with user-provided parameters.
///
/// If the `param` argument is a `&str`, it must be in the final hash
/// format. The number of rounds and the salt are parsed out of that value.
/// If the salt is too long, it is truncated to maximum length. If it contains
/// an invalid character, an error is returned. An out-of-range rounds value
/// will be coerced into the allowed range.
pub fn hash_with<'a, IHS>(param: IHS, pass: &str) -> Result<String>
    where IHS: IntoHashSetup<'a>
{
    sha2_hash_with(try!(IHS::into_hash_setup(param, parse_sha256_hash)),
                   pass,
                   do_sha256_crypt)
}

/// Verify that the hash corresponds to a password.
pub fn verify(pass: &str, hash: &str) -> bool {
    consteq(hash, hash_with(hash, pass))
}

#[cfg(test)]
mod tests {
    use HashSetup;

    #[test]
    fn custom() {
        assert_eq!(super::hash_with(
		   "$5$rounds=11858$WH1ABM5sKhxbkgCK$aTQsjPkz0rBsH3lQlJxw9HDTDXPKBxC0LlVeV69P.t1", "test")
            .unwrap(),
	    "$5$rounds=11858$WH1ABM5sKhxbkgCK$aTQsjPkz0rBsH3lQlJxw9HDTDXPKBxC0LlVeV69P.t1");
        assert_eq!(super::hash_with(HashSetup {
                                        salt: Some("WH1ABM5sKhxbkgCK"),
                                        rounds: Some(11858),
                                    },
                                    "test")
                           .unwrap(),
                   "$5$rounds=11858$WH1ABM5sKhxbkgCK$aTQsjPkz0rBsH3lQlJxw9HDTDXPKBxC0LlVeV69P.t1");
    }

    #[test]
    fn implicit_dflt_rounds() {
        assert_eq!(super::hash_with(
		   "$5$WH1ABM5sKhxbkgCK$sOnTVjQn1Y3EWibd8gWqqJqjH.KaFrxJE5rijqxcPp7", "test").unwrap(),
	    "$5$WH1ABM5sKhxbkgCK$sOnTVjQn1Y3EWibd8gWqqJqjH.KaFrxJE5rijqxcPp7");
    }
}
