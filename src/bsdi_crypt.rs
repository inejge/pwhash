//! Enhanced DES-based hash.
//
// Copyright (c) 2016 Ivan Nejgebauer <inejge@gmail.com>
//
// Licensed under the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>. This file may not be copied,
// modified, or distributed except according to the terms of this
// license.
//!
//! This algorithm was developed by BSDi for BSD/OS as an extension of
//! the traditional Unix __crypt__(3). It supports longer passwords, larger
//! salt, and a variable number of rounds. Despite that, the algorithm
//! is considered weak and is not recommended for new passwords.
//!
//! # Example
//!
//! ```
//! use pwhash::{bsdi_crypt, HashSetup};
//!
//! assert_eq!(bsdi_crypt::hash_with(
//!         HashSetup { salt: Some("K0Ay"), rounds: Some(7250) },
//!         "password").unwrap(),
//!     "_Gl/.K0Ay.aosctsbJ1k");
//! ```
//!
//! # Parameters
//!
//! * __Password length__: unlimited.
//!
//! * __Salt length__: 4 characters (24 bits).
//!
//! * __Rounds__: 1 to 2<sup>24</sup>-1. Default is 7250.
//!
//! # Hash Format
//!
//! The format of the hash is __`_`__*`{rounds}{salt}{checksum}`*, where:
//!
//! * *`{rounds}`* is a 4-character Base64 encoding of the number of rounds.
//!
//! * *`{salt}`* is a 4-character Base64 encoding of the salt.
//!
//! * *`{checksum}`* is a 11-character Base64 encoding of the checksum.

use super::{Result, HashSetup, IntoHashSetup, consteq};
use des_crypt::bsdi_crypt;
use enc_dec::decode_val;
use error::Error;
use random;
use parse::{self, HashIterator};

const MIN_ROUNDS: u32 = 1;
const MAX_ROUNDS: u32 = (1 << 24) - 1;
/// Default number of rounds.
///
/// The value is aligned with the default used on NetBSD.
pub const DEFAULT_ROUNDS: u32 = 7250;
/// Salt length.
pub const SALT_LEN: usize = 4;
const ROUNDS_LEN: usize = 4;

/// Hash a password with a randomly generated salt and the default
/// number of rounds.
///
/// An error is returned if the system random number generator cannot
/// be opened.
pub fn hash(pass: &str) -> Result<String> {
    let saltstr = try!(random::gen_salt_str(SALT_LEN));
    bsdi_crypt(pass, &saltstr, DEFAULT_ROUNDS)
}

fn parse_bsdi_hash(hash: &str) -> Result<HashSetup> {
    let mut hs = parse::HashSlice::new(hash);
    if hs.take(1).unwrap_or("X") != "_" {
        return Err(Error::InvalidHashString);
    }
    let rounds = if let Some(rounds_enc) = hs.take(ROUNDS_LEN) {
        try!(decode_val(rounds_enc, SALT_LEN))
    } else {
        return Err(Error::InvalidHashString);
    };
    let salt = if let Some(salt) = hs.take(SALT_LEN) {
        salt
    } else {
        return Err(Error::InvalidHashString);
    };
    Ok(HashSetup {
           salt: Some(salt),
           rounds: Some(rounds),
       })
}

/// Hash a password with user-provided parameters.
///
/// If the `param` argument is a `&str`, it must be in the final hash
/// format. The number of rounds and the salt are parsed out of that value.
/// An error is returned if the salt is too short or contains an invalid
/// character. An out-of-range rounds value will also result in an error.
pub fn hash_with<'a, IHS>(param: IHS, pass: &str) -> Result<String>
    where IHS: IntoHashSetup<'a>
{
    let hs = try!(IHS::into_hash_setup(param, parse_bsdi_hash));
    let rounds = if let Some(r) = hs.rounds {
        if r < MIN_ROUNDS || r > MAX_ROUNDS {
            return Err(Error::InvalidRounds);
        }
        r
    } else {
        DEFAULT_ROUNDS
    };
    if hs.salt.is_some() {
        bsdi_crypt(pass, hs.salt.unwrap(), rounds)
    } else {
        let saltstr = try!(random::gen_salt_str(SALT_LEN));
        bsdi_crypt(pass, &saltstr, rounds)
    }
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
        assert_eq!(super::hash_with(HashSetup {
                                        salt: Some("K0Ay"),
                                        rounds: None,
                                    },
                                    "password")
                           .unwrap(),
                   "_Gl/.K0Ay.aosctsbJ1k");
        assert_eq!(super::hash_with("_Gl/.K0Ay.aosctsbJ1k", "password").unwrap(),
                   "_Gl/.K0Ay.aosctsbJ1k");
    }

    #[test]
    #[should_panic(expected="value: InvalidRounds")]
    fn bad_rounds() {
        let _ = super::hash_with(HashSetup {
                                     salt: Some("K0Ay"),
                                     rounds: Some(0),
                                 },
                                 "password")
                .unwrap();
    }
}
