//! HMAC-SHA1 based hash.
//
// Copyright (c) 2016 Ivan Nejgebauer <inejge@gmail.com>
//
// Licensed under the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>. This file may not be copied,
// modified, or distributed except according to the terms of this
// license.
//!
//! This algorithm was developed for NetBSD. It's a modern
//! algorithm with a large salt and a variable number of rounds.
//! Although the SHA-1 hash, on which it's based, is considered
//! insecure and is being phased out in the PKI environment, its
//! use in a HMAC setup, as is the case here, is still acceptable.
//!
//! # Example
//!
//! ```
//! use pwhash::sha1_crypt;
//!
//! assert_eq!(sha1_crypt::hash_with(
//!     "$sha1$19703$iVdJqfSE$v4qYKl1zqYThwpjJAoKX6UvlHq/a",
//!     "password").unwrap(),
//!     "$sha1$19703$iVdJqfSE$v4qYKl1zqYThwpjJAoKX6UvlHq/a");
//! ```
//!
//! # Parameters
//!
//! * __Password length__: unlimited.
//!
//! * __Salt length__: 0 to 64 characters. Default is 8.
//!
//! * __Rounds__: 1 to 2<sup>32</sup>-1. Default is 24680, which
//! is slightly varied if chosen.
//!
//! # Hash Format
//!
//! The format of the hash is
//! __`$sha1$`__*`{rounds}`*__$__*`{salt}`*__$__*`{checksum}`*, where:
//!
//! * *`{rounds}`* is the number of rounds, encoded as a decimal number
//!   without leading zeroes.
//!
//! * *`{salt}`* is the salt string.
//!
//! * *`{checksum}`* is a 28-character Base64 encoding of the checksum.

use hmac::{Hmac, Mac, NewMac};
use sha1::Sha1;
use super::{Result, HashSetup, IntoHashSetup, consteq};
use crate::enc_dec::{sha1crypt_hash64_encode, bcrypt_hash64_decode};
use crate::error::Error;
use crate::random;
use crate::parse::{self, HashIterator};

const MIN_ROUNDS: u32 = 1;
/// Default number of rounds.
///
/// The value is aligned with the default used on NetBSD.
pub const DEFAULT_ROUNDS: u32 = 24680;
const MAX_SALT_LEN: usize = 64;
/// Default salt length.
pub const DEFAULT_SALT_LEN: usize = 8;

fn do_sha1_crypt(pass: &[u8], salt: &str, rounds: u32) -> Result<String> {
    let mut dummy_buf = [0u8; 48];
    bcrypt_hash64_decode(salt, &mut dummy_buf)?;
    let mut hmac = Hmac::<Sha1>::new_varkey(pass).map_err(|_| Error::InsufficientLength)?;
    hmac.update(format!("{}$sha1${}", salt, rounds).as_bytes());
    let mut result = hmac.finalize();
    for _ in 1..rounds {
        let mut hmac = Hmac::<Sha1>::new_varkey(pass).map_err(|_| Error::InsufficientLength)?;
        hmac.update(&result.into_bytes());
        result = hmac.finalize();
    }
    Ok(format!("$sha1${}${}${}", rounds, salt, sha1crypt_hash64_encode(&result.into_bytes())))
}

/// Hash a password with a randomly generated salt and the default
/// number of rounds (varied by a small amount, like on NetBSD).
///
/// An error is returned if the system random number generator cannot
/// be opened.
pub fn hash<B: AsRef<[u8]>>(pass: B) -> Result<String> {
    let saltstr = random::gen_salt_str(DEFAULT_SALT_LEN);
    do_sha1_crypt(pass.as_ref(), &saltstr, random::vary_rounds(DEFAULT_ROUNDS))
}

const MAGIC_LEN: usize = 6;

fn parse_sha1_hash(hash: &str) -> Result<HashSetup> {
    let mut hs = parse::HashSlice::new(hash);
    if hs.take(MAGIC_LEN).unwrap_or("X") != "$sha1$" {
	return Err(Error::InvalidHashString);
    }
    let rounds = if let Some(rounds_str) = hs.take_until(b'$') {
	rounds_str.parse::<u32>().map_err(|_e| Error::InvalidRounds)?
    } else {
	return Err(Error::InvalidHashString);
    };
    let salt = if let Some(salt) = hs.take_until(b'$') {
	salt
    } else {
	return Err(Error::InvalidHashString);
    };
    Ok(HashSetup { salt: Some(salt), rounds: Some(rounds) })
}

/// Hash a password with user-provided parameters.
///
/// If the `param` argument is a `&str`, it must be in the final hash
/// format. The number of iterations (rounds) and the salt are parsed out
/// of that value.
/// If the salt is too long, it is truncated to maximum length. If it contains
/// an invalid character, an error is returned. An out-of-range rounds value
/// will also result in an error.
pub fn hash_with<'a, IHS, B>(param: IHS, pass: B) -> Result<String>
    where IHS: IntoHashSetup<'a>, B: AsRef<[u8]>
{
    let hs = IHS::into_hash_setup(param, parse_sha1_hash)?;
    let rounds = if let Some(r) = hs.rounds {
	if r < MIN_ROUNDS {
	    return Err(Error::InvalidRounds);
	}
	r
    } else { random::vary_rounds(DEFAULT_ROUNDS) };
    if let Some(salt) = hs.salt {
	let salt = if salt.len() <= MAX_SALT_LEN {
	    salt
	} else if let Some(truncated_salt) = parse::HashSlice::new(salt).take(MAX_SALT_LEN) {
	    truncated_salt
	} else {
	    return Err(Error::InvalidHashString);
	};
	do_sha1_crypt(pass.as_ref(), salt, rounds)
    } else {
	let salt = random::gen_salt_str(DEFAULT_SALT_LEN);
	do_sha1_crypt(pass.as_ref(), &salt, rounds)
    }
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
	assert_eq!(super::hash_with("$sha1$19703$iVdJqfSE$v4qYKl1zqYThwpjJAoKX6UvlHq/a", "password").unwrap(),
	    "$sha1$19703$iVdJqfSE$v4qYKl1zqYThwpjJAoKX6UvlHq/a");
	assert_eq!(super::hash_with(HashSetup { salt: Some("iVdJqfSE"), rounds: Some(19703) }, "password").unwrap(),
	    "$sha1$19703$iVdJqfSE$v4qYKl1zqYThwpjJAoKX6UvlHq/a");
    }

    #[test]
    #[should_panic(expected="value: InvalidRounds")]
    fn bad_rounds() {
	let _ = super::hash_with(HashSetup { salt: Some("K0Ay"), rounds: Some(0) }, "password").unwrap();
    }
}
