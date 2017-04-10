//! MD5 based hash.
//
// Copyright (c) 2016 Ivan Nejgebauer <inejge@gmail.com>
//
// Licensed under the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>. This file may not be copied,
// modified, or distributed except according to the terms of this
// license.
//!
//! This algorithm was developed for FreeBSD to replace the
//! aging DES crypt. It was adopted in various Linux distributions
//! and saw wide use. Presently, it's considered insecure and
//! shouldn't be used for new passwords.
//!
//! # Example
//!
//! ```
//! use pwhash::md5_crypt;
//!
//! assert_eq!(md5_crypt::hash_with(
//!     "$1$5pZSV9va$azfrPr6af3Fc7dLblQXVa0",
//!     "password").unwrap(),
//!     "$1$5pZSV9va$azfrPr6af3Fc7dLblQXVa0");
//! ```
//!
//! # Parameters
//!
//! * __Password length__: unlimited.
//!
//! * __Salt length__: 0 to 8 characters. Default is 8.
//!
//! * __Rounds__: 1000 (fixed.)
//!
//! # Hash Format
//!
//! The format of the hash is
//! __`$1$`__*`{salt}`*__$__*`{checksum}`*, where:
//!
//! * *`{salt}`* is the salt string.
//!
//! * *`{checksum}`* is a 22-character Base64 encoding of the checksum.

use crypto::md5::Md5;
use crypto::digest::Digest;
use super::{Result, HashSetup, IntoHashSetup, consteq};
use error::Error;
use random;
use parse::{self, HashIterator};
use enc_dec::{md5_sha2_hash64_encode, bcrypt_hash64_decode};
use std::cmp::min;

/// Maximium salt length.
pub const MAX_SALT_LEN: usize = 8;
const MD5_MAGIC: &'static str = "$1$";
const MD5_TRANSPOSE: &'static [u8] =
    b"\x0c\x06\x00\x0d\x07\x01\x0e\x08\x02\x0f\x09\x03\x05\x0a\x04\x0b";

fn do_md5_crypt(pass: &str, salt: &str) -> Result<String> {
    let mut dummy_buf = [0u8; 6];
    try!(bcrypt_hash64_decode(salt, &mut dummy_buf));

    let mut dgst_b = Md5::new();
    let mut hash_b = [0u8; 16];
    dgst_b.input(pass.as_bytes());
    dgst_b.input(salt.as_bytes());
    dgst_b.input(pass.as_bytes());
    dgst_b.result(&mut hash_b);

    let mut dgst_a = Md5::new();
    let mut hash_a = [0u8; 16];
    dgst_a.input(pass.as_bytes());
    dgst_a.input(MD5_MAGIC.as_bytes());
    dgst_a.input(salt.as_bytes());

    let mut plen = pass.as_bytes().len();
    while plen > 0 {
        dgst_a.input(&hash_b[..min(plen, 16)]);
        if plen < 16 {
            break;
        }
        plen -= 16;
    }

    plen = pass.as_bytes().len();
    while plen > 0 {
        match plen & 1 {
            0 => dgst_a.input(&pass.as_bytes()[..1]),
            1 => dgst_a.input(&[0u8]),
            _ => unreachable!(),
        }
        plen >>= 1;
    }

    dgst_a.result(&mut hash_a);

    for r in 0..1000 {
        dgst_a.reset();
        if r % 2 == 1 {
            dgst_a.input(pass.as_bytes());
        } else {
            dgst_a.input(&hash_a);
        }
        if r % 3 > 0 {
            dgst_a.input(salt.as_bytes());
        }
        if r % 7 > 0 {
            dgst_a.input(pass.as_bytes());
        }
        if r % 2 == 0 {
            dgst_a.input(pass.as_bytes());
        } else {
            dgst_a.input(&hash_a);
        }
        dgst_a.result(&mut hash_a);
    }

    for (i, &ti) in MD5_TRANSPOSE.iter().enumerate() {
        hash_b[i] = hash_a[ti as usize];
    }
    Ok(format!("{}{}${}", MD5_MAGIC, salt, md5_sha2_hash64_encode(&hash_b)))
}

/// Hash a password with a randomly generated salt.
///
/// An error is returned if the system random number generator cannot
/// be opened.
pub fn hash(pass: &str) -> Result<String> {
    let saltstr = try!(random::gen_salt_str(MAX_SALT_LEN));
    do_md5_crypt(pass, &saltstr)
}

const MAGIC_LEN: usize = 3;

fn parse_md5_hash(hash: &str) -> Result<HashSetup> {
    let mut hs = parse::HashSlice::new(hash);
    if hs.take(MAGIC_LEN).unwrap_or("X") != MD5_MAGIC {
        return Err(Error::InvalidHashString);
    }
    let salt = if let Some(salt) = hs.take_until(b'$') {
        salt
    } else {
        return Err(Error::InvalidHashString);
    };
    Ok(HashSetup {
           salt: Some(salt),
           rounds: None,
       })
}

/// Hash a password with user-provided parameters.
///
/// If the `param` argument is a `&str`, it must be in the final hash
/// format. The salt is parsed out of that value.
/// If the salt is too long, it is truncated to maximum length. If it contains
/// an invalid character, an error is returned.
pub fn hash_with<'a, IHS>(param: IHS, pass: &str) -> Result<String>
    where IHS: IntoHashSetup<'a>
{
    let hs = try!(IHS::into_hash_setup(param, parse_md5_hash));
    if let Some(salt) = hs.salt {
        let salt = if salt.len() <= MAX_SALT_LEN {
            salt
        } else if let Some(truncated_salt) =
            parse::HashSlice::new(salt).take(MAX_SALT_LEN) {
            truncated_salt
        } else {
            return Err(Error::InvalidHashString);
        };
        do_md5_crypt(pass, salt)
    } else {
        let salt = try!(random::gen_salt_str(MAX_SALT_LEN));
        do_md5_crypt(pass, &salt)
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
        assert_eq!(super::hash_with("$1$5pZSV9va$azfrPr6af3Fc7dLblQXVa0", "password").unwrap(),
                   "$1$5pZSV9va$azfrPr6af3Fc7dLblQXVa0");
        assert_eq!(super::hash_with(HashSetup {
                                        salt: Some("5pZSV9va"),
                                        rounds: None,
                                    },
                                    "password")
                           .unwrap(),
                   "$1$5pZSV9va$azfrPr6af3Fc7dLblQXVa0");
    }
}
