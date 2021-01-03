//! Standard *BSD hash.
//
// Copyright (c) 2016 Ivan Nejgebauer <inejge@gmail.com>
//
// Licensed under the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>. This file may not be copied,
// modified, or distributed except according to the terms of this
// license.
//!
//! Bcrypt is a hashing algorithm based on the Blowfish stream cipher,
//! originally developed for OpenBSD and since adopted on other BSD
//! variants and other systems. It has a large salt, variable number
//! of rounds, and no known weaknesses.
//!
//! # Examples
//!
//! To hash a password with a randomly generated salt, default cost,
//! and default output variant (__2b__):
//!
//! ```
//! use pwhash::bcrypt;
//!
//! let hash = bcrypt::hash("password").unwrap();
//! ```
//!
//! To use a different variant (__2y__), while letting the program
//! pick the salt and use the default cost:
//!
//! ```
//! use pwhash::bcrypt::{self, BcryptSetup, BcryptVariant};
//!
//! let hash = bcrypt::hash_with(BcryptSetup {
//!                variant: Some(BcryptVariant::V2y),
//!                ..Default::default() },
//!            "password").unwrap();
//! ```
//!
//! # Parameters
//!
//! * __Password length__: up to 72 characters. Longer passwords are
//! truncated to the maximum length.
//!
//! * __Salt length__: 16 random bytes, encoded as 22 Base64 characters.
//!
//! * __Cost__: logarithmic value between 4 and 31, inclusive. Increasing
//! the value by 1 doubles the amount of work. The default is 8.
//!
//! # Hash Format
//!
//! The format of the hash is
//! **`$`**_`{variant}`_**`$`**_`{cost}`_**`$`**_`{salt}{checksum}`_, where:
//!
//! * _`{variant}`_ is one of **2a**, **2b**, or **2y**. The default is **2b**.
//! The actual computation is the same for all three variants; the choice
//! exists in order to retain compatibility with other software. See
//! [`BcryptVariant`](enum.BcryptVariant.html) for details.
//!
//! * _`{cost}`_ is a two-digit decimal cost value between 4 and 31. Values
//! below 10 have a leading zero.
//!
//! * _`{salt}`_ is a 22-character Base64 encoding of the 16 bytes of salt. The
//! salt must be exactly this long.
//!
//! * _`{checksum}`_ is a 31-character Base64 encoding of the computed hash.

use super::{Result, HashSetup, consteq};
use crate::enc_dec::{bcrypt_hash64_encode,bcrypt_hash64_decode};
use crate::error::Error;
use crate::random;
use crate::parse::{self, HashIterator};
use std::{iter, fmt};
use std::cmp::min;
use std::default::Default;
use blowfish::Blowfish;
use byteorder::{BE, ByteOrder};

const MAX_PASS_LEN: usize = 72;
const DEFAULT_VARIANT: BcryptVariant = BcryptVariant::V2b;
const ENC_SALT_LEN: usize = 22;
/// Minimum cost.
pub const MIN_COST: u32 = 4;
/// Maximum cost.
pub const MAX_COST: u32 = 31;
/// Default cost.
pub const DEFAULT_COST: u32 = 10;

/// Identifiers of algorithm variants which can be produced.
///
/// Bcrypt has a long history of use, during which a number bugs were found
/// and fixed in the widely-used implementations. Some bugs were serious
/// enough to warrant a change in the minor version number of the algorithm
/// identifier.
///
/// There are two major bcrypt implementations: OpenBSD (the original, used in
/// all *BSDs) and Openwall. A short history of variants is as follows:
///
/// * **2** is the original OpenBSD version, which was very quickly replaced by
///
/// * **2a**, which fixed a bug that caused passwords with repeated strings to
/// produce the same hash as those with a single string ("abab" hashed the same
/// as "ab".) This was the most widely used version, until
///
/// * **2y**, produced by Openwall, which fixed a sign-extension bug that
/// caused certain passwords with high-bit-set characters to produce weak keys.
/// OpenBSD didn't have this bug, and their logic can transparently handle the
/// **2y** hashes. The Openwall fix also introduced
///
/// * **2x**, meant for unambiguously identifying pre-fix **2a** hashes as
/// those produced by the buggy algorithm. OpenBSD doesn't treat **2x** hashes
/// specially, which means that it won't be able to verify buggy hashes. Some
/// time later, a wraparound bug was found in OpenBSD, leading to
///
/// * **2b**, which fixed the bug. As the problem involved unrealistically long
/// passwords, the bug was, fortunately, mostly theoretical. This variant is the
/// current default in most implementations.
///
/// This crate has a single bcrypt algorithm implementation which is equivalent
/// to the **2b** variant. It accepts **2a** and **2y** on input, and can
/// generate both on output, but doesn't treat them specially in any way.
pub enum BcryptVariant {
    /// Second OpenBSD variant, fixed repeated string hashing.
    V2a,
    /// Third OpenBSD variant, fixed a wraparound bug.
    V2b,
    /// Openwall variant, fixed a sign extension bug.
    V2y,
}

impl fmt::Display for BcryptVariant {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
	write!(f, "{}", match *self {
	    BcryptVariant::V2a => "2a",
	    BcryptVariant::V2b => "2b",
	    BcryptVariant::V2y => "2y",
	})
    }
}

/// Setup struct for bcrypt.
///
/// In addition to custom salt and cost values, a bcrypt hash can use different
/// algorithm variant identifiers.
pub struct BcryptSetup<'a> {
    /// Custom salt.
    pub salt: Option<&'a str>,
    /// Custom cost.
    pub cost: Option<u32>,
    /// Algorithm variant.
    pub variant: Option<BcryptVariant>,
}

/// A trait for converting a type into a `BcryptSetup` struct.
pub trait IntoBcryptSetup<'a> {
    /// The conversion function.
    fn into_bcrypt_setup(self) -> Result<BcryptSetup<'a>>;
}

const MAGIC_LEN: usize = 4;

impl<'a> IntoBcryptSetup<'a> for &'a str {
    fn into_bcrypt_setup(self) -> Result<BcryptSetup<'a>> {
	let mut hs = parse::HashSlice::new(self);
	let variant = match hs.take(MAGIC_LEN).unwrap_or("X") {
	    "$2a$" => BcryptVariant::V2a,
	    "$2b$" => BcryptVariant::V2b,
	    "$2y$" => BcryptVariant::V2y,
	    _ => return Err(Error::InvalidHashString),
	};
	let cost = if let Some(cost_str) = hs.take_until(b'$') {
	    if cost_str.len() != 2 {
		return Err(Error::InvalidHashString);
	    }
	    let cost = cost_str.parse::<u32>().map_err(|_e| Error::InvalidRounds)?;
	    if cost < 10 && !cost_str.starts_with('0') {
		return Err(Error::InvalidHashString);
	    }
	    cost
	} else {
	    return Err(Error::InvalidHashString);
	};
	let salt = if let Some(salt) = hs.take(ENC_SALT_LEN) {
	    salt
	} else {
	    return Err(Error::InvalidHashString);
	};
	Ok(BcryptSetup { salt: Some(salt), cost: Some(cost), variant: Some(variant) })
    }
}

impl<'a> IntoBcryptSetup<'a> for HashSetup<'a> {
    fn into_bcrypt_setup(self) -> Result<BcryptSetup<'a>> {
	Ok(BcryptSetup { salt: self.salt, cost: self.rounds, variant: Some(DEFAULT_VARIANT) })
    }
}

impl<'a> IntoBcryptSetup<'a> for BcryptSetup<'a> {
    fn into_bcrypt_setup(self) -> Result<BcryptSetup<'a>> {
	Ok(self)
    }
}

impl<'a> Default for BcryptSetup<'a> {
    fn default() -> Self {
	BcryptSetup { salt: None, cost: Some(DEFAULT_COST), variant: Some(DEFAULT_VARIANT) }
    }
}

fn bcrypt(cost: u32, salt: &[u8], password: &[u8], output: &mut [u8]) {
    assert!(cost < 32);
    assert!(salt.len() == 16);
    assert!(password.len() <= 72 && !password.is_empty());
    assert!(output.len() == 24);

    let mut state = Blowfish::bc_init_state();

    state.salted_expand_key(salt, password);
    for _ in 0..1u32 << cost {
        state.bc_expand_key(password);
        state.bc_expand_key(salt);
    }

    let mut ctext = [0x4f727068, 0x65616e42, 0x65686f6c, 0x64657253, 0x63727944, 0x6f756274];
    for i in (0..6).step_by(2) {
        for _ in 0..64 {
            let (l, r) = state.bc_encrypt(ctext[i], ctext[i+1]);
            ctext[i] = l;
            ctext[i+1] = r;
        }
        BE::write_u32(&mut output[i*4..(i+1)*4], ctext[i]);
        BE::write_u32(&mut output[(i+1)*4..(i+2)*4], ctext[i+1]);
    }
}

fn do_bcrypt(pass: &[u8], salt: &[u8], cost: u32, variant: BcryptVariant) -> Result<String> {
    let mut upd_pass = pass.iter().copied().chain(iter::repeat(0u8)).take(min(pass.len() + 1, MAX_PASS_LEN)).collect::<Vec<_>>();
    let mut output = [0u8; 24];
    bcrypt(cost, &salt, &upd_pass[..], &mut output);
    for b in &mut upd_pass {
	*b = 0u8;
    }
    Ok(format!("${}${:02}${}{}", variant, cost,
	bcrypt_hash64_encode(&salt), bcrypt_hash64_encode(&output[..23])))
}

/// Hash a password with a randomly generated salt, default cost,
/// and default variant.
///
/// An error is returned if the system random number generator cannot
/// be opened.
pub fn hash<B: AsRef<[u8]>>(pass: B) -> Result<String> {
    let mut salt_buf = [0u8; 16];
    random::gen_salt_bytes(&mut salt_buf);
    do_bcrypt(pass.as_ref(), &salt_buf, DEFAULT_COST, DEFAULT_VARIANT)
}

/// Hash a password with user-provided parameters.
///
/// Bcrypt has its own setup struct because of the additional variant
/// field. An ordinary `HashSetup` can be converted into `BcryptSetup`, which
/// will set the variant to default. The `Default` trait is implemented for
/// `BcryptSetup`, which makes it easier to initialize just the desired
/// fields (see the module-level example.)
pub fn hash_with<'a, IBS, B>(param: IBS, pass: B) -> Result<String>
    where IBS: IntoBcryptSetup<'a>, B: AsRef<[u8]>
{
    let bs = param.into_bcrypt_setup()?;
    let cost = if let Some(c) = bs.cost {
	if c < MIN_COST || c > MAX_COST {
	    return Err(Error::InvalidRounds);
	}
	c
    } else { DEFAULT_COST };
    let variant = if let Some(v) = bs.variant {
	v
    } else { DEFAULT_VARIANT };
    let mut salt_buf = [0u8; 16];
    if bs.salt.is_some() {
	bcrypt_hash64_decode(bs.salt.unwrap(), &mut salt_buf)?;
    } else {
	random::gen_salt_bytes(&mut salt_buf);
    }
    do_bcrypt(pass.as_ref(), &salt_buf, cost, variant)
}

/// Verify that the hash corresponds to a password.
pub fn verify<B: AsRef<[u8]>>(pass: B, hash: &str) -> bool {
    consteq(hash, hash_with(hash, pass))
}

#[cfg(test)]
mod tests {
    use super::{BcryptSetup, BcryptVariant};

    #[test]
    fn variant() {
	assert_eq!("$2y$05$bvIG6Nmid91Mu9RcmmWZfO5HJIMCT8riNW0hEp8f6/FuA2/mHZFpe",
	    super::hash_with(BcryptSetup { salt: Some("bvIG6Nmid91Mu9RcmmWZfO"), cost: Some(5),
		variant: Some(BcryptVariant::V2y) },
	    "password").unwrap());
    }
}
