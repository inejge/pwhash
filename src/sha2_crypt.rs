// Common routines for SHA-2 hashing.
//
// Copyright (c) 2016 Ivan Nejgebauer <inejge@gmail.com>
//
// Licensed under the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>. This file may not be copied,
// modified, or distributed except according to the terms of this
// license.

use std::cmp::min;
use sha2::Digest;
use crate::enc_dec::{md5_sha2_hash64_encode, bcrypt_hash64_decode};
use super::{Result, HashSetup};
use crate::error::Error;
use crate::parse::{self, HashIterator};
use crate::random;

/// Minimum rounds.
pub const MIN_ROUNDS: u32 = 1000;
/// Maximum rounds.
pub const MAX_ROUNDS: u32 = 999999999;
/// Default number of rounds.
pub const DEFAULT_ROUNDS: u32 = 5000;
/// Maximum (and default) salt length.
pub const MAX_SALT_LEN: usize = 16;

pub fn sha2_crypt<D: Digest>(pass: &[u8], salt: &str, rounds: Option<u32>,
			     new_digest: fn() -> D, trn_table: &[u8],
			     magic: &str) -> Result<String> {
    let mut dummy_buf = [0u8; 12];
    bcrypt_hash64_decode(salt, &mut dummy_buf)?;

    let mut dgst_b = new_digest();
    let dsize = D::output_size();
    dgst_b.update(pass);
    dgst_b.update(salt.as_bytes());
    dgst_b.update(pass);
    let mut hash_b = dgst_b.finalize();

    let mut dgst_a = new_digest();
    dgst_a.update(pass);
    dgst_a.update(salt.as_bytes());

    let plen = pass.len();
    let mut p = plen;
    while p > 0 {
	dgst_a.update(&hash_b[..min(p, dsize)]);
	if p < dsize {
	    break;
	}
	p -= dsize;
    }

    p = plen;
    while p > 0 {
	match p & 1 {
	    0 => dgst_a.update(pass),
	    1 => dgst_a.update(&hash_b[..dsize]),
	    _ => unreachable!()
	}
	p >>= 1;
    }

    let mut hash_a = dgst_a.finalize();

    let mut dgst_b = new_digest();
    for _ in 0..plen {
	dgst_b.update(pass);
    }
    hash_b = dgst_b.finalize();
    let mut dgst_b = new_digest();
    let mut seq_p = Vec::<u8>::with_capacity(((plen + dsize - 1) / dsize) * dsize);
    p = plen;
    while p > 0 {
	seq_p.extend(&hash_b[..min(p, dsize)]);
	if p < dsize {
	    break;
	}
	p -= dsize;
    }

    for _ in 0..MAX_SALT_LEN+(hash_a[0] as usize) {
	dgst_b.update(salt.as_bytes());
    }
    hash_b = dgst_b.finalize();
    let mut seq_s = Vec::<u8>::with_capacity(MAX_SALT_LEN);
    seq_s.extend(&hash_b[..salt.len()]);

    for r in 0..rounds.unwrap_or(DEFAULT_ROUNDS) {
	let mut dgst_a = new_digest();
	if r % 2 == 1 {
	    dgst_a.update(&seq_p[..]);
	} else {
	    dgst_a.update(&hash_a[..dsize]);
	}
	if r % 3 > 0 {
	    dgst_a.update(&seq_s[..]);
	}
	if r % 7 > 0 {
	    dgst_a.update(&seq_p[..]);
	}
	if r % 2 == 1 {
	    dgst_a.update(&hash_a[..dsize]);
	} else {
	    dgst_a.update(&seq_p[..]);
	}
	hash_a = dgst_a.finalize();
    }
    for (i, &ti) in trn_table.iter().enumerate() {
	hash_b[i] = hash_a[ti as usize];
    }

    match rounds {
	Some(rounds) => Ok(format!("{}rounds={}${}${}", magic, rounds, salt,
				   md5_sha2_hash64_encode(&hash_b[..dsize]))),
	None => Ok(format!("{}{}${}", magic, salt,
			   md5_sha2_hash64_encode(&hash_b[..dsize])))
    }
}

const MAGIC_LEN: usize = 3;

pub fn parse_sha2_hash<'a>(hash: &'a str, magic: &str) -> Result<HashSetup<'a>> {
    let mut hs = parse::HashSlice::new(hash);
    if hs.take(MAGIC_LEN).unwrap_or("X") != magic {
	return Err(Error::InvalidHashString);
    }
    let maybe_rounds = if let Some(elem) = hs.take_until(b'$') {
	elem
    } else {
	return Err(Error::InvalidHashString);
    };
    let rounds = if maybe_rounds.starts_with("rounds=") {
	let mut rhs = parse::HashSlice::new(maybe_rounds);
	rhs.take_until(b'=');
	Some(rhs.take_until(b'$').unwrap().parse::<u32>().map_err(|_e| Error::InvalidRounds)?)
    } else { None };
    let salt = if rounds.is_none() {
	maybe_rounds
    } else if let Some(salt) = hs.take_until(b'$') {
	salt
    } else {
	return Err(Error::InvalidHashString);
    };
    Ok(HashSetup { salt: Some(salt), rounds })
}

pub fn sha2_hash_with(param: HashSetup, pass: &[u8], hf: fn(&[u8], &str, Option<u32>) -> Result<String>) -> Result<String> {
    let rounds = if let Some(r) = param.rounds {
	if r < MIN_ROUNDS {
	    Some(MIN_ROUNDS)
	} else if r > MAX_ROUNDS {
	    Some(MAX_ROUNDS)
	} else {
	    Some(r)
	}
    } else { None };
    if let Some(salt) = param.salt {
	let salt = if salt.len() <= MAX_SALT_LEN {
	    salt
	} else if let Some(truncated_salt) = parse::HashSlice::new(salt).take(MAX_SALT_LEN) {
	    truncated_salt
	} else {
	    return Err(Error::InvalidHashString);
	};
	hf(pass, salt, rounds)
    } else {
	let salt = random::gen_salt_str(MAX_SALT_LEN);
	hf(pass, &salt, rounds)
    }
}
