// Encoding and decoding routines.
//
// Copyright (c) 2016 Ivan Nejgebauer <inejge@gmail.com>
//
// Licensed under the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>. This file may not be copied,
// modified, or distributed except according to the terms of this
// license.

use std::char;
use std::str::from_utf8;
use crate::error::Error;
use super::Result;

const CRYPT_HASH64: &[u8] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

const CRYPT_HASH64_ENC_MAP: &[u8] = b"\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x00\x01\
				      \x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x40\x40\x40\x40\x40\x40\
				      \x40\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\
				      \x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x40\x40\x40\x40\x40\
				      \x40\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\
				      \x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x40\x40\x40\x40";

const BCRYPT_HASH64: &[u8] = b"./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

const BCRYPT_HASH64_ENC_MAP: &[u8] = b"\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x00\x01\
				       \x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x40\x40\x40\x40\x40\
				       \x40\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\
				       \x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x40\x40\x40\x40\x40\
				       \x40\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\
				       \x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x40\x40\x40\x40\x40";

pub fn bcrypt_hash64_decode(enc: &str, decbuf: &mut [u8]) -> Result<()> {
    let mut cbuild = 0u8;
    let mut cpos = 0;
    let mut dec_idx = 0;
    for b in enc.chars() {
	let b = b as u32 - 0x20;
	if b > 0x60 {
	    return Err(Error::EncodingError);
	}
	let dec = BCRYPT_HASH64_ENC_MAP[b as usize];
	if dec == 64 {
	    return Err(Error::EncodingError);
	}
	if cpos == 0 {
	    cbuild = dec;
	} else {
	    cbuild <<= cpos;
	    cbuild |= dec >> (6 - cpos);
	    decbuf[dec_idx] = cbuild;
	    dec_idx += 1;
	    if dec_idx == decbuf.len() {
		break;
	    }
	    cbuild = dec & (0x3F >> cpos);
	}
	cpos += 2;
	if cpos > 6 {
	    cpos = 0;
	}
    }
    Ok(())
}

pub fn bcrypt_hash64_encode(bs: &[u8]) -> String {
    b_c_hash64_encode(bs, &BCRYPT_HASH64)
}

pub fn crypt_hash64_encode(bs: &[u8]) -> String {
    b_c_hash64_encode(bs, &CRYPT_HASH64)
}

fn b_c_hash64_encode(bs: &[u8], hs: &[u8]) -> String {
    let ngroups = (bs.len() + 2) / 3;
    let mut out = String::with_capacity(ngroups * 4);
    for g in 0..ngroups {
	let mut g_idx = g * 3;
	let mut enc = 0u32;
	for _ in 0..3 {
	    let b = (if g_idx < bs.len() { bs[g_idx] } else { 0 }) as u32;
	    enc <<= 8;
	    enc |= b;
	    g_idx += 1;
	}
	for _ in 0..4 {
	    out.push(char::from_u32(hs[((enc >> 18) & 0x3F) as usize] as u32).unwrap());
	    enc <<= 6;
	}
    }
    match bs.len() % 3 {
	1 => { out.pop(); out.pop(); },
	2 => { out.pop(); },
	_ => (),
    }
    out
}

const SHA1_HASH_LEN: usize = 20;

pub fn sha1crypt_hash64_encode(bs: &[u8]) -> String {
    assert!(bs.len() >= SHA1_HASH_LEN);
    let ngroups = (SHA1_HASH_LEN + 2) / 3;
    let mut out = String::with_capacity(ngroups * 4);
    for g in 0..ngroups {
	let mut g_idx = g * 3;
	let mut enc: u32 = 0;
	for _ in 0..3 {
	    let b = (if g_idx < SHA1_HASH_LEN { bs[g_idx] } else { bs[0] }) as u32;
	    enc <<= 8;
	    enc |= b;
	    g_idx += 1;
	}
	for _ in 0..4 {
	    out.push(char::from_u32(CRYPT_HASH64[(enc & 0x3F) as usize] as u32).unwrap());
	    enc >>= 6;
	}
    }
    out
}

pub fn md5_sha2_hash64_encode(bs: &[u8]) -> String {
    let ngroups = (bs.len() + 2) / 3;
    let mut out = String::with_capacity(ngroups * 4);
    for g in 0..ngroups {
	let mut g_idx = g * 3;
	let mut enc = 0u32;
	for _ in 0..3 {
	    let b = (if g_idx < bs.len() { bs[g_idx] } else { 0 }) as u32;
	    enc >>= 8;
	    enc |= b << 16;
	    g_idx += 1;
	}
	for _ in 0..4 {
	    out.push(char::from_u32(CRYPT_HASH64[(enc & 0x3F) as usize] as u32).unwrap());
	    enc >>= 6;
	}
    }
    match bs.len() % 3 {
	1 => { out.pop(); out.pop(); },
	2 => { out.pop(); },
	_ => (),
    }
    out
}

pub fn decode_val(val: &str, len: usize) -> Result<u32> {
    let mut processed = 0;
    let mut s = 0u32;
    for b in val.chars() {
	let b = b as u32 - 0x20;
	if b > 0x60 {
	    return Err(Error::EncodingError);
	}
	let dec = CRYPT_HASH64_ENC_MAP[b as usize];
	if dec == 64 {
	    return Err(Error::EncodingError);
	}
	s >>= 6;
	s |= (dec as u32) << 26;
	processed += 1;
	if processed == len {
	    break;
	}
    }
    if processed < len {
	return Err(Error::InsufficientLength);
    }
    Ok(s >> (32 - 6 * len))
}

pub fn encode_val(mut val: u32, mut nhex: usize) -> String {
    let mut val_arr = [0u8; 4];
    if nhex > 4 {
	nhex = 4;
    }
    let vlen = nhex;
    let mut i = 0;
    while nhex > 0 {
	nhex -= 1;
	val_arr[i] = CRYPT_HASH64[(val & 0x3F) as usize];
	val >>= 6;
	i += 1;
    }
    from_utf8(&val_arr[..vlen]).unwrap().to_owned()
}
