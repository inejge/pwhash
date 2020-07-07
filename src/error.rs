//! Error values.
//
// Copyright (c) 2016 Ivan Nejgebauer <inejge@gmail.com>
//
// Licensed under the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>. This file may not be copied,
// modified, or distributed except according to the terms of this
// license.
//!
//! For simplicity, there's no provision for recording the cause of any
//! errors except I/O errors when opening the system entropy source.
use std::fmt;
use std::error::Error as StdError;

/// Possible errors.
#[derive(Debug)]
pub enum Error {
    /// Random value cannot be generated.
    RandomError(String),
    /// Some component of the hash string contains an invalid character.
    EncodingError,
    /// An encoded value is too short.
    InsufficientLength,
    /// The number of rounds is out of range.
    InvalidRounds,
    /// The hash string is not in the expected format.
    InvalidHashString,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::RandomError(ref err) => write!(f, "{}", err),
            Error::EncodingError => write!(f, "Invalid encoding"),
            Error::InsufficientLength => write!(f, "Encoded value is too short"),
            Error::InvalidRounds => write!(f, "Invalid rounds value"),
            Error::InvalidHashString => write!(f, "Invalid hash string"),
        }
    }
}

impl StdError for Error {}
