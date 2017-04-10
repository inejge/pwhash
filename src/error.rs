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
use std::{io, fmt};
use std::error::Error as StdError;

/// Possible errors.
#[derive(Debug)]
pub enum Error {
    /// The system entropy source couldn't be opened.
    Io(io::Error),
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
            Error::Io(ref err) => write!(f, "{}", err),
            _ => write!(f, "{}", self.description()),
        }
    }
}

impl StdError for Error {
    fn description(&self) -> &str {
        match *self {
            Error::Io(_) => "I/O error",
            Error::EncodingError => "Invalid encoding",
            Error::InsufficientLength => "Encoded value is too short",
            Error::InvalidRounds => "Invalid rounds value",
            Error::InvalidHashString => "Invalid hash string",
        }
    }

    fn cause(&self) -> Option<&StdError> {
        match *self {
            Error::Io(ref err) => Some(err),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error::Io(err)
    }
}
