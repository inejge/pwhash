## v1.0.0, 2021-01-03

* Increase the default bcrypt cost to 10, in line with the recent OpenBSD
  value. Technically, this is a breaking change, so the crate version
  should go up.

* [internal] Update for 2018 Edition.

* [internal] Bump outdated dependencies and clean up Clippy warnings ([#15](https://github.com/inejge/pwhash/pull/15)).

* [internal] Move CI to GitHub.

## v0.3.1, 2020-07-08

* [internal] Update dependencies ([#13](https://github.com/inejge/pwhash/pull/13)).

## v0.3.0, 2019-01-13

* [internal] Update dependencies, replace outdated crates ([#11](https://github.com/inejge/pwhash/pull/11)).

## v0.2.0, 2018-05-09

* Widen password input type to [u8] ([#8](https://github.com/inejge/pwhash/issues/8)).

* Warn users who try to generate new insecure hashes by deprecating
  the corresponding hashing funcions ([#8](https://github.com/inejge/pwhash/issues/9)).
  Verification for insecure hashes is not deprecated.

* [internal] Use ? for error handling instead of try!

## v0.1.2, 2017-04-01

* Better compatibility with Unix crypt through the removal of length check
  from `unix::crypt()` ([#3](https://github.com/inejge/pwhash/pull/3)).

## v0.1.1, 2016-02-09

Initial version.
