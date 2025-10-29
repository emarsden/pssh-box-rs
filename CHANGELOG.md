# Changelog


## [0.1.12] - Unreleased

- Fix potential array out of bounds exception in `find_iter`. Issue reported by @lvzhenbo.


## [0.1.11] - 2025-04-26

- Implement `to_string` for `PsshData` objects.


## [0.1.10] - 2024-10-21

- Updated crate dependencies. No functional changes.


## [0.1.9] - 2024-07-28

- Change the default configuration to use a preinstalled protobuf compiler, instead of attempting to
  build the `protobuf-src` crate, which causes many headaches on less common platforms. This means
  that the `vendored-protoc` feature is no longer included in the default features.


## [0.1.8] - 2024-07-26

- New method `contains()` on `PsshBoxVec`.

- Replace some debugging printfs by trace logging.


## [0.1.7] - 2024-07-22

- Update protobuf-src crate which was causing builds to fail.


## [0.1.6] - 2024-06-13

- Update to v2 of the `protobuf-src` crate.

- Parsing: additional diagnostics information is logged at the `trace` level.


## [0.1.5] - 2024-02-27

- Generation of a Widevine PSSH: fix bug related to spurious inclusion of an empty string for the
  `policy` field when the field is not set explicitly (reported by ElCap).


## [0.1.4] - 2024-02-21

- Add support for the FairPlay DRM system, and in particular the mystery FairPlay PSSH boxes that
  are reported to be used by Netflix for DASH-like streaming.

- Add support for UUID-style strings in `DRMKeyId::try_from(&str)`.


## [0.1.3] - 2024-02-14

- New example `fetch-pssh-data`, a commandline utility which fetches an initialization segment from
  a DASH stream that uses ContentProtection (DRM) and displays the content of any DRM initialization
  data (PSSH boxes) it may contain.

- Release builds optimize for space.


## [0.1.2] - 2024-02-05

- Add feature `vendored-protoc` to pull in the `protobuf-src` crate. With this feature, which
  defaults to being enabled, the protobuf compiler is built from C sources at build time, instead of
  using a locally installed protoc compiler. This is intended to make it easier for users of our
  crate (it turns out to be very difficult to ensure that protoc is installed on build machines when
  using Github actions such as the upload-rust-binary-action, which depends on cross-rs running in a
  container).


## [0.1.1] - 2024-02-04

- Add a compact `to_string()` method on `PsshBox` and `PsshBoxVec`.

- Add a `to_string()` method on `DRMSystemId` and `DRMKeyId`, in addition to the more basic Debug
  printer.

- Add a `to_json()` method on `WidevinePsshData`.
