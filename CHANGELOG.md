# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Added

### Changed

### Fixed

## 3.0.0 2024-4-29
- Update to Cedar 4 (requires breaking change)
- Renamed `PolicyStoreId` to `PolicySelector` (because that's what it is now)
- Added `PolicyStoreFilter` as an optional part of the `PolicySelector` which then allows a policy store policy
  cache to contain only a subset of the policies actually managed by the AVP Policy Store (for example,
  only policies associated with a certain policy template). Note that if the set of policies that one 
  `PolicySelector` identifies intersects with the set of policies that another `PolicySelector` identifies,
  the policies in the intersection will be cached _twice_.
- Remove dependency on `cedar-policy-core`, `cedar-policy-formatter`, and `cedar-policy-validator`. (Breaking change due to new import on `EntitiesError`)
- Update `thiserror` and `derive_builder` versions
- Remove unused deps

## 2.0.0 2024-3-15
- Update to Cedar 3 (requires breaking change)

## 1.0.0 - 2023-12-14
AVP Local Agent Version: 1.0.0
- Initial release of `avp-local-agent`.
