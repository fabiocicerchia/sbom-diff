# Changelog

## [1.0.0](https://github.com/fabiocicerchia/sbom-diff/compare/v0.1.1...v1.0.0) (2026-08-10)


### ⚠ BREAKING CHANGES

* the action's `old-sbom` / `new-sbom` inputs are now `base-sbom` / `head-sbom`, matching the generate-both-sides model.

### Features

* converge sbom-diff-action's features into the Python engine ([#27](https://github.com/fabiocicerchia/sbom-diff/issues/27)) ([7615d05](https://github.com/fabiocicerchia/sbom-diff/commit/7615d05c302917c2bd2d134e251c40de8a67404d))

## [0.1.1](https://github.com/fabiocicerchia/sbom-diff/compare/v0.1.0...v0.1.1) (2026-08-06)


### Bug Fixes

* **pre-commit:** stop check-yaml failing on Helm templates and multi-doc manifests ([ada82b4](https://github.com/fabiocicerchia/sbom-diff/commit/ada82b4548c41f501e9c91779c3e70d5de2a6a1a))
* **security:** skip the SARIF upload on private repos ([ae1e77e](https://github.com/fabiocicerchia/sbom-diff/commit/ae1e77ef86f4fdf1171fff509961c0d2516a7d3a))

## Changelog

All notable changes to this project are documented here.

This file is maintained automatically by
[release-please](https://github.com/googleapis/release-please) from
[Conventional Commit](https://www.conventionalcommits.org/) messages — do not
edit it by hand.
