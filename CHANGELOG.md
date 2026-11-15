# Changelog

## [1.2.0](https://github.com/fabiocicerchia/sbom-diff/compare/v1.1.2...v1.2.0) (2026-11-14)


### Features

* expose the JSON report path as an output ([#110](https://github.com/fabiocicerchia/sbom-diff/issues/110)) ([47ce345](https://github.com/fabiocicerchia/sbom-diff/commit/47ce345a27819a8ebf397f68f6b0488508329be4))
* **review:** rank which dependency changes a human should read ([3932346](https://github.com/fabiocicerchia/sbom-diff/commit/3932346ddc6c2be7c825ff44108473b09e00de01))


### Bug Fixes

* 3 issues found by code-atlas (code design) ([#154](https://github.com/fabiocicerchia/sbom-diff/issues/154)) ([63fc8cb](https://github.com/fabiocicerchia/sbom-diff/commit/63fc8cb56b40aade07102318945e4f6e8e7fd1a8))
* 3 issues found by code-atlas (quality gates) ([#144](https://github.com/fabiocicerchia/sbom-diff/issues/144)) ([6fe1a01](https://github.com/fabiocicerchia/sbom-diff/commit/6fe1a0133a5569ab36dc8eec3bb3a5216886bca5))
* 6 issues found by code-atlas (ci that cannot fail) ([#155](https://github.com/fabiocicerchia/sbom-diff/issues/155)) ([036e787](https://github.com/fabiocicerchia/sbom-diff/commit/036e78715adcc12af089002388225167b32535c0))
* 6 issues found by code-atlas (test suites) ([#156](https://github.com/fabiocicerchia/sbom-diff/issues/156)) ([dbdb4c5](https://github.com/fabiocicerchia/sbom-diff/commit/dbdb4c557accc16fb34bee2b9b15241fa9a6b5db))
* **ci:** keep actions: read on the job that uploads sarif ([#109](https://github.com/fabiocicerchia/sbom-diff/issues/109)) ([00cde45](https://github.com/fabiocicerchia/sbom-diff/commit/00cde45a50a49f559b4c0bee3e0e457a750cba81))
* **release:** grant id-token on the job that calls the signing workflow ([#82](https://github.com/fabiocicerchia/sbom-diff/issues/82)) ([f12dd65](https://github.com/fabiocicerchia/sbom-diff/commit/f12dd65265ddc41cd4d5d54c0e44c7fe546f0b70))
* **release:** let the release PR carry a token that isn't GITHUB_TOKEN ([#92](https://github.com/fabiocicerchia/sbom-diff/issues/92)) ([7321bf5](https://github.com/fabiocicerchia/sbom-diff/commit/7321bf587d4e360ab7c60a1362c39ffe07b11c38))
* The oldest supported Python is past end of life ([#152](https://github.com/fabiocicerchia/sbom-diff/issues/152)) ([8a56702](https://github.com/fabiocicerchia/sbom-diff/commit/8a567028ec1fee03d7edcc7921c8bb41465a5a8c))
* Update 3 dependencies in pyproject.toml ([#151](https://github.com/fabiocicerchia/sbom-diff/issues/151)) ([d827dbb](https://github.com/fabiocicerchia/sbom-diff/commit/d827dbb0343ea2e6e19ae0394246193dad26f258))
* Upgrade setuptools 84.0.0 → 84.1.0 ([#143](https://github.com/fabiocicerchia/sbom-diff/issues/143)) ([a60287b](https://github.com/fabiocicerchia/sbom-diff/commit/a60287bb370e812a0732808f8e36dcc00d0039da))
* yamllint fails in the repository ([#145](https://github.com/fabiocicerchia/sbom-diff/issues/145)) ([04a802e](https://github.com/fabiocicerchia/sbom-diff/commit/04a802ea3b6c107a42de5b70ff6f5d1765f277b7))

## [1.1.2](https://github.com/fabiocicerchia/sbom-diff/compare/v1.1.1...v1.1.2) (2026-09-09)


### Bug Fixes

* **ci:** pin the editorconfig-checker binary version ([#66](https://github.com/fabiocicerchia/sbom-diff/issues/66)) ([2182040](https://github.com/fabiocicerchia/sbom-diff/commit/2182040f43741223d2a26e0109dd05e5961cabcd))
* **docs:** link out-of-tree files by URL so --strict passes ([#67](https://github.com/fabiocicerchia/sbom-diff/issues/67)) ([95351b0](https://github.com/fabiocicerchia/sbom-diff/commit/95351b07c28b9a8d2583dd325648e3561884a0a6))


### Documentation

* drop the curl | sh installer, pin and unpipe the syft one ([#75](https://github.com/fabiocicerchia/sbom-diff/issues/75)) ([9c1bd23](https://github.com/fabiocicerchia/sbom-diff/commit/9c1bd235e531e9704190f0444d415246db06cd76))

## [1.1.1](https://github.com/fabiocicerchia/sbom-diff/compare/v1.1.0...v1.1.1) (2026-08-29)

### Bug Fixes

- unblock quality and clear the Scorecard pinned-dependencies finding ([#51](https://github.com/fabiocicerchia/sbom-diff/issues/51)) ([9d621c8](https://github.com/fabiocicerchia/sbom-diff/commit/9d621c81c9daf81bbe13eb62a8d5fb07fa6009fd))

## [1.1.0](https://github.com/fabiocicerchia/sbom-diff/compare/v1.0.2...v1.1.0) (2026-08-25)

### Features

- **docs:** build the docs site in Actions and drop Read the Docs ([#42](https://github.com/fabiocicerchia/sbom-diff/issues/42)) ([0e95313](https://github.com/fabiocicerchia/sbom-diff/commit/0e95313128654a544d9d560550562240b6f906af))

## [1.0.2](https://github.com/fabiocicerchia/sbom-diff/compare/v1.0.1...v1.0.2) (2026-08-24)

### Documentation

- **examples:** add drop-in configs for 16 non-GitHub CI systems ([#39](https://github.com/fabiocicerchia/sbom-diff/issues/39)) ([66096dc](https://github.com/fabiocicerchia/sbom-diff/commit/66096dc24acc1e087846e684ffaf9a672501c26e))

## [1.0.1](https://github.com/fabiocicerchia/sbom-diff/compare/v1.0.0...v1.0.1) (2026-08-13)

### Bug Fixes

- security and code-quality findings ([#30](https://github.com/fabiocicerchia/sbom-diff/issues/30)) ([643eec7](https://github.com/fabiocicerchia/sbom-diff/commit/643eec72f2ac34a00bd0c8609019d122bf3c3093))

## [1.0.0](https://github.com/fabiocicerchia/sbom-diff/compare/v0.1.1...v1.0.0) (2026-08-10)

### ⚠ BREAKING CHANGES

- the action's `old-sbom` / `new-sbom` inputs are now `base-sbom` / `head-sbom`, matching the generate-both-sides model.

### Features

- converge sbom-diff-action's features into the Python engine ([#27](https://github.com/fabiocicerchia/sbom-diff/issues/27)) ([7615d05](https://github.com/fabiocicerchia/sbom-diff/commit/7615d05c302917c2bd2d134e251c40de8a67404d))

## [0.1.1](https://github.com/fabiocicerchia/sbom-diff/compare/v0.1.0...v0.1.1) (2026-08-06)

### Bug Fixes

- **pre-commit:** stop check-yaml failing on Helm templates and multi-doc manifests ([ada82b4](https://github.com/fabiocicerchia/sbom-diff/commit/ada82b4548c41f501e9c91779c3e70d5de2a6a1a))
- **security:** skip the SARIF upload on private repos ([ae1e77e](https://github.com/fabiocicerchia/sbom-diff/commit/ae1e77ef86f4fdf1171fff509961c0d2516a7d3a))

## Changelog

All notable changes to this project are documented here.

This file is maintained automatically by
[release-please](https://github.com/googleapis/release-please) from
[Conventional Commit](https://www.conventionalcommits.org/) messages — do not
edit it by hand.
