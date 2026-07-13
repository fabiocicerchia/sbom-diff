# Basic Example

Two tiny CycloneDX SBOMs that exercise every kind of change sbom-diff reports:
a major-version jump (`openssl`), a license change (`openssl`), a patch update
(`libfoo`), a removed dependency (`oldpkg`), and an added one (`newpkg`).

## Run

```sh
sbom-diff old.json new.json
```
