# Third-party notices and release inventory

This repository does not vendor Gatus, PostgreSQL, Go module source, Python
packages, or container-base source. Their licenses and notices remain with the
corresponding upstream distribution. The root [NOTICE](NOTICE) describes the
boundary between those materials, provider data, and Datapan-authored work.

## Components configured here

- [Gatus](https://github.com/TwiN/gatus) is an unmodified external image. The
  exact image reference is pinned in `compose.yaml`; obtain its license and
  notices from the upstream project and the resolved image before redistributing
  that image.
- PostgreSQL and the images named in `Dockerfile` / `compose.yaml` are external
  images. Those files, including their digests, are the repository's source of
  truth for the selected image inputs.
- Go dependencies are selected by `go.mod` and resolved by `go.sum`. Generate
  the exact module inventory for the release revision with:

  ```sh
  go list -m -json all
  ```

- The archive image's direct Python input is
  `docker/hf-requirements.txt`. Its installation can include transitive
  packages, so a release must record the resolved Python inventory rather than
  infer licenses from this direct-requirement file alone.

## Release procedure

Before publishing a source archive, OCI image, or binary distribution that
contains third-party material:

1. Run `make release-oci`. It first runs the governance gates and emits a
   reproducible `governance-bundle.tar` alongside the OCI archives. That bundle
   contains the legal notices, component manifests, and a checksum-bound,
   resolved Go-module inventory for the source revision.
2. Preserve the bundle, its `sha256sums.txt` entry, and the
   `DATAPAN_HEALTH_GOVERNANCE_BUNDLE_*` bindings in `infra-image-inputs.env`
   with the OCI promotion record. Add the resolved Python package inventory if
   an archive image distribution introduces packages beyond its direct pinned
   requirements.
3. Preserve the license and NOTICE files required by each resolved component.
   Do not replace them with this repository's Apache-2.0 LICENSE.
4. Review the terms of source data, provider APIs, and pinned cross-repository
   artifacts separately. They are outside this repository's code license.

This is attribution guidance, not a claim that a complete third-party license
inventory has already been produced for every possible build environment.
