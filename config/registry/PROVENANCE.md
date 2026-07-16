# Pinned Registry probe catalog

This is the signed, manifest-bound `datapan.health-probe-catalog.v1` artifact
from `StatPan/datapan-registry` release `v2026.07.14`, tag commit
`d4171c303aa57845f6d6764c192e746bde7401e3` (catalog source commit
`b49d66b97d8155c34649f4dd2040b884c4212d64`). The release zip SHA-256 is
`f6aec27c5a73cd9087bdf620d49d3a2ede5f47838effe8d736672ebf504c06e2` and
the immutable Dataset revision is `10f375182f992bc700468dd9d6e2930acd3bf8e8`.

The scheduler verifies the vendored artifact SHA-256 from `config/canaries.json`
before it starts. The local artifact SHA-256 is
`e84f0da2f532a32833def1118a4610bf2322f370783d120b84cf85306d244840`; this
pin deliberately covers the exact reviewed projection.
`config/canaries.json` separately pins the immutable Dataset revision, source
Registry SHA-256, release tag and release-manifest SHA-256. These identifiers
must not be collapsed: public archive `registry_revision` is the Dataset
revision, while the source SHA is only the signed catalog-input identity.
It only uses operation identity and policy metadata from this artifact; no
credential value, query value, response row, or mutable receipt is vendored.

## M003 diagnostic compatibility inputs

`diagnostic-contract-pin.json` pins the exact Registry #566/#567 consumer-proof
inputs merged at Registry commit
`8c5d397f13929ec2b85e63e4ca600887f37929b8`. The vendored schema, mapping,
Health consumer packet, and eleven fixtures live under `diagnostic/`. Their
schema, mapping, and consumer-packet SHA-256 values are respectively:

- `da254b40947462347fcda90fdd7686b6632c76943b438f2046a28f079f33e403`
- `da55d52d2ee1f197969ac63a1d5ab5b98e3b88fd65f90d6a48800d2e3c522d33`
- `e831df46e50107c116132f423525af5b1ea8c9743c014956a2fc3732077db70c`

`diagnostic-test-manifest.json` is a Health-owned, non-self-referential proof
input with SHA-256
`274d394133eb90fe5553bb47947644d45f338ad2e193345e13759f7bb9e2619b`.
It pins the exact compatibility test names and the source digests for
`internal/health/diagnostic_test.go` and the preserved v1 compatibility test in
`internal/health/health_test.go`. The receipt generator validates those bytes
and Go test declarations before reporting compatibility.

These files remain offline compatibility inputs while Registry #568 is
pending. They are not a public release, a runtime diagnosis authority, or a
deployment instruction. The compatibility loader rejects any other Registry
revision or artifact digest.
