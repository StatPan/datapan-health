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
