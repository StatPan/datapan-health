# Pinned Registry probe catalog

This is the reviewed, manifest-bound `datapan.health-probe-catalog.v1` artifact
merged by `StatPan/datapan-registry` PR #551 (ticket #550), commit
`2186f9b447fdd72c2292aaa8b18d64b2eff5eb38`.

The scheduler verifies the vendored artifact SHA-256 from `config/canaries.json`
before it starts. The source artifact digest is recorded above in the Registry
commit and this local pin deliberately covers the exact reviewed projection.
It only uses operation identity and policy metadata from this artifact; no
credential value, query value, response row, or mutable receipt is vendored.
