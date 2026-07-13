# Canonical receipt schema provenance

`datapan.health-probe.v1.schema.json` is a canonical, semantically identical pinned copy of the merged Datapan CLI schema. Its formatting is repository-local; its sorted JSON structure is compared to the source during update review.

- Source repository: `StatPan/datapan-cli`
- Source commit: `2fc8343993b7704b50f7d50fcba2642fca439c7f`
- Source path: `schemas/datapan.health-probe.v1.schema.json`
- Canonical source SHA-256: `b755a5af33152bcb36dc7c2382b94857953d0a9359b6b77cd8b2cb093d0a820d`
- Local pinned copy SHA-256: `0ea4dc0cbcbd2387a47e098a362fcdd136591d45d6a4f8e51b52b1acb2cedf2b`

Compatibility tests validate every accepted fixture with this copy and assert its digest. Update the copy and provenance together only after a reviewed CLI schema change.
