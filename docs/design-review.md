# Design quality review

Design source: Issues #1 and #3 product direction plus the upstream Gatus v5.36.0 dashboard pattern. This is a proposed Datapan treatment; no separate Figma or brand guide exists in the repository.

Asset taxonomy: One inline SVG product mark used only as a logo. No screenshots, illustrations, full-button images, or mixed control assets are used in the UI.

Visual decision: Preserve the familiar Gatus status-page controls and cards, constrain content to 760px, and force endpoint grids to one column at every viewport. The canonical catalog-backed canary names remain readable as a single vertical public list on desktop and mobile. Korean title, heading, description, and subheading establish the public context without forking the frontend.

Evidence:

- [Desktop, 1280×1000](evidence/status-desktop.png)
- [Mobile, 390×844](evidence/status-mobile.png)
- Both viewports show the same vertical order, healthy and unhealthy badges, visible focus styling, readable sample-scope copy, and no observed text/image overlap or horizontal overflow.
- Ticket #40 recaptured the local Compose Gatus view at 1280×1000 and 390×844 after the honest 10-canary scope copy changed. The public JSON adapter remains a separate machine-readable surface; this upstream Gatus view does not render its incident fields.
- The 2026-08-09 capture used the ephemeral PostgreSQL-backed Compose stack after healthy and unhealthy CLI-style receipts were persisted for `holiday-emergency-clinics` and `qnet-practical-pass-rate`. PNG SHA-256: desktop `637f4da25936b2b7070ef5fe9f2ea16eff20fa57dd26877c843e621079431587`; mobile `eb3d479962ca747b4e1be5dbd7f175f71c5bd2602732baab75c87ba1d082ad09`.
- Gatus provides endpoint link accessibility names; icon controls retain upstream titles/labels.

Open design risk: none. The remaining English filter labels are upstream Gatus controls and do not prevent the Korean Datapan status context; translating them would require a frontend fork, which is explicitly out of scope.
