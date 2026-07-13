# Design quality review

Design source: Issue #1 product direction plus the upstream Gatus v5.36.0 dashboard pattern. This is a proposed Datapan treatment; no separate Figma or brand guide exists in the repository.

Asset taxonomy: One inline SVG product mark used only as a logo. No screenshots, illustrations, full-button images, or mixed control assets are used in the UI.

Visual decision: Preserve the familiar Gatus status-page controls and cards, constrain content to 760px, and force endpoint grids to one column at every viewport. Korean title, heading, description, and subheading establish the public context without forking the frontend.

Evidence:

- [Desktop, 1440×1200](evidence/status-desktop.png)
- [Mobile, 390×844](evidence/status-mobile.png)
- Both viewports show the same vertical order, healthy and unhealthy badges, visible focus styling, and no text/image overlap.
- Evidence was recaptured from the ephemeral PostgreSQL-backed Compose stack after healthy and unhealthy CLI-style receipts were persisted.
- Gatus provides endpoint link accessibility names; icon controls retain upstream titles/labels.

Open design risk: none. The remaining English filter labels are upstream Gatus controls and do not prevent the Korean Datapan status context; translating them would require a frontend fork, which is explicitly out of scope.
