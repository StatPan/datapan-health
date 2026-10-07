# Design quality review

Issue #45 keeps the familiar single-column vertical status list backed by the
pinned Gatus v5.36.0 checker and history store. Health owns the Korean HTML
projection so people can understand API names, providers, purpose, inspection
coverage, recent result receipt times, and bounded result history without
changing Gatus endpoint keys or resetting stored history.

The main `/datapan/` page is the full pinned `data.go.kr` metadata directory,
not a selected status sample. It shows source scope and saved-source time before
the list, separates registered APIs/functions/links from configured and
recently received results, and offers bounded search and pagination. Each API
stays a vertical card with its source purpose and function counts. A single
observed function never promotes its parent API to healthy. The API detail and
`/datapan/dependencies/` views show only exact configured-function joins,
allowlisted failure explanations/actions, and up to 50 Gatus receipt-history
points. The `Datapan 관제` aggregate is separate from provider results; missing
or invalid scheduler status appears as an inspection-system issue.

The design uses text labels alongside color, full KST times alongside relative
times, keyboard focus outlines, source disclosure for revisions, and a
mobile-width single-column layout. No external fonts, images, JavaScript, or
provider calls are needed to render the page.

Visual evidence and browser acceptance at 390×844 and 1280×900 are pending the
final built preview. The checked-in older Gatus screenshots are historical
evidence and are not used to claim this Health-owned HTML passed the current
review.
