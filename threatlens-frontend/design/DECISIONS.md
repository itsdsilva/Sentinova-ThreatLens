# ThreatLens design decisions

## Reference dossier
- Grafana: borrow a clear top-left-to-detail information hierarchy and restrained, question-specific charts rather than a tile wall ([dashboard guidance](https://grafana.com/docs/grafana/latest/visualizations/dashboards/build-dashboards/best-practices/)).
- Datadog Cloud SIEM: borrow severity-first filtering, explicit triage state, assignment, and incident declaration from a signal detail surface ([triage workflow](https://docs.datadoghq.com/security/cloud_siem/triage_and_investigate/investigate_security_signals/)).
- OpenCTI: borrow the separation between count summaries, active-threat lists, relationship volume, and targeted-entity analysis ([dashboard model](https://docs.opencti.io/latest/usage/getting-started/)).
- MISP: borrow event-as-context and the ability to pivot through typed indicator relationships without losing provenance ([system guide](https://www.circl.lu/doc/misp/using-the-system/)).
- MITRE ATT&CK Navigator: borrow matrix layers, technique annotations, scoring, and coverage comparison instead of inventing a decorative heatmap ([layer model](https://github.com/mitre-attack/attack-navigator/blob/master/layers/README.md)).
- Bloomberg Terminal: borrow compact mono data, fixed alignment, terse labels, and keyboard-led scan patterns; not its legacy color noise.
- Palantir Gotham: borrow object-centric investigation, where alerts, indicators, people, systems, and actions remain linked in one workspace.
- Linear: borrow command discipline, visible focus, quiet chrome, and a fast route model without borrowing its spacious issue-list density.
- Airline operations boards: borrow persistent UTC, state-at-a-glance, row stability, and the principle that late or stale data must announce itself.
- Paste and micro-blogging tools: borrow economical metadata stacking where source, state, and time occupy one compact reading line.

## Domain aesthetic
- A SOC analyst scans for exceptions, not decoration; severity must interrupt an otherwise neutral surface.
- UTC is the operating clock. Absolute timestamps use `YYYY-MM-DD HH:mm:ssZ` and never depend on locale.
- Relative time belongs only in a live queue, with absolute Z-time available on hover and focus.
- Indicators, hashes, IPs, timestamps, IDs, ATT&CK techniques, and correlation IDs are machine material and render in mono.
- Severity is semantic infrastructure: the same critical, high, medium, low, and info colors recur in rows, chips, charts, and graph edges.
- TLP is a handling constraint, not a decorative tag; its label is compact, uppercase, and always textual as well as colored.
- Dense queues need 34px rows, sticky headers, stable columns, right-aligned scores, and actions that stay quiet until needed.
- Provenance is part of the verdict: feeds and sighting counts sit beside state rather than in a distant detail page.
- Triage is keyboard-first because pointer travel compounds over hundreds of alerts.
- Incidents read chronologically, with append-only events visually distinct from editable analyst notes.
- Threat hunting begins with facets and pivots, not a blank hero or a large search illustration.
- Relationship graphs need typed edges and legible mono node labels; glow effects imply meaning that does not exist.
- ATT&CK coverage is a matrix with explicit technique IDs, not a generic colored mosaic.
- Empty states tell the operator what will happen next; errors include machine code and correlation ID.
- Stale data is a first-class state and always exposes the last successful update.
- Executive views still use operational nouns and current evidence; they do not become marketing dashboards.
- Motion confirms interaction or marks a genuinely new alert, then stops.
- Dark mode is the baseline for long shifts, while contrast remains sufficient for small metadata.

## Argued decisions
| ID | Decision | One-sentence defense |
|---|---|---|
| D01 | Graphite-black canvas with a mineral teal action color | Teal separates operator intent from severity colors without turning the console into a blue-purple software template. |
| D02 | IBM Plex Sans with IBM Plex Mono | The pair shares proportions, keeps dense text calm, and makes machine values visibly different without changing visual era. |
| D03 | 2/4/6/10/14/20/28/40 spacing ladder | A deliberately non-8px rhythm lets queue chrome stay compact while preserving larger jumps for view structure. |
| D04 | One 4px control radius and one 8px panel radius | Small radii keep the interface mechanical and prevent every surface from becoming a soft floating card. |
| D05 | Hairlines for structure and one shadow only for detached overlays | Persistent surfaces should read by alignment and borders; only menus and trays need to appear physically above the work plane. |
| D06 | A 34px table row with a 2px severity edge on hover or selection | The row is dense enough for shift work while the edge communicates urgency without painting the entire record. |
| D07 | One dominant work region plus one subordinate rail per view | Analysts need an obvious working surface and nearby context, not a democratic grid of equally loud modules. |
| D08 | Severity color is reserved for security meaning | Reusing critical orange or red for ordinary controls would train operators to ignore the product's most important visual language. |
| D09 | Charts use hairline axes, direct labels, and at most an 8% area wash | Restrained marks preserve comparison accuracy and keep trend graphics subordinate to the queue and evidence tables. |
| D10 | Navigation and triage are keyboard-addressable | Slash, arrows or j/k, Enter, and Escape match the repetition rate of real queue work and reduce pointer dependency. |

## Type contract
- IBM Plex Sans: selected for compact, open counters and disciplined UI texture from 11px through 24px.
- IBM Plex Mono: selected for unambiguous hashes, timestamps, IPs, IDs, scores, and aligned evidence.
- 11px/16px/600/0.075em: uppercase eyebrows, table headers, and chips only.
- 12px/18px/400/0: metadata, help, graph labels, and secondary actions.
- 13px/20px/400/-0.006em: default table and control copy.
- 14px/22px/400/-0.006em: body copy and primary controls.
- 16px/24px/600/-0.015em: section headings.
- 20px/28px/600/-0.015em: view titles.
- 24px/32px/600/-0.015em: the single executive risk number only.
- All metric numerals use tabular lining figures; machine values use the mono face with 0.01em tracking.

## API contract
- REST root: `/api/v1`; reads cover alerts, indicators, search, incident timeline, feeds, users, audit, and health.
- Mutations use the documented alert lifecycle and enrichment/report/export operations with the uniform error envelope `{ error: { code, message, correlation_id } }`.
- WebSocket subscriptions bind `alerts.stream`, `indicators.high_severity`, `incidents.{id}`, and `system.health` after connection.
- Demo fallback is local and deterministic; live responses replace it without changing view components.
