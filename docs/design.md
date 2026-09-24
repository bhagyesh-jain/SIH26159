# SecureMailScope — Product Design System

**Version:** 1.0 proposed | **Direction:** professional dark SOC workstation, evidence-first, restrained motion.

## 1. Design principles
1. Evidence before aesthetics: every claim has a route to its packet/stream evidence.
2. Distinguish **verified weakness**, **ML anomaly**, **unknown evidence** and **healthy observed configuration**.
3. Keep large data tables legible; motion must not distract during investigation.
4. Desktop-first responsive design; tablet supported; mobile supports overview and basic triage, not full packet inspection.
5. Accessibility: keyboard focus, text labels alongside color, WCAG AA contrast target and reduced-motion preference.

## 2. Visual tokens
| Token | Suggested value | Use |
|---|---|---|
| App background | `#0B1220` | Dark canvas |
| Surface | `#111D30` | Sidebar, cards |
| Raised surface | `#18283D` | Hover, panels |
| Border | `#2A3B52` | Separation |
| Primary text | `#F1F5FA` | Headings and values |
| Secondary text | `#A7B8CC` | Labels and metadata |
| Primary accent | `#4CE0C2` | Active state and positive actions |
| Secondary accent | `#7EA6FF` | Links and secondary series |
| Critical | `#FF6B79` | Critical findings |
| High | `#FF9B6A` | High severity |
| Medium | `#F2C46D` | Medium severity |
| Low | `#7DB5ED` | Low severity |
| Unknown | `#AAB4C2` | Unavailable evidence |

Fonts: Inter for interface; JetBrains Mono for packet numbers, hashes, ciphers and technical IDs. Spacing: 4 px base scale; card radius 12 px; input radius 8 px. Use semantic tokens and dark/light-safe component styles, not raw color strings throughout the app.

## 3. Frontend library ownership
- **shadcn/ui:** sidebar, buttons, inputs, tabs, dialogs, badges, tooltips, skeletons, accessible primitives.
- **TanStack Table:** session and finding tables with pagination, filters and column visibility.
- **Recharts:** baseline time-series, bar and donut charts; do not add Bklit until licensing and actual component APIs are confirmed.
- **Motion:** page transitions, controlled layout animations, loading state and hover/press feedback.
- **React Bits:** selectively use Decrypted Text or Split Text on marketing landing page, Spotlight Card on feature cards and a subtle Aurora/Dark Veil background only if performance/accessibility tests pass. Confirm each component's installation/license before copying code.
- **Bklit (optional):** evaluate heatmap, Sankey and gauge components against Recharts/custom alternatives; do not make it a hard dependency in MVP.
- **Lucide React:** consistent iconography.

## 4. Information architecture
Persistent desktop sidebar: Overview, Investigations, Sessions, Findings, AI Insights, Reports, Settings. Top bar: current investigation, global search (later), processing state, help and account (when authentication exists). Breadcrumbs on detail pages.

### Overview
KPI cards for captures analyzed, sessions, verified high-risk findings, ML anomalies and assessment coverage. Protocol distribution, TLS version chart, findings trend and recent investigations. Every KPI shows its data scope and time range. Never show fabricated demo metrics without a visible `DEMO DATA` banner.

### Investigations
List/create case; drag-and-drop `.pcap`/`.pcapng`; explicit maximum size and retention notice; actual job stages: validating, hashing, extracting, reconstructing, assessing, completed/failed. Upload errors with actionable details.

### Session Explorer (core page)
Resizable two-pane layout: searchable/filterable session table at left and details at right. Detail tabs: Overview, Timeline, TLS, Certificates, Packets. Timeline shows plaintext commands, upgrade request/response, TLS ClientHello/ServerHello, alerts and gaps. Include source packet numbers, capture hash, timestamps and completeness badges. Filters: protocol, TLS version, handshake outcome, finding severity and evidence availability.

### Findings
Table/cards with severity, finding type (deterministic vs ML), affected session, confidence, evidence completeness and remediation. Detail drawer with exact observed fields, rule explanation, packet references and explicit limitations. Severity alone is never a substitute for confidence.

### AI Insights
Anomaly distribution, feature breakdown and model/version metadata. Label all predictions as advisory. Show threshold, false-positive caveat and comparison with rule-based findings. No fictional explainability values.

### Reports
Report preview, export JSON/HTML/PDF, captured-at vs analyzed-at dates, included captures/hashes, tool and rule versions, scope, assumptions and evidence limitations.

### Settings
Local storage and retention, upload size, analysis timeouts, report preferences, reduced motion, theme; admin/security controls only after authentication is implemented.

## 5. Component inventory
- `AppShell`, `SidebarNav`, `Topbar`, `Breadcrumbs`, `InvestigationSwitcher`
- `CaptureDropzone`, `UploadValidation`, `ProcessingTimeline`, `JobStatusBadge`
- `KpiCard`, `ProtocolDistributionChart`, `TLSVersionChart`, `FindingTrendChart`, `CoverageGauge`
- `SessionTable`, `SessionFilterBar`, `SessionDetailPanel`, `HandshakeTimeline`, `PacketEvidenceLink`, `CertificatePanel`
- `FindingTable`, `SeverityBadge`, `EvidenceConfidenceBadge`, `FindingDetailDrawer`, `RemediationCard`
- `AnomalyScatter`, `ModelInfoPanel`, `FeatureExplanation`, `RiskMethodologyPanel`
- `ReportPreview`, `ExportMenu`, `EmptyState`, `ErrorBoundary`, `Skeleton`, `ConfirmDialog`

## 6. Motion specification
- Route transitions: 150–220 ms fade/translate; no forced animation on large data refreshes.
- Card hover: border/emphasis or 2 px elevation, 120–180 ms.
- Drawer/modal: 180–240 ms opacity/translate; focus trapping and Escape close.
- Table filtering: instant or minimal opacity; no per-row cascade for large datasets.
- Processing: indeterminate animation only when backend progress is unknown; never invent completion percentage.
- Landing: restrained React Bits hero effect; disable expensive canvas/WebGL on low-power or reduced-motion devices.
- Honor `prefers-reduced-motion`; provide no-motion alternatives.

## 7. Wireframe: desktop investigation
```text
┌──────────────────────────────────────────────────────────────────────┐
│ Sidebar          │ Investigation: CASE-001        [Export] [Settings]│
│ Overview         ├───────────────────────────────────────────────────┤
│ Investigations   │ Captures  Sessions  Findings  Coverage             │
│ Sessions         ├──────────────────────┬────────────────────────────┤
│ Findings         │ Session table        │ Selected session           │
│ AI Insights      │ filters/search       │ Overview | TLS | Packets   │
│ Reports          │ stream / protocol    │ Handshake timeline         │
│                  │ outcome / severity   │ Evidence + findings        │
└──────────────────┴──────────────────────┴────────────────────────────┘
```

## 8. Responsive rules
>=1280 px: full sidebar and two-pane explorer. 768–1279 px: collapsible sidebar, tabbed explorer. <768 px: stacked overview, compact investigation list and read-only session summary; prompt desktop for packet-heavy inspection. Tables retain horizontal scrolling and explicit column controls rather than crushing technical values.

## 9. Acceptance checklist
Keyboard access to upload, filtering and detail drawer; focus visibility; semantic table headers; contrast tests; screen-reader announcements for job completion; reduced-motion check; empty/error/unknown states; large-table responsiveness; all sample data visibly labelled; all findings link to real evidence when available.
