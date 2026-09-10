# UI Simplification and Progressive-Disclosure Audit

**Inspection dates:** 25–26 August 2026

**Status:** Recommendations only; no product UI or behavior changes were made.

**Decision model:** Each item is written so it can be approved, modified, or rejected independently.

## Executive summary

The products share a coherent visual language, but several interfaces expose product architecture, security documentation, inactive destinations, and maintenance controls as if they were everyday tasks. The largest gains come from reducing primary navigation, hiding controls until they are relevant, and moving technical explanations into contextual detail views without removing security state.

The strongest recommendations are:

1. Reduce the Noctweave messaging client from six iPhone tabs and seven iPad rail items to three primary destinations: **Chats**, **People**, and **You**.
2. Remove NoctGallery's documentation-only **Share** tab; preserve one concise privacy warning at the moment a share is created.
3. Replace Noctweb Lab's documentation-heavy Settings page with actionable preferences plus a separate **Technical details** disclosure.
4. Hide NoctBoard's six content destinations until a live board or audit file is opened.
5. Make Noctweb Browser's empty state one focused surface instead of showing an empty library, single-tab strip, inactive toolbar actions, and a second central call to action together.
6. Assign distinct roles to the three relay-management surfaces so lifecycle, policy, and diagnostics are not repeated everywhere.
7. Make refresh, sync, logs, digests, raw identifiers, credential-copy actions, and unavailable controls contextual instead of permanently visible.
8. Correct fixed-width desktop layouts that leave roughly half of wide windows unused in NoctweaveJS, Relay Desktop, the group companion, and Publisher.

If the high-confidence changes below are accepted, the visible primary choices would fall approximately as follows:

| Surface | Current | Proposed |
|---|---:|---:|
| Noctweave iPhone primary tabs | 6 | 3 |
| Noctweave iPad primary rail items | 7 | 3–4 |
| NoctGallery primary tabs | 3 | 2 |
| NoctBoard destinations before opening data | 6 | 0 |
| Noctweb Lab Settings cards | 5 | 1 actionable card + details disclosure |
| Noctweb Browser empty-state chrome | 10+ controls/regions | about 5 contextual controls |

## Highest-value approval list

| ID | Recommendation | Impact | Effort | Preserve |
|---|---|---|---|---|
| A1 | Consolidate Noctweave navigation into Chats, People, and You | High | Medium | Pairwise identity and relay boundaries remain reachable |
| A2 | Remove NoctGallery's Share Privacy tab | High | Low | Keep the decoy-metadata limitation at share time |
| A3 | Hide NoctBoard navigation until a source is opened | High | Low | Keep source provenance obvious after opening |
| A4 | Move Noctweb Lab technical cards behind Technical details | High | Low | Keep verification failure and active routing mode visible |
| A5 | Collapse Noctweb Browser's empty library and single-tab strip | High | Medium | Keep relay trust and publication verification visible when applicable |
| A6 | Hide manual sync/refresh controls unless work or an error exists | Medium | Medium | Show active sync, failure, retry, and stale-state warnings |
| A7 | Give relay lifecycle, policy, and diagnostics separate homes | High | Medium–High | Keep exposure, persistence, federation, and TLS state visible |
| A8 | Hide raw hashes, ports, byte counts, latency, and protocol names under Details | Medium | Low | Never hide the human-readable consequence |
| A9 | Center or stretch fixed-width desktop workspaces | High | Low–Medium | Preserve readable maximum line lengths inside content cards |
| A10 | Use one call to action per empty state | Medium | Low | Preserve alternate actions in a secondary menu |

## Scope and evidence quality

| Product/surface | Repository | Rendered states inspected | Confidence |
|---|---|---|---|
| Noctweave Messaging Client | `Noctweave Messaging Client` | Live macOS conversation and attachment evidence; current Debug fixture on iPhone and iPad; chats, conversation, contacts, code, relays, identity, settings | High for mobile/tablet and conversation UI; medium for unrendered macOS secondary screens |
| Native Noctweave Relay | `Noctweave Relay` | Current packaged/reference console plus current source hierarchy | Medium |
| Relay Desktop launcher | `NoctweaveRelayServer/desktop` | Production HTML/CSS rendered in a loopback browser | High for layout; runtime values were placeholders |
| Operator Console | `NoctweaveRelayServer` | Live login surface from an isolated memory-only relay; current authenticated console reference and source | Medium–High |
| Noctweb Publisher | `NoctweaveRelayServer` | Live default workspace from an isolated memory-only loopback relay | High |
| NoctweaveJS web/desktop | `NoctweaveJS` | Live encrypted-persona gate, group companion, current DOM/source, and packaged client reference | High for locked/setup states; medium for unlocked secondary screens |
| NoctCord | `/Users/luiz/Desktop/Projects/NoctCord` | Current first-connect state plus live populated conversation and attachment evidence | High |
| NoctBoard | `/Users/luiz/Desktop/Projects/NoctBoard` | Current empty audit-console state and current populated hierarchy/source | High for pre-open state; medium for populated layout |
| NoctGallery | `/Users/luiz/Desktop/Projects/NoctGallery` | Current iPhone gallery, photo detail, advanced share, Share Privacy, and Settings | High |
| Noctweb Browser | `/Users/luiz/Desktop/Projects/noctweave-net` | Current empty browser, verification panel, and relay chooser | High |
| Noctweb Lab | `/Users/luiz/Desktop/Projects/noctweave-net` | Current default site editor, Settings, and Relays | High |

No real user state or passwords were used. The review used DEBUG-only fixtures, existing simulators, repository evidence from the real-world messaging test, and disposable loopback services. No Keychain prompt or OS permission prompt was accepted.

Two limitations are worth retaining with the findings:

- The macOS messaging fixture remained on “Opening encrypted state” when launched outside its XCUITest host, so the macOS conversation evidence and the current iPhone/iPad hierarchy were used together for that shell.
- The NoctBoard file picker disrupted UI control while opening a generated audit JSONL. The pre-open screen was directly rendered; populated recommendations are additionally source-backed.

## Cross-product simplification rules

These rules account for most individual recommendations:

- **Primary navigation represents user goals, not implementation domains.** “My Code,” “Relays,” protocol identity, raw storage, and diagnostics should generally be secondary destinations.
- **Automatic until exceptional.** Sync, refresh, route renewal, and cleanup should stay invisible while healthy; expose status and retry when work is active, stale, or failed.
- **One empty state, one primary next step.** Do not show disabled destination navigation, a blank search field, and two equivalent calls to action at once.
- **Progressively disclose technical proof.** Show a plain-language status first, then hashes, ports, protocol modules, latency, and raw error bodies under Details.
- **Documentation is not a primary tab.** Security explanations belong at onboarding, at the consequential action, in an info sheet, and in documentation—not permanently beside daily work.
- **Hide controls, not consequences.** A user may not need to see `nw.net-host@1`, but must see whether hosting is verified, unavailable, public, persistent, or requires a restart.

## Noctweave Messaging Client

### Observed

- iPhone exposes six bottom tabs: Chats, Contacts, Code, Relays, Identity, and Settings.
- iPad exposes seven rail items because Files is added as another primary destination.
- The global tab bar remains visible inside an active iPhone conversation.
- Direct conversations permanently show **Join Group** and manual **Sync** actions in the header.
- Identity Management contains a persistent **Refresh Secure Routes** maintenance row.
- The macOS shell repeats the same broad information architecture in its sidebar.

### Recommendations

| ID | Simplify or hide | Proposed placement | Priority |
|---|---|---|---|
| NW-1 | Combine Contacts and My Code | **People** destination; one Add Contact flow offers scan, import, or one-use code | High |
| NW-2 | Move Relays and Identity out of primary navigation | **You** or Settings, with Persona and Relays as rows | High |
| NW-3 | Move Files out of the iPad rail/macOS global library | Chats toolbar or conversation/file library | Medium |
| NW-4 | Hide global navigation while inside a phone conversation | Restore it on back navigation | High |
| NW-5 | Hide Join Group in normal direct-chat chrome | Conversation overflow menu | Medium |
| NW-6 | Replace the permanent sync button with transient sync state | Show retry only after failure or stale state | Medium |
| NW-7 | Hide Refresh Secure Routes during healthy operation | Persona diagnostics; surface automatically when renewal is needed | High |
| NW-8 | Shorten page subtitles and long relay-privacy copy | One plain-language sentence plus Learn more | Medium |
| NW-9 | Replace “Post-quantum relationship” as the default contact subtitle | “Secure relationship”; retain algorithm detail in verification/details | Low |

### Keep visible

- Whether the conversation is secure, locked, syncing, stale, or failed.
- That invitations are one-use and do not publish a global identity.
- Which persona is active before changing persona-scoped data.
- Relay trust or availability when creating a new relationship.

## NoctCord

NoctCord is the cleanest dense desktop interface in this set. Its primary community/channel/message layout should receive a light-touch pass rather than a redesign.

| ID | Simplify or hide | Recommendation | Priority |
|---|---|---|---|
| NC-1 | Empty Voice Rooms section | Hide until a room exists; keep Create/Join in the add menu | Medium |
| NC-2 | Members panel on constrained widths | Default collapsed and reveal from the existing members control | Medium |
| NC-3 | First-connect explanatory duplication | Keep the existing advanced disclosures; reduce the two relay-helper sentences to one | Low |
| NC-4 | Attachment byte count and exact retention timestamp | Put under attachment details; keep **encrypted** and expiry state on the card | Low |
| NC-5 | Repeated profile isolation wording | Show one compact profile status, expanding to the full boundary explanation on demand | Low |

The existing **Advanced relay access** and **Advanced call network override** disclosures are already the correct pattern and should be retained.

## NoctBoard

### Observed

Before any source is opened, the sidebar presents Security Overview, Threads & Messages, Tasks, Member Roles, Decision Ledger, and Imported Audit. All six lead to the same “No board opened” content. Open actions are duplicated in the sidebar and toolbar, while Sync remains visible but disabled.

### Recommendations

| ID | Simplify or hide | Recommendation | Priority |
|---|---|---|---|
| NB-1 | All content navigation before opening data | Replace with a focused source chooser: **Open Live Board** or **Inspect Audit Export** | High |
| NB-2 | Duplicate open actions | Keep one toolbar action after a source is loaded; use the source chooser before load | High |
| NB-3 | Disabled Sync action | Hide unless a live local board is open | High |
| NB-4 | Imported Audit destination | Show only when an imported audit exists; otherwise offer it from Open | Medium |
| NB-5 | Raw schema, digest, event IDs, and credential handles | Put in expandable Evidence/Technical Details sections | Medium |
| NB-6 | Every section for every source type | Show only applicable live-board or imported-audit destinations | Medium |

Do not demote accepted/rejected decisions, source type, unsigned-export status, history attestation, or fixture/live provenance. Those are the product's trust boundary.

## NoctGallery

### Observed

The Gallery and photo-detail flows are focused. The third primary tab, **Share**, is a static four-step explanation rather than a workflow. Settings exposes codec fallback, maximum edge, quality, read-only storage facts, and temporary-file cleanup even when no temporary files exist.

### Recommendations

| ID | Simplify or hide | Recommendation | Priority |
|---|---|---|---|
| NG-1 | Share Privacy tab | Remove it; move a concise summary to the share sheet and a fuller explanation to Help/Privacy | High |
| NG-2 | Permanent search row for very small libraries | Use a collapsible native search affordance; keep search readily available for large libraries | Low |
| NG-3 | Top-right refresh button | Prefer automatic observation/pull-to-refresh; show retry only after a load failure | Medium |
| NG-4 | Maximum edge, codec fallback, and lossy quality | Put in **Advanced Share Defaults**; conditionally show quality only for lossy formats | Medium |
| NG-5 | Read-only “Private media copies” and “Source of truth” rows | Move to Privacy/About | Low |
| NG-6 | Clear Temporary Share Files when none exist | Hide until cleanup is possible; retain in Advanced/Privacy as recovery | Medium |
| NG-7 | Duplicate capture date on photo detail | Keep either the navigation title or Captured row, not both | Low |
| NG-8 | Repeated on-demand/iCloud helper text | One short line with an info button | Low |

The warning that decoy metadata is not anonymity must remain visible immediately before that advanced action.

## Noctweb Browser

### Observed

The fresh window simultaneously shows an empty bookmark/history sidebar, a single “New Tab” strip, an unresolved address, back/forward, refresh, relay, disabled bookmark, verification, new-tab, and a central Browse Noctweb card. Opening verification before a publication resolves creates an empty third pane. The relay chooser can surface raw HTTP status and redacted-body byte information as primary feedback.

### Recommendations

| ID | Simplify or hide | Recommendation | Priority |
|---|---|---|---|
| WB-1 | Empty library sidebar | Auto-collapse until the user has a bookmark/history item; keep its toolbar toggle | High |
| WB-2 | Single-tab strip | Hide until a second tab exists | High |
| WB-3 | Default `noct://untitled…` address | Start with an empty field and instructional placeholder | High |
| WB-4 | Refresh, bookmark, and verification when unresolved | Disable visually or hide until there is a resolved page | High |
| WB-5 | Empty verification side pane | Use a status popover; open a full pane only when evidence exists | High |
| WB-6 | Duplicate Enter Address/Choose Relay paths | One primary Browse field; relay status remains a compact secondary control | Medium |
| WB-7 | Raw HTTP/body diagnostics | Plain-language error first, raw diagnostics under Details/Copy Diagnostic | Medium |

Publication signature/hash state, relay identity, and an unsafe or unverifiable result must remain prominent once a page resolves.

## Noctweb Lab

### Observed

- New Site appears in the sidebar and as a top plus action.
- Preview exists in the sidebar and again as an editor mode.
- Site selection is repeated in the top picker and page strip.
- Settings has one true preference—Theme—surrounded by Workspace Storage, Publication Security, Routing Policy, and Hosted Profile documentation cards.
- Relays exposes suffix, a full namespace hash, latency, connection actions, and a large “What a successful connection proves” card at once.

### Recommendations

| ID | Simplify or hide | Recommendation | Priority |
|---|---|---|---|
| WL-1 | Duplicate New Site/Sites controls | One site switcher with a New Site action | High |
| WL-2 | Sidebar Preview | Keep Design/Code/Preview as editor modes; remove the duplicate global destination | High |
| WL-3 | Settings technical cards | Keep actionable preferences; move the rest to **Technical details** or About Security | High |
| WL-4 | Relay suffix, namespace hash, and latency | Details disclosure on each configured endpoint | High |
| WL-5 | Permanent proof essay | One “Verified hosting means…” info disclosure | Medium |
| WL-6 | Publisher/key/relay icons in the editor header | One labeled publication-status menu | Medium |
| WL-7 | Draft validation prose | Compact status pill; expand only for validation errors | Low |

Keep Code as a first-class mode for agent-built sites. The simplification target is duplicated navigation and background protocol detail, not capable editing.

## NoctweaveJS web client, desktop wrapper, and group companion

### Recommendations

| ID | Simplify or hide | Recommendation | Priority |
|---|---|---|---|
| JS-1 | Unlock/onboarding card anchored near the upper-left of wide windows | Center it in the viewport and use a slightly larger readable width | High |
| JS-2 | Appearance selector on the security gate | Move to post-unlock Settings or a small menu | Low |
| JS-3 | Six implementation-oriented destinations | Mirror the proposed Chats, People, and You structure | High |
| JS-4 | Empty search/list plus two equivalent contact calls to action | Hide search and collapse the list column until a conversation exists; keep one Add Contact action | High |
| JS-5 | Permanent manual refresh | Background refresh; show retry on failure | Medium |
| JS-6 | Group composer before a group is selectable | Hide conversation and composer until companion setup and group selection complete | High |
| JS-7 | “Experimental runtime” and protocol-boundary copy in daily chrome | Retain as one info disclosure and documentation link | Medium |
| JS-8 | Fixed-width group and desktop layouts | Center or stretch the workspace to use the available window | High |

The local/no-account-recovery acknowledgement belongs in onboarding and must remain explicit before persona creation.

## Relay products: native app, Relay Desktop, and Operator Console

The largest simplification is clarifying responsibility between surfaces:

- **Relay Desktop launcher:** install/build, start/stop, basic status, and Open Console.
- **Operator Console:** live relay policy and configuration.
- **Native Relay app:** either the primary native operator experience or an advanced standalone distribution—not a third copy of every setup control.

This role decision should be approved before individual relay screens are rearranged.

### Relay Desktop launcher

| ID | Simplify or hide | Recommendation | Priority |
|---|---|---|---|
| RD-1 | Runtime setup after the first successful launch | Collapse into a summary with Edit Advanced Setup | High |
| RD-2 | Raw TCP, HTTP/WS, and operator ports | Advanced Setup | High |
| RD-3 | Rendezvous and trusted-proxy controls | Advanced Setup with consequence-focused warnings | High |
| RD-4 | Four separate console/credential buttons | Open Console primary; credentials in one protected Credentials menu | High |
| RD-5 | Logs section while stopped and healthy | Hide until running, error, or user explicitly opens Diagnostics | Medium |
| RD-6 | Permanent Docker/Noctweb warning blocks | Show at first build or when exposure/hosting changes; retain in Help | Medium |
| RD-7 | Narrow left-aligned content column | Center or stretch to a desktop-appropriate maximum width | High |

### Native Relay and authenticated Operator Console

| ID | Simplify or hide | Recommendation | Priority |
|---|---|---|---|
| RO-1 | Full read-only runtime profile on Overview | Show four key facts; expand Full Runtime Details | High |
| RO-2 | Advanced listener, storage, federation-peer, and protocol-module fields | Basic/Advanced split within their existing sections | High |
| RO-3 | Login card near the upper-left | Center it in the viewport | Medium |
| RO-4 | Technical capability explanations repeated on every section | Contextual info disclosures and one durable operator guide link | Medium |
| RO-5 | Disabled actions for unavailable runtime capabilities | Hide unless enabling prerequisites is the next action | Medium |

Always keep the following relay facts visible: running/stopped, public exposure, federation mode, memory-only versus persistent storage, TLS/trusted-proxy state, client endpoint, and unresolved startup/security errors.

## Noctweb Publisher

### Observed

The default workspace occupies roughly half a wide browser window. A large principle statement, publisher identity card, theme selector, Reset Draft, Host Revision, design/code/preview modes, editor, and an empty “Current relay copy” card all appear at once.

### Recommendations

| ID | Simplify or hide | Recommendation | Priority |
|---|---|---|---|
| PUB-1 | Narrow fixed workspace | Center it or use the space for editor + live preview | High |
| PUB-2 | Reset Draft in the primary header | Site overflow menu with confirmation | High |
| PUB-3 | Publisher identity card while healthy | Compact verified/unavailable status; details in a popover | Medium |
| PUB-4 | Button label and destination on every draft | Reveal after enabling a call-to-action block | Medium |
| PUB-5 | Empty Current Relay Copy section | Hide until a hosted revision exists | High |
| PUB-6 | Large principle copy after first use | Reduce to a compact page title; retain the trust boundary in Help | Medium |
| PUB-7 | Theme selector in the work header | Settings/menu | Low |

Host/verification failure, the active publisher scope, signed-revision status, and the distinction between relay hosting and ownership/finality must remain clear.

## Information that should not be hidden

| Boundary | Minimum always-visible signal |
|---|---|
| Messaging encryption | Secure/failed/locked/stale state for the active conversation |
| Persona scope | Active persona before changing persona-scoped data |
| Invitation scope | One-use invitation; no global public identity |
| Relay trust | Human-readable reachability and verification state |
| Federation | Current mode when it changes routing/trust behavior |
| Relay exposure | Loopback/private/public and TLS/trusted-proxy consequence |
| Storage | Memory-only versus persistent and consequences of removal |
| Publisher/browser verification | Verified, unverified, changed, or unavailable |
| NoctGallery advanced decoys | Image/account/timing/network context can still identify origin |
| NoctBoard provenance | Live, fixture, imported, unsigned, accepted/rejected, and attestation status |
| Destructive actions | Clear label and consequence, even when placed in an overflow menu |

## Suggested approval batches

### Batch 1 — Low-risk progressive disclosure

- Hide unavailable/disabled actions until relevant.
- Collapse raw IDs, hashes, ports, byte counts, latency, runtime profiles, and proof essays under Details.
- Hide NoctBoard destinations before data opens.
- Hide single-tab strips, empty voice-room sections, empty logs, and empty hosted-copy cards.
- Center fixed-width authentication and setup cards.

### Batch 2 — Primary navigation reductions

- Noctweave and NoctweaveJS: Chats / People / You.
- NoctGallery: Gallery / Settings, with privacy guidance in the share workflow.
- Noctweb Lab: remove duplicate Preview and duplicate New Site controls.

### Batch 3 — Relay product-role decision

- Decide which surface owns lifecycle, policy, and advanced native operation.
- Remove duplicated configuration only after that decision.

## Visual evidence index

- [Noctweave macOS live conversation](audit_evidence/2026-08-25/noctweave-live-conversation.jpg)
- [Noctweave iPhone Chats](ui_audit_evidence/2026-08-26/noctweave-iphone-chats.jpeg)
- [Noctweave iPad conversation](ui_audit_evidence/2026-08-26/noctweave-ipad-conversation.jpeg)
- [NoctGallery iPhone library](ui_audit_evidence/2026-08-26/noctgallery-iphone-library.jpeg)
- [Noctweb Browser empty state](ui_audit_evidence/2026-08-26/noctweb-browser-empty.jpeg)
- [Noctweb Lab default editor](ui_audit_evidence/2026-08-26/noctweb-lab-default.jpeg)
- [NoctweaveJS persona gate](ui_audit_evidence/2026-08-26/noctweavejs-persona-onboarding.png)
- [NoctweaveJS group companion](ui_audit_evidence/2026-08-26/noctweavejs-group-companion.png)
- [Relay Desktop launcher](ui_audit_evidence/2026-08-26/relay-desktop-launcher.png)
- [Operator Console login](ui_audit_evidence/2026-08-26/operator-console-login.png)
- [Noctweb Publisher default workspace](ui_audit_evidence/2026-08-26/noctweb-publisher-default.png)
- [NoctCord live conversation](/Users/luiz/Desktop/Projects/NoctCord/docs/audit-evidence/2026-08-25/noctcord-live-conversation.jpg)
- [NoctBoard empty audit console](ui_audit_evidence/2026-08-26/noctboard-empty.jpeg)
- [Native relay console reference](../docs/assets/NoctweaveRelayConsole.png)

## Decision note

No changes should be implemented until the navigation reductions and relay-surface roles are approved. Batch 1 can be reviewed independently because it changes presentation and disclosure, not protocol behavior or trust boundaries.
