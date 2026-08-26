# Noctweave ecosystem UI change report — 2026-08-26

## Disposition

This report records the UI simplification work implemented after the
25–26 August 2026 visual audit. It covers every Git repository in the local
Noctweave application workspace, not only the parent checkout:

1. `PICCP Project`
2. `PICCP Project/Noctweave Messaging Client`
3. `PICCP Project/Noctweave Relay`
4. `PICCP Project/NoctweaveJS`
5. `NoctCord`
6. `NoctBoard`
7. `NoctGallery`
8. `noctweave-net`

The implementation reduces primary navigation, gives empty states one clear
next step, hides inactive maintenance controls, moves technical evidence behind
contextual disclosures, and makes narrow desktop workspaces use their windows
more effectively. Security and trust consequences remain visible.

No protocol, cryptographic, relay-trust, application-identity, or persistence
boundary was changed by this UI pass.

The local `ui_simplification_audit_2026-08-26.md` remains the discovery and
recommendation snapshot. This file is its implementation companion and
supersedes the audit's original “recommendations only” status for the items
listed below.

## Published implementation commits

| Repository | Surfaces | Commit | Branch |
|---|---|---|---|
| Noctweave | Relay Desktop, Operator Console, Noctweb Publisher | `f980ae4` | `main` |
| Noctweave Messaging Client | iPhone, iPad, and macOS client shell | `e586857` | `main` |
| Noctweave Relay | Native macOS relay | `68d9ce2` | `main` |
| NoctweaveJS | Browser client, desktop wrapper, group companion | `787d7e2` | `main` |
| NoctCord | Native community client | `9265f72` | `main` |
| NoctBoard | Native audit console | `3acb255` | `main` |
| NoctGallery | Native iPhone gallery | `fbc3095` | `main` |
| noctweave-net | Noctweb Browser and Noctweb Lab | `ca1f3dc` | `main` |

All eight UI commits were pushed to their configured `origin/main` branches and
were verified at local/remote parity.

NoctBoard's persistently failing GitHub workflows were subsequently removed in
`1b08942` and explicitly disabled in GitHub. That operational correction is not
part of the UI change set, but it affects how future Board verification is run:
tests are local until a reliable CI design is approved.

## Cross-product outcomes

### Navigation now represents user goals

- The Messaging Client and NoctweaveJS now lead with **Chats**, **People**, and
  **You** instead of exposing contacts, one-use codes, relays, persona identity,
  settings, and files as equal top-level destinations.
- NoctGallery now has **Gallery** and **Settings** only. The documentation-only
  Share tab was removed.
- Noctweb Lab no longer repeats Preview and New Site in multiple navigation
  locations.
- NoctBoard does not reveal six empty destinations before a source is opened.

### Healthy automation stays quiet

- Manual sync and refresh controls are hidden during healthy operation.
- Retry and diagnostics appear when work is active, stale, or failed.
- Empty logs, voice rooms, hosted-copy cards, and cleanup actions do not occupy
  daily UI.
- Unavailable actions are hidden when they are not the next useful step.

### Technical evidence is progressively disclosed

- Raw identifiers, digests, ports, listener addresses, storage paths, relay
  suffixes, namespace hashes, latency, credentials, and runtime profiles moved
  into Evidence, Diagnostics, Advanced, or Technical Details disclosures.
- Human-readable consequences remain visible: secure or failed conversation,
  live or imported Board source, relay exposure, storage durability, federation
  mode, TLS/proxy state, publication verification, and attachment availability.

### Empty states have one primary action

- NoctBoard starts with **Open Live Board** and **Inspect Audit Export**.
- Noctweb Browser starts with an empty address field and a single browsing path.
- NoctweaveJS hides empty relationship chrome and duplicate Add Contact actions.
- The group companion hides its conversation and composer until a group can be
  selected.

### Desktop layouts use available space

The NoctweaveJS gate and group companion, Relay Desktop, Noctweb Publisher, and
other fixed-width workspaces were centered or widened while retaining readable
line lengths inside cards and disclosures.

## Changes by product

### Noctweave Messaging Client

Implemented audit items `NW-1` through `NW-9`:

- Consolidated Contacts and My Code into **People**.
- Added **You** as the home for Relays, Persona, and Settings.
- Moved Files into the Chats toolbar.
- Hid global phone navigation inside a conversation.
- Moved Join Group and File Gallery into contextual overflow actions.
- Replaced permanent manual sync with active, failed, and retry states.
- Moved secure-route refresh into diagnostics and renewal-error handling.
- Shortened relay guidance and defaulted relationship wording to **Secure chat**.
- Added stable accessibility identifiers for the new You destinations.

Preserved: active persona scope, one-use invitations, conversation security
state, relay availability, and access to verification details.

### NoctCord

Implemented `NC-1` through `NC-4`:

- The member inspector is collapsed by default.
- Empty Voice Rooms sections are hidden; text, voice, and invitation creation
  live in one add menu.
- Duplicate first-connect relay helper text was removed while the existing
  advanced relay and call-network disclosures remain.
- Attachment cards keep encryption and availability visible while exact byte
  count and expiry timestamp live in an info menu.

`NC-5`, further compression of repeated profile-isolation wording, was retained
for a later copy-specific review because that language communicates a security
boundary and was not required to resolve layout crowding.

### NoctBoard

Implemented `NB-1` through `NB-6`:

- Replaced the empty six-destination sidebar with a focused source chooser.
- Consolidated opening into one contextual action after load.
- Shows Sync only for a live local board.
- Shows Imported Audit only when imported evidence exists.
- Places schema, digests, event IDs, credential handles, and source proof under
  Evidence or Technical Details.
- Filters destinations to the active source type.

Preserved: live/imported/fixture provenance, unsigned-export warnings,
accepted/rejected decisions, history attestation, and redaction boundaries.

### NoctGallery

Implemented `NG-1` and `NG-3` through `NG-8`:

- Removed the Share Privacy tab and kept concise privacy guidance at the share
  action.
- Removed the permanent refresh button in favor of observation and native
  pull-to-refresh.
- Moved maximum edge, codec fallback, and quality into Advanced Share Defaults.
- Hides quality for PNG and keeps HEIC fallback copy concise.
- Moved read-only storage/privacy facts into a disclosure.
- Shows temporary-file cleanup only when temporary exports exist.
- Removed duplicate capture-date presentation and shortened iCloud guidance.

The advanced decoy warning still states that altered metadata is not anonymity.
`NG-2` did not require a source change: the gallery retains SwiftUI's native
collapsible `.searchable` affordance rather than adding custom permanent search
chrome.

### Noctweb Browser

Implemented `WB-1` through `WB-6`, with `WB-7` partially implemented:

- The empty bookmark/history sidebar starts collapsed and collapses again when
  its last saved item is removed.
- The tab strip appears only when more than one tab exists.
- New tabs use an empty address field with an instructional placeholder.
- Navigation, reload, bookmark, and trust actions appear only when applicable.
- Verification starts as a compact status popover and opens the evidence pane
  only when evidence exists.
- The empty state no longer duplicates address and relay calls to action.
- Verification errors are contextual; deeper relay connection diagnostics were
  left available in the relay panel rather than redesigned in this pass.

Publication signatures, hosted-object state, and relay trust evidence remain
available whenever a page resolves.

### Noctweb Lab

Implemented `WL-1` through `WL-6`:

- Consolidated site selection and New Site into one control.
- Removed the duplicate global Preview destination.
- Reduced Settings to actionable appearance controls plus Technical Details.
- Moved relay suffix, namespace hash, and latency into endpoint details.
- Replaced the permanent verification essay with an info disclosure.
- Unified publisher identity and relay access into one publication-status menu.

`WL-7` was not separately changed because validation already expands around
actionable errors; no new always-visible validation prose was introduced.

### NoctweaveJS

Implemented `JS-1` through `JS-8`:

- Centered and widened the encrypted-persona gate.
- Moved Appearance out of the locked security gate.
- Adopted Chats, People, and You navigation.
- Hid the empty relationship list, duplicate Add Contact path, and inactive
  sync, retry, and mute controls.
- Uses background refresh and contextual retry.
- Hides the group conversation and composer until a group is selected.
- Moves runtime/protocol explanation into secondary information.
- Centers or stretches browser, desktop, and group-companion workspaces.

The no-account-recovery acknowledgement remains mandatory before persona
creation.

### Relay Desktop

Implemented `RD-1` through `RD-7`:

- Treats the desktop surface as a launcher for build/install, start/stop,
  status, and **Open Console**.
- Collapses setup after a successful image build.
- Moves ports, rendezvous, trusted-proxy, and exposure details into Advanced.
- Consolidates protected credentials into one menu.
- Shows logs and diagnostics only when running, failing, or explicitly opened.
- Moves Docker and hosting warnings into contextual Help.
- Widens and centers the launcher workspace.

### Native Relay and Operator Console

Implemented `RO-1` through `RO-5`:

- Overview pages now lead with four consequential facts rather than full runtime
  inventories.
- Listener, storage, federation, protocol, and disk-path detail lives in Basic,
  Advanced, or Full Runtime Details disclosures.
- The Operator login card is centered.
- Repeated capability explanations became contextual disclosures.
- Dependent controls are hidden when their runtime capability is unavailable.

Always visible: running/stopped state, endpoint, public exposure, federation
mode, memory-only versus persistent storage, TLS/proxy consequence, and active
startup/security errors.

### Noctweb Publisher

Implemented `PUB-1` through `PUB-7`:

- Widened and centered the workspace.
- Moved Reset Draft and Appearance into the More menu.
- Collapsed publisher identity into status plus details.
- Reveals call-to-action label and destination only after CTA is enabled.
- Hides Current Relay Copy until a hosted revision exists.
- Replaced the large principle statement with a compact title.
- Keeps Host Revision as the primary publishing action.

Publisher scope, signed-revision status, host verification failure, and the
distinction between relay hosting and ownership remain clear.

## Additional defects found during rendered QA

The implementation pass found and fixed three presentation defects that were
not explicit audit recommendations:

1. Publisher's `.publication-card { display: flex; }` overrode the HTML
   `hidden` attribute, revealing an empty hosted-copy card. A global
   `[hidden] { display: none !important; }` rule and regression test now enforce
   the intended state.
2. Native Relay still printed the exact disk path above its new Advanced disk
   location disclosure. The path now appears only inside that disclosure.
3. NoctweaveJS's empty relationship fixture could show inactive Sync, Retry,
   and Mute controls before hydration. The HTML now fails closed and runtime
   rendering also hides Mute without a selected relationship.

The Messaging Client's new You rows also exposed missing accessibility
identifiers during UI testing; stable identifiers were added and the failed
tests passed on rerun.

## Verification evidence

| Product | Automated verification | Rendered verification |
|---|---|---|
| Messaging Client | macOS and iOS builds passed; the two failed accessibility regressions passed after correction | iPhone Chats, People, You, and conversation navigation |
| Native Relay | 15 tests passed with an ad-hoc signed test host and volatile test Keychain path | Overview, Profile, Storage, and Advanced disk location |
| Relay Desktop | TypeScript typecheck and 9 desktop tests passed | Expanded and collapsed launcher setup |
| Operator and Publisher | Relay Server full suite: 150 tests passed; focused Publisher regression suite: 7 passed | Login, Overview, Noctweb host view, and fresh Publisher workspace |
| NoctweaveJS | Full suite: 220 tests passed before final empty-state hardening; focused final shell suite: 10 passed | Persona gate, group companion, Chats, People, and You |
| NoctCord | Changed-area app-model suite: 18 tests passed | Populated community, conversation, attachment, and Privacy sheet |
| NoctBoard | 34 tests passed with 3 configured relay-integration skips | Focused live-board/audit source chooser |
| NoctGallery | iOS simulator build passed | Gallery and Settings |
| Noctweb Browser | 28 tests passed with 1 configured live-host skip | Fresh empty browser and relay-selection state |
| Noctweb Lab | 69 non-WebKit tests and 3 WebKit tests passed; 2 configured live-host skips | Sites, Settings, and Relays |

All repository diffs passed `git diff --check` before publication.

## Test-safety and privacy controls

- Native visual tests used DEBUG-only fixtures, volatile/file-backed test state,
  memory-only relay storage, and synthetic credentials.
- No production Keychain item, machine administrator password, or user message
  state was read or modified.
- No Keychain or OS authentication prompt was accepted.
- At most two app instances were open during exchange-oriented testing, and all
  task app processes were closed afterward.
- Existing simulators were reused; none were created, erased, or deleted.
- Task-specific DerivedData, temporary app copies, and loopback servers were
  removed after verification.

## Residual limitations and intentional exclusions

- NoctCord's unrelated full media-integration run encountered restricted
  loopback behavior and later hung in the media tests. The changed UI model
  suite and rendered app passed; this report does not claim a fresh complete
  media-suite result for the UI commit.
- Relay Desktop's visual fixture validated the current HTML/CSS states. Its
  runtime-dependent hiding was additionally covered by typecheck and desktop
  tests rather than a live Docker lifecycle during the screenshot pass.
- NoctBoard's CI is intentionally absent because every recorded workflow run
  failed. Local test evidence is retained above; no replacement automation is
  claimed.
- Raw visual-audit captures remain local review evidence and are intentionally
  excluded from the published source changes.
- This is product-level UI verification, not accessibility certification,
  independent usability research, notarization, or production-network testing.

## Review checklist

The most consequential decisions for product review are:

1. Confirm that Chats, People, and You provide the right messaging hierarchy on
   both compact and regular-width devices.
2. Confirm that the relay product split is understandable: Relay Desktop owns
   lifecycle, Operator Console owns live policy, and Native Relay remains the
   advanced standalone operator surface.
3. Confirm that hidden maintenance controls still surface quickly enough during
   stale, failed, or security-relevant states.
4. Confirm that Evidence, Diagnostics, Advanced, and Technical Details preserve
   enough proof for expert users without returning implementation detail to
   primary navigation.
5. Decide whether the deferred NoctCord profile-copy reduction and deeper
   Browser relay-diagnostic redesign merit a separate copy/diagnostics pass.
