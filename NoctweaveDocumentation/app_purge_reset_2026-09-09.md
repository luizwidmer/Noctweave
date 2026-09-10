# Apple app purge and reset

Implemented locally on 2026-09-09 across the seven Apple apps in the Noctweave workspace. This report covers the reset feature, not completion of the earlier whole-project audit.

## User flow and scope

Every entry point opens a destructive confirmation requiring the exact text `RESET`. Completion returns to initial setup, onboarding, or the app's empty starting workspace. Failures are shown instead of reporting a successful reset.

| App | Entry point | Removed by reset | Result |
| --- | --- | --- | --- |
| Noctweave messaging, macOS and iOS | Settings → Storage Protection → Purge and Reset App | Current and staged duress profiles, chats, attachments, app-lock settings, scoped storage keys, app-owned support files, temporary shares, notifications, and preferences | Finish your onboarding |
| Noctweave Relay, macOS | Sidebar → Reset App… | Operator configuration and identities, saved secrets, local databases and their sidecars, opaque-route snapshots, local hosted content, managed coturn configuration, app-owned support files, and preferences | Initial relay setup |
| Noct Cord, macOS | User Settings → Reset app | Local community/chat state, identity vault and scoped keys, cached attachments, connection profiles, temporary media, app-owned support files, and preferences | Welcome/setup |
| NoctBoard, macOS | Window toolbar → Purge and Reset App | Loaded projection/import state and preferences; the selected live board's state, scoped keys, and admission recovery records when a live file was selected | Source chooser |
| Noctweb Browser, macOS | Settings → Reset app | Tabs, bookmarks, history, relay profile, appearance preferences, website data, and browser caches | Empty unconfigured browser |
| Noctweb Lab, macOS | Settings → Reset app | Local workspaces, publication state, publisher private keys including orphaned keys, local journals, preview data/caches, and preferences | Fresh starter workspace |
| Noct Gallery, iOS and iPadOS | Settings → Reset app | Temporary share copies, cached previews, and all app preferences | Onboarding |

NoctBoard identifies its selected external live-state path in the confirmation. Its imported audit exports and other external files are preserved. Relay removes the exact files belonging to configured databases, including databases used earlier in the running session; it preserves neighboring files and external parent directories.

Photos originals, copies exported or already shared, remote relay/host/IPFS data, other devices, backups, operating-system permissions, and credentials stored on the physical security key are outside local app reset. No reset issues a remote community deletion or revocation. Local storage uses scoped key erasure where supported; identity-free rollback tombstones and shared legacy Keychain material are preserved so resetting one app cannot weaken another store's rollback protection. Filesystem deletion is not a claim of physical overwriting of SSD blocks or backups.

## Interruption and late-write handling

- Noctweave, Relay, Cord, and Lab persist reset intent before destructive cleanup and check it before reopening old state. NoctBoard does the same alongside the selected live state and resumes cleanup when that state is reopened. An incomplete purge keeps its marker and offers retry.
- Messaging retires the old model and storage writers, drains ongoing work, then purges active and every staged duress scope. Multiple windows share the replacement app session.
- Relay retires and drains current and superseded server instances, including accepted connections and persistence callbacks, before removing files. Managed coturn must stop before its configuration is removed. The public `RelayServer.retireAndDrain()` API is terminal; ordinary `stop()` remains restartable.
- Cord and Lab cancel and drain tracked work and direct async operations before deleting storage. Cord discards local realtime subscription capabilities without needing a remote unsubscribe response.
- Board drains imports and synchronization, clears loading flags, and retains the selected security-scoped URL for cleanup retry.
- Browser removes persisted browsing state before async website-data cleanup and rejects stale resolutions and commands during reset. Gallery invalidates export sessions so an old export cannot recreate deleted share files, and explicitly restarts its startup task after reset.

## Validation

All results below are local Debug builds or tests. Tests that delete data used isolated temporary stores, test credentials, or unique review bundle IDs; the user's real profiles were not reset.

| Component | Automated evidence | Rendered review |
| --- | --- | --- |
| Noctweave messaging | macOS and arm64 iPhone Simulator builds passed. Storage harness passed with real isolated Keychain rotation/erasure, old-writer rejection, active/staged full purge, orphan-file removal, and recovery after an injected cleanup failure. | macOS reset card and confirmation reviewed; disposable profile reset returned to Finish your onboarding. |
| Relay | 10 focused reset, vault, and runtime-policy tests passed after final shutdown changes; included model reset/reopen, external-store cleanup, neighbor preservation, and retry after secret-deletion failure. | Sidebar action and confirmation reviewed in an isolated app copy. |
| Core relay retirement | 2 tests passed for terminal retirement and draining suspended work while rejecting new work. | Not applicable. |
| Cord | 59 selected model/core/sanitizer/vault tests passed; 21 model/vault tests rerun after final cleanup changes also passed. | Reset settings and confirmation reviewed; disposable profile reset returned to Welcome. |
| Board | Suite: 35 executed, 3 skipped, zero failures. Final 7 audit-surface tests passed, including the new queued-import/reset regression. External-store purge test also passed after orphan-file cleanup changes. | Toolbar action and confirmation reviewed in an isolated app copy. |
| Browser | Suite: 29 executed, 1 skipped, zero failures. Final 14 app tests executed with 1 skip and zero failures, including commands arriving during reset. | Settings card and confirmation reviewed. |
| Lab | 71 executed, 2 skipped, zero failures, including removal of workspaces and orphan publisher keys. | Settings card and confirmation reviewed with an isolated workspace and memory-only keys. |
| Gallery | 12 tests passed on the existing iPhone 17 simulator; final app build passed. Tests cover preference/onboarding reset, stale-export rejection, and preservation of files outside its export root. | iPhone settings and confirmation reviewed with Photos access denied; RESET enabled the action. No Photos access was granted. |

`git diff --check` passed in all seven repositories (Browser and Lab share the net repository). Review app copies were closed and the simulator was returned to its prior shutdown state.

Validation limits: this is focused reset verification, not a production-signed archive or physical-device certification. Noctweave iOS was compiled for the existing arm64 simulator because its vendored liboqs does not provide x86_64; the build also retains the existing app/extension build-number warning. Gallery's iPad layout and Noctweave's iOS reset UI were not separately rendered in this pass. Broader Cord media/live-transport checks and Relay's bundled-coturn launch check did not finish in the local test runs; they are not counted as passing. The isolated reset suites above completed.

Raw test/build logs are retained locally under `.runtime/purge-reset-2026-09-09/`. Task-specific Xcode DerivedData and disposable review app bundles are removed after verification.
