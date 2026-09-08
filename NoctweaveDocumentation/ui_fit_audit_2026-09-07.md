# Noctweave UI fit review — 7 September 2026

The rendered UI review produced fixes in six repositories: the Apple messaging client, NoctweaveJS, the relay desktop launcher, NoctCord, NoctBoard, and NoctGallery. The other app surfaces were inspected at compact and regular sizes. The saved evidence includes 75 selected screenshots, 48 browser viewport measurements, successful builds, and nine passing UI test executions.

[Open the screenshot gallery](ui_fit_evidence_2026-09-07/index.html) · [Validation records](ui_fit_evidence_2026-09-07/validation.json) · [Browser measurements](ui_fit_evidence_2026-09-07/browser-viewport-results.json)

**Later correction:** The user found macOS welcome-card centering and chat-background coverage defects missed by this pass. The [macOS layout follow-up](ui_chat_layout_followup_2026-09-07.md) records their reproduction, fixes, new screenshots, and three passing macOS UI tests. The evidence and source hashes below describe the earlier snapshot; use the follow-up for the corrected client state.

## Changes verified on screen

| App | Observed issue | Result |
| --- | --- | --- |
| Noctweave macOS | The visible “Pairing direction” label offset the Invite / Join selector. | Centered selector with its accessible label retained. |
| Noctweave iPad | The rectangular rail and separator did not match the inset rounded header. | Continuous 20-point rail corners, an inset border, and consistent outer spacing in portrait and landscape. |
| NoctweaveJS onboarding | Small screens clipped the lower form; the relay field and test action used different heights. | A bounded viewport scroll area reaches the final action. Inputs and relay test action are 46 pixels high with 12-pixel corners; onboarding buttons have a 44-pixel minimum height. |
| NoctweaveJS conversation | The empty-state Add Contact button was clipped; expanded privacy controls could push the composer outside the reachable layout. | Content determines the empty-state minimum height, the conversation scrolls, and the hidden composer label stays inside its own layout. Add Contact and the composer are reachable in compact desktop and mobile views. |
| NoctweaveJS groups | Setup actions touched the preceding field. A selected group’s long identifier forced its conversation grid beyond narrow viewports. | Consistent action spacing, a scrollable mobile page, constrained grid columns, and an ellipsized identifier. The loaded workspace and an encrypted fixture message fit at 320 and 390 pixels. |
| NoctweaveJS desktop | The Groups shortcut led to a page unavailable in the desktop host. | An explicitly unavailable button explains that groups use the browser companion; the native host’s navigation restrictions remain effective. |
| Relay desktop launcher | WebKit’s native select appearance produced short, square controls beside rounded inputs; compact action labels wrapped awkwardly. | Rounded dropdowns match text fields, and action buttons retain their intended width and single-line labels. |
| NoctCord | Compact windows hid both search and members, and the channel header did not align with its sidebar. | Search stays available; members open in a bounded popover below the header with a shorter heading and scrolling for longer lists. The new popover follows capture protection and closes on protected focus loss. Privacy switches use the app’s accent. |
| NoctBoard | Source actions lacked a consistent rounded container; the state-file field shared its width with a long visible label. | Centered rounded entry card, 44-point actions with 12-point corners, and a separately labeled path field with an aligned folder chooser. |
| NoctGallery | Nearly square thumbnails and three-point gaps made the grid feel cramped. | Continuous 12-point thumbnail corners, eight-point spacing, and consistent 16-point side insets on iPhone and iPad. |

## App and platform coverage

“Reviewed” means the app was launched and its rendered state was inspected. Fixture and live-local checks are identified so they are not mistaken for production account or release validation.

| Surface | Sizes / platforms | States and interactions covered | Evidence |
| --- | --- | --- | --- |
| Noctweave Apple client | macOS down to 860 × 592; existing iPhone 17; existing iPad mini A17 Pro, portrait and landscape | Loaded product fixture; Chats, People, You, settings, appearance, Invite / Join, and expanded alternate handoff controls. Final macOS selector and iPad rail inspected. | Gallery: Noctweave client |
| Native Noctweave Relay | macOS down to 900 × 632; light and dark | Operator gate, readiness checks, Overview, Relay Profile, Storage, NoctCord, Noctweb, Transport, and Logs in an isolated app profile. Settings-save limitation below. | Gallery: Native relay |
| NoctweaveJS desktop | Electrobun / WebKit, including 860 × 650 | Created and later unlocked a disposable encrypted persona against the local test relay. Checked the welcome action, unavailable Groups action, expanded relationship controls, and scrolling to the composer. | Gallery: NoctweaveJS |
| NoctweaveJS browser client | Chrome, 1280 × 850, 390 × 844, 390 × 667, and 320 × 568 | Onboarding, light/dark rendering, test-relay alignment, Chats, People, You, pairing, expanded privacy controls, and scrolled composer. | Browser measurements; NoctweaveJS images |
| NoctweaveJS group companion | Chrome, 1280 × 850, 390 × 844, and 320 × 568 | Local Core companion setup, group creation and selection, one-member encrypted message publication, message wrapping, composer, and invitation controls. | Loaded group workspace images |
| Relay desktop launcher | Electrobun / WebKit, including 900 × 720 | Overview, local setup, expanded advanced ports and trust controls, operator links, diagnostics, and appearance. Docker availability was detected; no image build or relay launch was performed through this GUI. | Gallery: Relay desktop launcher |
| Relay web operator console | Chrome, 1280 × 850 and 390 × 844 | Local authentication and all eight destinations: Overview, Relay Profile, Delivery, NoctCord, Noctweb, Storage, Federation, and Privacy research. Resize animations were settled for captures; the existing mobile navigation scrolls correctly. | Operator images and measurements |
| Web Publisher | Chrome, 1280 × 850 and 390 × 844 | Design, Code, and Preview, including responsive layout. | Publisher images and measurements |
| Noctweb Lab | macOS down to 900 × 702; light and dark | Empty workspace, connection to the local test host, local site creation, Design, Code, block editor, and settings. | Gallery: Noctweb Browser and Lab |
| Noctweb Browser | macOS down to 780 × 572 | Start screen, relay selection, connection and pinning of the local test relay, sidebar, and error presentation. | Gallery: Noctweb Browser and Lab |
| NoctCord | macOS, including 980 × 712 | Synthetic community, channel and voice workspace, compact search filtering, member popover, user settings, and capture-protection behavior. | Gallery: NoctCord |
| NoctBoard | macOS, including minimum 960 × 640 | Source chooser, redacted export import and inspection, and encrypted-state opening form. A retained live board was not reopened during this visual pass. | Gallery: NoctBoard |
| NoctGallery | Existing iPhone 17 and iPad mini, including iPad landscape | Existing simulator stock / synthetic images, grid, photo preview and metadata, settings, and advanced sharing layout. The sharing pipeline itself was not changed or re-certified. | Gallery: NoctGallery |
| Example browser client | Chrome, 1280 × 850 and 390 × 844 | Entry/onboarding view. | Browser measurements and example image |

## Verification

- Apple client builds passed for macOS arm64 and iOS Simulator arm64. The initial generic simulator build failed when linking the x86_64 Sync Activity target; the successful build and device runs explicitly used arm64. Intel simulator support is not claimed.
- NoctGallery’s simulator build, the native Relay macOS build, and the NoctBoard, NoctCord, Noctweb Browser, and Noctweb Lab app builds passed.
- NoctweaveJS desktop type checking and its isolated Electrobun development build passed. The relay desktop launcher’s isolated development build and the Linux relay build passed.
- All eight existing iPhone UI tests passed. These ran before the last tablet rail and explicit picker-label adjustment; the focused pairing UI test then passed on the final build on iPad. Final changed native views were also inspected in screenshots.
- The group companion used its explicit development-only plaintext local-state profile inside the ignored review directory. The relay received encrypted group events. The desktop JavaScript app used a separate UI-test state root; these fixtures do not establish production storage or rollback guarantees.
- All 48 saved browser states have document width equal to viewport width. Internal horizontal navigation and vertical content scrolling are intentional. The loaded group view passed at both 320 and 390 pixels after a real encrypted message was published to its isolated one-member group.
- At 390 × 844, onboarding scrolls to its final action (scroll height 1111, scroll top 267). At 390 × 667, the expanded conversation scrolls to the composer (container height 532, scroll height 1217, scroll top 685).
- The new NoctCord popover was present in the accessibility tree while standard capture excluded its contents with capture protection enabled. Its visible layout was then inspected using synthetic preview data with the two preview-only visibility switches temporarily disabled. No real community data was used.

Build/test log excerpts, source hashes, and screenshot hashes are saved alongside the report. Complete local logs and the two Xcode result bundles remain in the ignored `.runtime/ui-fit-2026-09-07/` review directory.

## Remaining limits

The isolated, ad hoc native Relay review profile reported **“Settings persistence failed: Settings could not be written.”** Its local-network readiness probe also timed out, while the listener probe passed. The cause has not been established; successful production signing, settings persistence, and live GUI relay operation are not asserted. The [captured Logs view](ui_fit_evidence_2026-09-07/relay-logs-before.png) preserves this follow-up.

The native messaging client and NoctCord loaded disposable product/preview states. This pass does not certify persistent production startup, two-peer voice calls, every retained NoctBoard workspace, physical iOS devices, release signing, all accessibility text sizes, localization, or every possible error path. Those limits do not negate the rendered layout fixes above, but they prevent a blanket claim that every application state is defect-free.

## Change ownership and cleanup

The ten changed product files belong to six separate repositories. The parent repository does not include the nested/sibling source changes in its own diff. All branches stayed on their selected `main` branch. The validation records preserve the source state at capture time; the reviewed UI source was subsequently committed at the user's request.

Pre-existing August UI evidence and the client’s Xcode user scheme-order change were preserved. Build-generated dependency lockfile changes were restored to their recorded starting contents. Review apps and local services were stopped after verification; only the two existing simulator devices were used, and task-specific Xcode DerivedData was removed. No simulator was created or erased.

## Source commits

| Repository | Commit |
| --- | --- |
| Noctweave Messaging Client, including the macOS follow-up | [74b6bdf](https://github.com/luizwidmer/NoctweaveMessagingClient/commit/74b6bdfd0f6100acf6b7fd696599450abd2bcc0d) |
| NoctweaveJS | [32edef5](https://github.com/luizwidmer/NoctweaveJS/commit/32edef5469f41079b820f4ca36550b62acc5b659) |
| NoctCord | [55f5bbb](https://github.com/luizwidmer/NoctCord/commit/55f5bbb741fa3fccd79398d35ded9d413af9b3a9) |
| NoctBoard | [b4e83f0](https://github.com/luizwidmer/NoctBoard/commit/b4e83f0baaadd2a1256490ba540127e654ca5866) |
| NoctGallery | [6d81fb0](https://github.com/luizwidmer/NoctGallery/commit/6d81fb0d2a5880cc6dfa31f993ca57cb08d4e6c9) |

The relay launcher change, this report, and both evidence sets are included in the parent repository commit containing this report.
