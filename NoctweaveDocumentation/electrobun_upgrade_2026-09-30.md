# Electrobun stable upgrade — 2026-09-30

NoctweaveJS and the NoctweaveRelayServer desktop launcher now pin **Electrobun
2.0.2**, replacing the previously resolved 1.18.1. Both desktop suites and
typechecks pass. Both checked stable builds produce fresh macOS arm64 app
archives, update manifests, installer wrappers and DMGs. This replaces the
signal-killed build tool recorded in the earlier
[harness audit](test_harness_audit_2026-09-30.md).

This was an authorized dependency upgrade and compatibility check. No commit,
push, publication, branch change, Apple submission or macOS security-setting
change was performed. Existing unrelated harness improvements were preserved.
The native GUI relay and Gallery were not changed by this upgrade.

## Release selection and compatibility

The official npm stable selection and GitHub release identify 2.0.2 as the
stable release, published September 29. The available 2.0.3 beta was not used.
The version is pinned exactly in both package manifests and lockfiles, and in
each new `hutch.config.ts`. Sources:
[official release](https://github.com/blackboardsh/electrobun/releases/tag/v2.0.2),
[npm version metadata](https://registry.npmjs.org/electrobun/2.0.2), and
[2.0.2 release notes](https://framework.blackboard.sh/electrobun/guides/changelog/v2-0-2/).

Electrobun 2 uses a dependency-free npm bootstrap, paired Hutch tools and a
generated project SDK. The applications explicitly retain the Bun main
process. They keep application settings in `electrobun.config.ts`, remove
obsolete v1 configuration fields and extend `.hutch/devkit/tsconfig.json`.
Generated files are ignored and were not manually patched. The existing
TypeScript 7 compiler rejects the SDK's inherited legacy `baseUrl`; the project
configuration resets that value to `null` while preserving the SDK aliases.
The installed package bootstrap replaces assumptions about v1 native tools
inside `node_modules`. See the official
[migration guide](https://framework.blackboard.sh/electrobun/guides/migrating-to-v2/)
and [project ownership guide](https://framework.blackboard.sh/electrobun/guides/project-ownership/).

The paired tools are Hutch 0.27.1 and build-time Cottontail 0.7.1. Packaged app
metadata confirms Bun 1.4.0. The machine's existing global Bun remains 1.3.14;
the upgrade did not replace it. Application identifiers, names, version 0.1.0,
native WebView selection, signing and notarization settings were preserved.

Only the shared locked Electrobun selection changed. Its obsolete transitive
graph was pruned: 43 entries in JS and 44 in the relay. No other retained
dependency changed version, and no unrelated dependency was added. The existing
`ip-address: 10.3.1` override remains, although that package is no longer part
of the resolved dependency graph. This is not an advisory-scan result.

## Build checks retained and adapted

The checked runners still reject missing tools, start errors, signals, nonzero
statuses, missing outputs, symlink outputs, empty outputs and unchanged stale
artifacts. They invoke the installed npm bootstrap through Bun; they do not use
an on-demand `bunx` or `npx` package installation. `desktop:prepare` makes the
new tool/SDK preparation step explicit. After preparation, the verified build
uses `DASH_RELEASE_OFFLINE=1` to require cached release files.

Electrobun 2 stable builds produce an installer wrapper around the actual app
archive. The checks now inspect the Zstd archive itself and require matching
app/version/platform/channel/hash and runtime metadata, the real launcher,
bundled Bun entrypoint, main view and macOS icon. Required members must occur
exactly once and contain regular nonempty files. The wrapper must embed the
same archive. Five additional real archive cases cover this layout alongside
the original ten subprocess/output cases.

The relay's previous icon hook updated only the installer. The hook now runs
after building the actual app as well as after wrapping, preserving the
existing icon in both layers. No UI asset was redesigned. Independent package
inspection confirms the actual payload and installer icons match the existing
source files, and that the JS security-key bridge and relay Keychain helper are
included and executable.

## Fresh validation

These are completion timings from the local M4/macOS 27.0.1 environment, not
performance benchmarks. Exact commands, timestamps, exit statuses and logs are
retained under
[`ReleaseArtifacts/ElectrobunUpgrade-2026-09-30/`](../ReleaseArtifacts/ElectrobunUpgrade-2026-09-30/).
The evidence directory is ignored by Git.

| Gate | Final result | Evidence prefix |
| --- | --- | --- |
| JS desktop tests | 15 passed, 0 failed; exit 0, 0.882 s | `js-desktop-tests-final` |
| Relay desktop tests | 29 passed, 0 failed; exit 0, 0.959 s | `relay-desktop-tests-final` |
| JS desktop typecheck | Exit 0, 0.257 s | `js-typecheck-final` |
| Relay desktop typecheck after icon fix | Exit 0, 0.406 s | `relay-typecheck-complete` |
| Full JS protocol suite | 255 passed, 0 failed/skipped; exit 0, 38.150 s | `js-protocol-tests-final` |
| Both explicit prepare scripts | Exit 0; cached SDK preparation | `js-prepare-script`, `relay-prepare-script` |
| JS checked stable packaging | Exit 0, 20.235 s; fresh archive/update/DMG | `js-packaging-complete` |
| Relay checked stable packaging | Exit 0, 19.672 s; fresh archive/update/DMG | `relay-packaging-complete` |
| Independent artifact inspection | Both DMGs verify; payload/wrapper metadata, archives, icons and helpers match | `artifact-verification`, `artifact-validation.json` |

Earlier failed migration checks remain in the evidence directory: inherited
TypeScript configuration, Buffer type compatibility and checks expecting v1
metadata outside the v2 archive. These were corrected before the final passing
gates. The independent inspection also discovered the missing relay payload
icon, which was corrected and rebuilt. Failed attempts are not counted as
passing gates.

An initial read-only DMG inspection failed on macOS `/var` versus
`/private/var` path aliases. The fixture now compares resolved paths and
detaches its mount even if inspection fails. That failed fixture attempt is
retained; the final inspection passed and both temporary mounts were detached.

### Artifact identity

| Project | Artifact | Bytes | SHA-256 |
| --- | --- | ---: | --- |
| JS | `stable-macos-arm64-NoctweaveJS.app.tar.zst` | 21,788,109 | `447978b59e999655292015f1265c11d2c0433ff34e5c0498b31e93a18a8cfa63` |
| JS | `macos-arm64-NoctweaveJS.dmg` | 22,558,105 | `8ff47c1dc6da1d282c8678171d1ca209da5596c8674a0f08c0f9be63599b3658` |
| Relay | `stable-macos-arm64-NoctweaveRelay.app.tar.zst` | 20,775,377 | `cf239b227186f91838757747f1de96fcff83054cbfbd6eefd30af2c2e1f3b11a` |
| Relay | `macos-arm64-NoctweaveRelay.dmg` | 21,552,029 | `c46064626e0537d37e7daab51371846c913f69c8eeeb77bcb21c3e2576274efe` |

Build timestamps and recorded output fingerprints establish freshness. The
installer's embedded archive matches the separate verified app archive. DMGs
were checked with `hdiutil verify` and inspected through temporary read-only
mounts; their metadata, icon and embedded archive match the verified wrapper.
Mounts were detached and extracted inspection bundles were removed.

## Installed tool integrity

The official npm archive's SHA-512 matches registry integrity metadata. All six
installed npm package files in each project match that archive byte for byte.
Separately downloaded official release archives match their GitHub asset size
and SHA-256 digest, and match the installed cached files: all three Hutch
archive members and all 225 regular Electrobun core/SDK members.

| Official release asset | SHA-256 |
| --- | --- |
| `electrobun-hutch-macos-arm64.tar.gz` | `5478ebc6ea25e93b12964615956f8a1cbaf38b9e7da38850e20e1c6aa5022e2b` |
| `electrobun-core-darwin-arm64.tar.gz` | `beaf9a720959a38439cb9aef422351c5e5ca386cebd32d301fe0d48254e64a33` |

Strict `codesign --verify --strict --verbose=2` succeeds for the installed
Hutch, Hutch engine and managed Bun executables. No cached executable was
edited or re-signed. Downloads used the official npm registry and the vendor's
release assets; no unrecognized download source was required. Evidence:
`dependency-scope-final.json`, `installed-hutch-integrity.json`,
`installed-core-integrity.json`, `installed-tool-signatures-final.json`.

## Limits and release follow-up

- This verifies macOS arm64 tooling and packaging. Other operating systems and
  architectures were not built. The official 2.0.2 asset inventory does not
  include a macOS Intel core/SDK asset, so Intel compatibility is not claimed.
- Both configurations retain `codesign: false` and `notarize: false`. Strict
  checking of the packaged launcher returns exit 1 with “code has no resources
  but signature indicates they must be present.” The packaged Bun and checked
  native libraries verify successfully. These are local packages; complete app
  signing, Gatekeeper launch, GUI behavior and notarization were not validated.
- The broad release/security audit was not resumed. The existing general SBOM
  snapshots/policy still describe the previous dependency graph. They need a
  scoped refresh in that release work. The existing `verify-release.sh` guard
  also requires an `ip-address` SBOM component even when the package is absent
  from the new graph. That guard was not weakened or changed here, and the full
  release gate was not run.
- No production protocol, encryption, storage, permission or entitlement change
  was made. Existing native-client Xcode/UI failures from the earlier audit
  are separate and were not retested by this dependency upgrade.

Final source hashes and repository statuses are recorded in
`source-final.json` and `source-hashes.json`. All eight reviewed repository
HEADs and selected `main` branches remain unchanged; unrelated prior audit
files retain their recorded contents. The scoped changes remain uncommitted.
