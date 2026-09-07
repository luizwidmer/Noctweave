# Published evidence handling

This directory contains selected results from the 7 September 2026 local audit.
Before publication, home and project-root paths were replaced with `<HOME>` and
`<PROJECTS>`, and hardware and simulator identifiers were redacted. Test results,
source-file hashes and test-log hashes were not changed. `sourceLogSHA256` values
identify original full local logs; `sha256-manifest.json` identifies the published
files, including sanitized excerpts.

The original Publisher screenshot includes a browser profile avatar. It remains
in the local evidence archive and is omitted here; the Publisher accessibility
transcript remains available under `validation/publisher-hosted-ax.txt`. Published
images show isolated test profiles and synthetic content and are otherwise
unchanged.

The original report and complete original evidence, including their original
manifest, are retained under the ignored `.runtime/audit-2026-09-07/` directory.
The repository-state snapshot records the working tree at audit close, before
commits. Existing Xcode user-scheme ordering and earlier August audit files remain
local and are excluded from publication. No production deployment or release is
part of this publication.
