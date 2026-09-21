# README style guide

Use this shared structure across the Noctweave repositories. A README should
help a new reader understand the project, run the smallest useful workflow,
and find the right technical reference without reading every implementation
detail first.

## Project pages

Use the same order for repository roots and runnable app/package entry points:

1. **Masthead:** existing local artwork when available, one title, one concrete
   sentence, and compact jump links.
2. **Overview:** who the project is for and what it does, followed by a small
   platform / stack / license table. Put experimental or release status here.
3. **Quick start:** verified prerequisites, the command working directory, the
   shortest useful command sequence, and the expected result.
4. **Features:** outcomes a reader can scan. Use tables for parallel
   capabilities and an existing product screenshot where it adds information.
5. **Security and privacy:** authorities, data visibility, storage limits,
   hardware requirements, and unresolved assurance boundaries.
6. **Development:** tests, build variants, or packaging when they are separate
   from first-run setup.
7. **Documentation:** descriptive links paired with their purpose.
8. **License:** link to the license that actually governs this component.

Add named workflow or architecture sections where the product needs them.
Do not manufacture a feature, status, screenshot, or build command just to
fill a section. Small packages may combine testing with Quick start.

## Reference pages

Fixtures, evidence bundles, protocol workbenches, and test harnesses use a
shorter variant: **Overview → Getting started → Reference → Related
documentation**. State the intended reader and working directory. A fixtures
README should explain how data is generated; an evidence README should keep
passing, failing, skipped, and unverified results distinct.

## Writing and appearance

- Use sentence case headings, short paragraphs, and concrete verbs.
- Keep one H1. Use existing local icons at 112 px in the masthead; do not add
  remote artwork or a row of unverified status badges.
- Keep top navigation to a few useful anchors. Use ordinary Markdown tables,
  code fences with a language, meaningful image descriptions, and GitHub-safe
  HTML for the masthead and optional details.
- Keep required warnings and setup constraints visible. Details blocks are
  suitable for extra screenshots and long reference indexes.
- Use relative links within one repository and explicit repository URLs
  across repositories. A sibling checkout is not a portable documentation URL.
- Prefer a linked guide for long API, CLI, or operator examples. Preserve old
  section anchors when moving or renaming content.
- Check requirements against manifests and commands against scripts. Do not
  present an internal review as an independent security audit, an archive as
  a public release, or a skipped test as a pass.
- Verify links and images against tracked files, then inspect a rendered
  desktop and narrow-width view. Markdown source alone does not establish
  visual quality.

## Copyable project skeleton

````markdown
<h1 align="center">Project name</h1>

<p align="center"><strong>One concrete sentence about the project.</strong></p>

<p align="center">
  <a href="#overview">Overview</a> ·
  <a href="#quick-start">Quick start</a> ·
  <a href="#features">Features</a> ·
  <a href="#security-and-privacy">Security</a> ·
  <a href="#documentation">Documentation</a>
</p>

## Overview

Explain the project and its intended reader.

| Detail | At a glance |
| --- | --- |
| Platform | Verified target platforms |
| Built with | Principal tools or libraries |
| License | [Verified license](LICENSE) |

> **Status:** State a meaningful release or assurance limit, if applicable.

## Quick start

State prerequisites and the working directory.

```sh
# Verified setup and run commands.
```

Explain the expected result.

## Features

Describe the main user-facing capabilities.

## Security and privacy

Describe the actual trust and data boundaries.

## Development

Explain relevant tests or packaging steps.

## Documentation

| Read | For |
| --- | --- |
| [Guide title](path/to/guide.md) | The question this guide answers |

## License

Link to the applicable license and dependency notices.
````
