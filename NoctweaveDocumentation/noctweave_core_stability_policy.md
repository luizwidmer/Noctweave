# NoctweaveCore Stability Policy

The architecture-revision branch defines the Noctweave 1.0 origin. Public APIs,
wire objects, persisted state, CLI behavior, JavaScript models, Linux relay
models, OpenAPI, and test vectors must describe that one architecture.

Research-build state and wire formats are not supported surfaces. Git history
is their record; the 1.0 runtime contains no adapters, aliases, importers, or
dual protocol paths.

## Release numbering

- `1.0.0` freezes the documented stable core.
- `1.x` adds backward-compatible stable API or optional-module features.
- `1.x.y` fixes defects without changing authenticated semantics.
- a post-1.0 breaking public API, wire, or persisted-state change requires the
  next major version and an explicit specification decision.

Experimental modules may change under their explicit profile/version and must
never be presented as part of the stable core.

## Change gate

A public protocol change requires:

1. philosophy-filter review;
2. normative specification and exact field semantics;
3. bounds, errors, downgrade behavior, and metadata analysis;
4. strict positive and negative decoding tests;
5. shared vectors and differential tests for multi-language structures;
6. Swift Core and Linux relay build/test success where applicable;
7. JavaScript tests and desktop type-check where applicable;
8. updated security requirements, extension status, and public documentation.

No release may advertise an optional module solely because models or research
code exist. The runtime and tests must implement the exact advertised methods.
