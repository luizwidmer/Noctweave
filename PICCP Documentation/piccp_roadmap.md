# PICCP Development Roadmap

**Version**: 1.1  
**Last Updated**: June 2026  
**Estimated Timeline to v1.0**: 12-15 months

---

## Overview

This roadmap outlines a realistic development timeline for PICCP, accounting for the complexity of cryptographic systems, security hardening, and the need for external review. The phases are designed to be sequential with some overlap, and each includes explicit security and testing milestones.

---

## Current Implementation Status (Snapshot)

**Implemented in current app + relay builds:**
- ML-KEM/ML-DSA integration (liboqs), PQ prekey bundle flow, and periodic ML-KEM root ratchet.
- Symmetric AEAD message protection with ratchet auto-heal paths for session mismatch recovery.
- Identity rotation, burn/reset, continuity audit logging, and contact continuity controls.
- Relay capabilities including encrypted envelope relay, attachment relay/chunk controls, optional temporal bucketing, and normalized SQLite persistence.
- Federation-mode policy enforcement with curated/open isolation, coordinator-assisted directories, signed snapshots, and bounded open-federation peer exchange experiments.
- MLS-derived relay group messaging flows for create/join/update membership, signed commits, group-ratchet envelopes, member-scoped acknowledgements, and bounded epoch-history recovery.
- Decentralized wake policy advertisement and client-side jittered polling where Apple platform limits permit background work.

**Still pending for full whitepaper parity:**
- Full cryptographic PIR or mixnet transport path.
- Formal MLS-class group security proof work.
- Public transparency/auditable continuity log model.

**Tracking file:** See `TODO.md` in repo root for active checklist items.  
**Note:** Phase sections below remain the long-horizon plan. Checked items reflect repository evidence in the current Noctyra client, Noctyra Relay, documentation, or automated tests. Unchecked items either need external review, formal proof work, published benchmarks, full release/beta evidence, or a deliberately different product target such as a separate CLI/Electron client.

**Easy-first pass status:** Completed easy, repository-owned items in this pass include Phase 0 protocol/API/security documentation, evidence-backed checkbox alignment, HTTP security headers, and basic relay request rate limiting. Remaining unchecked items are not classified as easy-first work because they require external audit, formal or side-channel analysis, fuzzing infrastructure, coverage/benchmark instrumentation, operational dashboards, separate CLI/third-party client products, or real beta/launch/community evidence.

---

## Phase 0: Specification Finalization
**Duration**: 3-4 weeks  
**Team**: 1-2 people  

### Objectives
- Freeze core cryptographic protocol specification
- Define wire formats and message structures
- Specify relay API contracts
- Document test vectors for all cryptographic operations

### Deliverables
- [x] Complete protocol specification (PICCP v1.0 spec): `piccp_protocol_spec_v1.md`
- [x] Wire format documentation with test vectors: `wire_format_and_test_vectors.md`
- [x] Relay API specification (OpenAPI/Swagger): `noctyra_relay_openapi.yaml`
- [x] Threat model refinement
- [x] Security requirements document: `security_requirements.md`

### Dependencies
- Community feedback on whitepaper
- Review by at least 2 external cryptographers (informal)

### Success Criteria
- No major protocol changes anticipated
- Test vectors verified by independent implementation
- Consensus on core design decisions

### Risks
- Scope creep (new feature requests during review)
- Fundamental design flaws discovered late

**Contingency**: Budget 1 additional week for addressing critical feedback

---

## Phase 1: Cryptographic Core Implementation
**Duration**: 2.5-3 months  
**Team**: 1-2 people with cryptography experience  

### Objectives
- Implement ML-KEM and ML-DSA integration
- Build key derivation and management layer
- Implement Double Ratchet state machine
- Develop identity rotation mechanism with continuity proofs
- Create comprehensive test suite

### Milestones

#### Milestone 1.1: Primitive Integration (3 weeks)
- [x] ML-KEM-768 wrapper with safe API
- [x] ML-DSA-65 wrapper with safe API
- [x] HKDF-SHA256/HMAC-SHA256 KDF implementation (current Noctyra path)
- [x] AES-256-GCM wrapper
- [ ] Test vectors passing for all primitives
- [ ] Constant-time operations verification

#### Milestone 1.2: Key Exchange (3 weeks)
- [x] Prekey bundle generation and serialization
- [x] X3DH-style initialization protocol
- [x] Session establishment logic
- [x] Initial key derivation
- [x] Test cases: successful exchange, missing prekeys, replays

#### Milestone 1.3: Double Ratchet (4 weeks)
- [x] Symmetric chain key ratchet
- [x] Root key ratchet with ML-KEM
- [x] Out-of-order message handling
- [x] Skipped message key storage (bounded)
- [x] State serialization and recovery
- [ ] Extensive state machine testing (fuzzing)

#### Milestone 1.4: Identity Rotation (2 weeks)
- [x] Rotation proof generation
- [x] Proof verification
- [x] Rotation counter management
- [x] Integration with session state

#### Milestone 1.5: Security Hardening (2-3 weeks)
- [ ] Memory zeroization for sensitive data
- [ ] Side-channel mitigation (timing attacks)
- [ ] Secure random number generation verification
- [x] Key storage encryption at rest
- [ ] Comprehensive fuzzing (at least 100M iterations)
- [ ] Property-based testing for state machine
- [ ] Code review (internal + 1 external reviewer)

### Deliverables
- [ ] `piccp-crypto` library with stable API
- [ ] Test suite with >95% code coverage
- [ ] Fuzzing infrastructure
- [ ] API documentation
- [ ] Security audit report (self + external)

### Dependencies
- Specification freeze (Phase 0)
- ML-KEM/ML-DSA reference implementations (available)

### Success Criteria
- All test vectors passing
- Fuzzing reveals no crashes or hangs
- External review finds no critical issues
- Performance benchmarks within acceptable range (<5ms per message)

### Risks
- **HIGH**: Subtle bugs in ratchet state machine
- **MEDIUM**: Performance issues with PQ primitives
- **MEDIUM**: Memory safety issues

**Contingencies**:
- Allocate 2 additional weeks for unexpected complexity
- Budget for external cryptographic review ($2-5K)

---

## Phase 2: Relay Implementation
**Duration**: 6-8 weeks  
**Team**: 1-2 people  

### Objectives
- Build zero-trust relay server
- Implement capability-based routing
- Deploy epoch bucketing and message storage
- Create relay API endpoints
- Develop admin tools and monitoring

### Milestones

#### Milestone 2.1: Core Relay (3 weeks)
- [x] Capability-based mailbox creation
- [x] Message ingestion endpoint
- [x] Epoch bucketing logic
- [x] Normalized SQLite storage backend with row-scoped corrupt-record skip behavior
- [x] Basic rate limiting

#### Milestone 2.2: Message Retrieval (2 weeks)
- [ ] Epoch listing endpoint
- [x] Epoch retrieval with capability auth
- [x] Padding to fixed message sizes
- [ ] Efficient batch operations

#### Milestone 2.3: Operational Concerns (2 weeks)
- [x] Message expiry and cleanup
- [x] Storage quota management
- [x] Logging (minimal, privacy-preserving)
- [ ] Monitoring and metrics (aggregate only)
- [x] Health check endpoints

#### Milestone 2.4: Hardening (1-2 weeks)
- [x] DoS protection (rate limiting, size limits)
- [x] Input validation and sanitization
- [x] TLS configuration
- [x] Security headers
- [ ] Load testing (10K+ messages/hour)
- [x] Failure mode testing

### Deliverables
- [x] `piccp-relay` server application
- [x] Deployment documentation
- [ ] Admin CLI tools
- [ ] Monitoring dashboards
- [ ] Load testing report

### Dependencies
- Finalized relay API spec (Phase 0)
- Cryptographic library for capability generation (Phase 1)

### Success Criteria
- Handles 10,000 messages/hour on single instance
- Sub-100ms p99 latency for message submission
- Passes security scanner (e.g., OWASP ZAP)
- Zero metadata leakage confirmed by review

### Risks
- **MEDIUM**: Storage scaling issues
- **MEDIUM**: DoS vulnerabilities
- **LOW**: Epoch synchronization bugs

**Contingency**: Add 1 week for performance optimization

---

## Phase 3: Client Implementation
**Duration**: 8-10 weeks  
**Team**: 2-3 people  

### Objectives
- Build CLI/API client for testing, diagnostics, and power users
- Implement relay communication layer
- Create contact management system
- Develop local message storage
- Build basic GUI (optional, stretch goal)

### Milestones

#### Milestone 3.1: CLI Foundations (3 weeks)
- [x] Identity creation and management
- [x] Prekey bundle generation and upload
- [x] Mailbox creation and management
- [x] Basic send/receive loop
- [x] CLI interface with clear commands: `NoctyraCLI` supports endpoint normalization, relay health/info, and raw relay requests.

#### Milestone 3.2: Contact Management (2 weeks)
- [x] Contact database (identity keys, mailbox IDs)
- [x] Key verification workflows
- [x] Identity rotation UI
- [x] Trust-on-first-use (TOFU) implementation

#### Milestone 3.3: Message Handling (2 weeks)
- [x] Epoch fetching and decryption
- [x] Message ordering and threading
- [x] Duplicate detection
- [x] Local message storage (encrypted)
- [x] Search and history

#### Milestone 3.4: User Experience (2 weeks)
- [x] Notifications for new messages
- [x] Background epoch polling
- [x] Error handling and user feedback
- [x] Configuration management
- [x] Help documentation

#### Milestone 3.5: Optional GUI (3 weeks, stretch)
- [ ] Basic Electron or Tauri app
- [x] Conversation view
- [x] Contact list
- [x] Settings panel

### Deliverables
- [x] `NoctyraCLI` command-line API client
- [x] User documentation and tutorials
- [x] (Optional) Noctyra SwiftUI GUI application
- [ ] Client library for third-party integrations

### Dependencies
- Crypto library (Phase 1)
- Relay deployed and accessible (Phase 2)

### Success Criteria
- Can send/receive messages reliably
- Key verification workflow is clear
- Local storage encrypted and safe
- User documentation complete

### Risks
- **MEDIUM**: UX complexity confuses users
- **MEDIUM**: Background polling battery impact
- **LOW**: Platform-specific issues

**Contingency**: Skip GUI for v1.0, defer to v1.1

---

## Phase 4: Integration and Testing
**Duration**: 6-8 weeks  
**Team**: 2-3 people  

### Objectives
- End-to-end integration testing
- Multi-client interoperability testing
- Security testing and penetration testing
- Performance benchmarking
- Documentation completion

### Milestones

#### Milestone 4.1: Integration Testing (3 weeks)
- [x] Multi-client message exchange (Alice ↔ Bob scenarios)
- [x] Identity rotation with continuity proofs
- [x] Out-of-order message handling
- [x] Network failure scenarios
- [x] Relay failure and recovery
- [x] Message expiry testing

#### Milestone 4.2: Security Testing (2 weeks)
- [ ] Penetration testing (relay and client)
- [x] Replay attack testing
- [x] Man-in-the-middle testing
- [ ] Side-channel analysis (timing, cache)
- [x] Dependency security audit
- [x] Supply chain verification

#### Milestone 4.3: Performance Testing (1 week)
- [ ] End-to-end latency measurement
- [ ] Bandwidth usage analysis
- [ ] Client CPU and memory profiling
- [ ] Relay scaling tests
- [ ] Battery usage on mobile (if applicable)

#### Milestone 4.4: Documentation (2 weeks)
- [x] User guide (installation, setup, usage)
- [x] Developer documentation (API, architecture)
- [x] Deployment guide (relay setup, hardening)
- [x] Security best practices
- [x] FAQ and troubleshooting

### Deliverables
- [x] Integration test suite
- [x] Security audit report (internal review)
- [ ] Performance benchmark report
- [x] Complete documentation set
- [x] Known issues and limitations document

### Dependencies
- All previous phases complete

### Success Criteria
- All integration tests passing
- No critical security issues
- Performance within acceptable bounds
- Documentation reviewed and approved

### Risks
- **HIGH**: Critical bugs discovered late
- **MEDIUM**: Performance below requirements
- **MEDIUM**: Security vulnerabilities found

**Contingency**: Budget 2-4 additional weeks for critical fixes

---

## Phase 5: External Security Review
**Duration**: 4-6 weeks (mostly waiting)  
**Budget**: $10-25K  

### Objectives
- Engage professional security auditors
- Address findings from external review
- Obtain independent validation of security claims

### Activities
- [ ] Select reputable security firm (e.g., NCC Group, Trail of Bits, Cure53)
- [ ] Provide codebase and documentation
- [ ] Respond to auditor questions
- [ ] Fix identified vulnerabilities
- [ ] Re-review critical fixes
- [ ] Publish audit report (redacted if necessary)

### Deliverables
- [ ] Professional security audit report
- [ ] Fixes for all critical/high findings
- [ ] Public summary of audit (for transparency)

### Success Criteria
- No critical or high-severity findings remaining
- Auditors validate core security claims
- Audit report publishable

### Risks
- **HIGH**: Critical flaws requiring protocol changes
- **MEDIUM**: Budget constraints limit audit scope

**Contingency**: If critical flaws found, budget 4-8 additional weeks for fixes and re-audit

---

## Phase 6: Private Beta
**Duration**: 6-8 weeks  
**Team**: 2-3 people + community testers  

### Objectives
- Deploy to limited set of users (50-200)
- Gather real-world usage feedback
- Monitor for bugs and edge cases
- Iterate on UX based on feedback

### Activities
- [ ] Invite technically savvy early adopters
- [ ] Set up support channels (forum, chat)
- [ ] Monitor relay metrics and logs
- [ ] Collect bug reports and feature requests
- [ ] Release bi-weekly updates
- [ ] Conduct user interviews

### Deliverables
- [ ] Bug fixes for issues found in beta
- [ ] UX improvements based on feedback
- [ ] Stability and reliability metrics
- [ ] Beta testing report

### Success Criteria
- <1% message delivery failure rate
- No critical bugs in 4 consecutive weeks
- Positive user feedback on core functionality
- At least 500 messages exchanged successfully

### Risks
- **MEDIUM**: Major bugs discovered in production
- **LOW**: Low user adoption in beta

**Contingency**: Extend beta by 2-4 weeks if stability issues persist

---

## Phase 7: Public v1.0 Launch
**Duration**: 2-3 weeks  
**Team**: Full team + marketing/community  

### Objectives
- Public release of PICCP v1.0
- Announce to wider audience
- Provide clear onboarding and documentation
- Establish community governance

### Activities
- [ ] Final release candidate testing
- [ ] Launch announcement (blog post, social media)
- [ ] Submit to Hacker News, Reddit, crypto forums
- [ ] Host AMA or launch webinar
- [ ] Monitor launch metrics
- [ ] Respond to community questions

### Deliverables
- [ ] PICCP v1.0 release (clients + relay)
- [ ] Launch blog post
- [ ] Press kit and media outreach
- [ ] Community forum/Discord setup
- [ ] Post-launch retrospective

### Success Criteria
- Stable release with no show-stopper bugs
- Positive reception in crypto/privacy communities
- Clear roadmap for v1.1 and beyond

---

## Timeline Summary

| Phase | Duration | Start | End |
|-------|----------|-------|-----|
| 0: Specification | 3-4 weeks | Week 0 | Week 4 |
| 1: Crypto Core | 2.5-3 months | Week 4 | Week 16 |
| 2: Relay | 6-8 weeks | Week 16 | Week 24 |
| 3: Client | 8-10 weeks | Week 20 | Week 30 |
| 4: Integration Testing | 6-8 weeks | Week 30 | Week 38 |
| 5: External Review | 4-6 weeks | Week 38 | Week 44 |
| 6: Private Beta | 6-8 weeks | Week 44 | Week 52 |
| 7: Public Launch | 2-3 weeks | Week 52 | Week 55 |

**Total Duration**: 12-15 months (55-65 weeks)

**Note**: Some phases overlap (e.g., Client and Relay development)

---

## Resource Requirements

### Team Composition
- **Lead Developer/Cryptographer**: 1 FTE for entire project
- **Backend Developer** (relay): 0.5 FTE for 3 months
- **Frontend/Client Developer**: 0.5-1 FTE for 3 months
- **Security Reviewer/Tester**: 0.25 FTE ongoing
- **Technical Writer**: 0.25 FTE for 2 months

**Total**: ~1.5-2 FTE-years

### Budget (Rough Estimates)
- **Personnel**: $150-250K (depends on location, experience)
- **Security Audit**: $10-25K
- **Infrastructure**: $2-5K (relay hosting, CI/CD)
- **Miscellaneous**: $3-5K (domains, tools, etc.)

**Total**: $165-285K

---

## Success Metrics

### Technical Metrics (v1.0)
- [x] 100% of core test vectors passing
- [ ] >95% code coverage for crypto core
- [x] Zero critical security vulnerabilities
- [ ] <5ms median message encryption/decryption
- [ ] <100ms p99 relay latency
- [ ] Successfully exchange 10,000+ messages in beta

### Adoption Metrics (6 months post-launch)
- [ ] 500+ active users
- [ ] 5+ independent relay deployments
- [ ] 2+ third-party client implementations
- [ ] Featured in at least 3 security/privacy publications

### Community Metrics
- [ ] Active developer community (10+ contributors)
- [ ] Regular releases (monthly patches, quarterly features)
- [ ] Clear governance model
- [ ] Responsive to security reports (<24hr acknowledgment)

---

## Post-v1.0 Roadmap

### v1.1 (3-4 months post-launch)
- Mobile clients (iOS, Android)
- Improved UX and onboarding
- Multi-device support
- Contact discovery (privacy-preserving)

### v1.2 (6-8 months post-launch)
- Proxy routing for enhanced metadata protection
- Open-federation public-network adapters, if externally validated
- Expanded attachment controls
- Message reactions and threading

### v2.0 (12-18 months post-launch)
- PIR-based message retrieval
- Stronger formal group-protocol analysis
- Wider decentralized relay discovery
- Formal security proofs published

### v3.0 (18-24 months post-launch)
- Mixnet integration
- Cover traffic strategies
- Advanced traffic analysis resistance
- IETF standardization submission

---

## Risk Management

### Critical Risks

**Risk**: Fundamental cryptographic flaw discovered  
**Probability**: Low  
**Impact**: Catastrophic  
**Mitigation**: External review, conservative design, multiple reviews  
**Response**: Immediate disclosure, protocol revision, coordinated upgrade

**Risk**: Post-quantum primitives broken/weakened  
**Probability**: Very Low  
**Impact**: High  
**Mitigation**: Use NIST-standardized algorithms, monitor research  
**Response**: Rapid migration to alternative primitives

**Risk**: Team capacity insufficient  
**Probability**: Medium  
**Impact**: High (delays)  
**Mitigation**: Realistic timeline, buffer time, clear milestones  
**Response**: Reduce scope, extend timeline, seek additional help

**Risk**: Low user adoption  
**Probability**: Medium  
**Impact**: Medium  
**Mitigation**: Focus on usability, clear value proposition, community building  
**Response**: Iterate on UX, target specific use cases, partnerships

### High Risks

**Risk**: Security vulnerabilities in implementation  
**Probability**: Medium  
**Impact**: High  
**Mitigation**: Testing, fuzzing, external audit, bug bounty  
**Response**: Rapid patching, coordinated disclosure, transparency

**Risk**: Relay scaling issues  
**Probability**: Medium  
**Impact**: Medium  
**Mitigation**: Load testing, efficient design, horizontal scaling  
**Response**: Performance optimization, infrastructure upgrades

**Risk**: Regulatory challenges (encryption backdoors, etc.)  
**Probability**: Low-Medium  
**Impact**: High  
**Mitigation**: Legal review, jurisdiction selection  
**Response**: Community coordination, advocacy, compliance where possible

---

## Governance and Decision Making

### Pre-v1.0
- Lead developer has final say on technical decisions
- Major decisions discussed with advisors/community
- Security issues have override authority

### Post-v1.0
- Establish steering committee (3-5 members)
- RFC process for protocol changes
- Security committee for vulnerability handling
- Community voting on major features

---

## Contact and Updates

- **Project Lead**: Luiz Widmer
- **Repository**: github.com/lwidmer/piccp (forthcoming)
- **Discussion Forum**: TBD
- **Security Contact**: security@piccp.org (forthcoming)
- **Monthly Progress Updates**: Blog + mailing list

---

**Last Updated**: December 17, 2025  
**Next Review**: End of Phase 0 (January 2026)
