# Decentralized Wake Plan

Noctyra will not use APNs or any equivalent centralized notification authority for message delivery. That means closed-app instant delivery is intentionally not guaranteed today. The wake direction is a decentralized relay-advertised pull model that can improve latency while preserving the no-central-server stance.

## Implemented Model

Relays can advertise `wakeSupport` metadata:

- `pullOnly`: clients schedule jittered authenticated fetches
- `longPoll`: compatible clients may hold a fetch window open for bounded relay-selected timeouts
- `minPollIntervalSeconds` and `maxPollIntervalSeconds`: operator bounds for client fetch cadence
- `jitterPermille`: deterministic spread to avoid synchronized client polling
- `longPollTimeoutSeconds`: bounded timeout for long-poll capable relays

Clients derive a local wake plan using `DecentralizedWakePlanner`. The planner uses identity-local seed material, relay identifier, current time bucket, and failure count to produce bounded jitter and backoff without contacting any third-party notification service.

The client relay detail UI renders advertised wake policy metadata. Active sync loops consume the policy when the app is unlocked and the OS permits background or foreground network work. If a relay does not advertise wake metadata, clients fall back to bounded pull-only local defaults.

Linux and mac relays can advertise wake policy settings, and the HTTP/WebSocket relay path supports bounded long-poll fetches when operators enable long-poll mode.

## Security Properties

- No relay receives plaintext messages through this mechanism.
- No central push service receives device tokens or message metadata.
- Jitter reduces synchronized polling spikes and timing correlation.
- Failure backoff prevents repeated connection failures from becoming relay load amplification.

## Limits

- This is not a push-notification system.
- iOS and macOS may still suspend or terminate apps according to OS policy.
- Closed-app instant delivery remains out of scope unless a future decentralized wake mechanism can work within platform constraints without introducing a central credential holder.
- Long-polling increases relay connection occupancy and should be operator-configurable.

## Verification Coverage

- Policy normalization clamps unsafe operator values into bounded ranges.
- Planner output is deterministic for the same identity, relay, time bucket, and failure count.
- Multi-identity simulation coverage verifies jitter spread across a relay window.
- Missing relay policy falls back to bounded pull-only polling defaults.
- Relay info round-trips preserve advertised `wakeSupport` metadata.
