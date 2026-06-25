# Decentralized Wake Plan

Noctyra will not use APNs or any equivalent centralized notification authority for message delivery. That means closed-app instant delivery is intentionally not guaranteed today. The wake direction is a decentralized relay-advertised pull model that can improve latency while preserving the no-central-server stance.

## Current Prototype

Relays can advertise `wakeSupport` metadata:

- `pullOnly`: clients schedule jittered authenticated fetches
- `longPoll`: compatible clients may hold a fetch window open for bounded relay-selected timeouts
- `minPollIntervalSeconds` and `maxPollIntervalSeconds`: operator bounds for client fetch cadence
- `jitterPermille`: deterministic spread to avoid synchronized client polling
- `longPollTimeoutSeconds`: bounded timeout for long-poll capable relays

Clients can derive a local wake plan using `DecentralizedWakePlanner`. The planner uses identity-local seed material, relay identifier, current time bucket, and failure count to produce bounded jitter and backoff without contacting any third-party notification service.

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

## Next Steps

1. Render relay wake policy in the client relay detail UI.
2. Teach client sync loops to consume `wakeSupport` when the app is active or background execution is available.
3. Add simulation tests for many identities polling one relay with jitter and backoff.
4. Add relay-side long-poll fetch behavior for HTTP/WebSocket transports.
