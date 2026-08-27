# DiscV5 State and Effect Ownership

## Architectural rule

Each logical fact has one canonical owner. Indexes may reference that fact, but must not independently represent it. Actor transitions are synchronous and bounded. Runtime owns cancelable I/O and reports completion events to Actor.

## Baseline outbound reliable-request slice

| Logical fact | Current representations / owners |
| --- | --- |
| A reliable result will eventually be published | `Runtime.sendPing()` reserves the request-result outbox; `RuntimeImpl.handleSendPing()` claims or releases it; `RequestOrigin.reliable_api` marks the request; `Actor.publishRequestTerminal()` selects and publishes to the outbox. |
| A request is accepted but not yet active | `RequestBook` owns a generation-tagged `.sending` entry with the compact `ResponseExpectation`, admission permit, recovery state, and indexes. `SendDatagramEffect` carries only its exact `RequestHandle` and packet bytes. |
| An endpoint is establishing a session | `RequestBook.EndpointLane.establishing` stores the exact request handle; the canonical active request owns `awaiting_whoareyou`, compact `handshake_send`, or the generation-tagged pending candidate; the challenge nonce index stores the same request handle whenever the phase remains challengeable and no handshake send is in flight. |
| A datagram corresponds to a future request | `SendDatagramEffect.handle` identifies the canonical sending entry by request key and generation; `SendDatagramEffect.packet` owns the bounded encoded datagram. |
| Send completion | Runtime reports `.sent`, `.failed`, or `.runtime_stopped` to `Actor.applySendCompletion()`. Actor applies the completion only when the handle still names the exact `.sending` generation. |
| Cancellation ownership | Runtime maps canceled execution to `.runtime_stopped`; `RequestBook.abortSending()` removes only the exact generation, clears matching indexes, and releases its permit. Runtime shutdown synthesizes completion for other accepted effects. |

The transaction currently spans Runtime command/result ownership, Actor/RequestBook state, ingress admission, and cancelable transport execution.

## Implemented slice: tracked reliable API requests

```text
Runtime accepts command and claims result reservation
    -> Actor.preparePing | prepareFindNode | prepareTalkRequest
       -> queued(request_id)
       -> send(SendDatagramEffect)
    -> Runtime.execute(send)
       -> Actor.applySendCompletion(effect, sent | failed)
    -> Runtime replies with request_id or transport error
```

### Canonical owners

| Fact | Target owner |
| --- | --- |
| Canonical request state, compact response expectation, admission permit, nonce recovery, request key | Generation-tagged `RequestBook` `.sending` entry until completion. Exact `.sent` activates the response accumulator and transitions it to `.active`; exact `.failed` or `.runtime_stopped` removes it. |
| Bounded encoded datagram | `SendDatagramEffect.packet`; `SendDatagramEffect.handle` resolves destination, request kind, and canonical ownership without copying request state. |
| Cancelable send operation | Runtime only. |
| Send success/failure | Explicit completion applied by Actor only while the exact handle remains `.sending`; duplicate or stale completions are ignored. |
| Sending, active, and endpoint-establishing state | `RequestBook` only. Sending and active response representations are distinct union variants. |
| Reliable result reservation | Runtime result plane until command acceptance; canonical request origin after `beginSending()`; explicit terminal publication after exact send failure or request completion. |

### Slice constraints

- Preserve request ID, packet bytes, nonce, deadline, admission budget, metrics, and queue behavior.
- Actor must not call `transport.Sender.send` on reliable PING, FINDNODE, or TALKREQ command paths.
- Before send completion, the request occupies bounded `RequestBook` capacity as `.sending`, is hidden from active lookups, and retains only a compact response expectation.
- The canonical `.sending` entry owns exactly one admission permit; the effect owns no permit or response state.
- Exact `.sent` activates the response state, transitions the entry to `.active`, and records the sent metric once.
- Exact `.failed` releases the permit and removes matching request, challenge, and endpoint-establishing indexes.
- Runtime cancellation during send must apply `.runtime_stopped` before propagating shutdown.
- Existing direct/internal Actor callers remain behavior-compatible through a temporary synchronous adapter; later slices remove that adapter path by path.

## Acceptance measurements

The slice is accepted only if it:

1. removes transport from the Actor preparation transition for reliable PING, FINDNODE, and TALKREQ;
2. gives canonical sending state and the packet one bounded owner each;
3. replaces implicit send/commit/`errdefer` choreography with one explicit completion transition;
4. does not add another authoritative request or result-reservation fact;
5. preserves focused send-failure, cancellation, session-establishment, request-result, and shutdown behavior;
6. uses one reusable effect boundary for reliable PING, FINDNODE, and TALKREQ.

## Measured outcome

| Narrow measure | Baseline | Final slice |
| --- | ---: | ---: |
| Reliable-command `Sender.send` sites owned by Runtime | 0 | 1 shared executor |
| Reliable-command `Sender.send` sites executed inside Actor/flow orchestration | 1 | 0 |
| Full active response accumulators constructed before successful send completion | 1 per request | 0 |
| Mirrored effect fields for destination, request kind, and queued source | N/A | 0 |
| Tracked-request `sendTracked` orchestration entry points | 1 | 0 |
| Explicit send-completion domain handlers | 0 | 1 |
| Cancelable sends executed while the Actor-domain transition remains on the call stack | 1 | 0 for reliable commands |
| Request effect size | rejected 11,864 bytes | 1,376 bytes (`RequestHandle` plus `PacketBytes`) |

These counts are scoped to the tracked reliable-request send transition; they do not describe response, retry, maintenance, lookup, or shutdown paths.

- Reliable PING, FINDNODE, and TALKREQ now follow `Actor.prepare* -> Runtime.send -> Actor.applySendCompletion`.
- Runtime uses its own transport and admission fields for those commands; the Actor preparation context contains no sender.
- `sendTracked` was removed. Internal health, eviction, and queue-drain paths use the same preparation/completion contract through a synchronous compatibility executor.
- The old `errdefer prepared.abort()` send choreography was replaced by `.failed` completion. A mutation that suppressed failure resolution left the permit live and failed the ownership test.
- The rejected first effect representation was 11,864 bytes and prematurely embedded the full active NODES accumulator. The canonical `.sending` entry retains `ResponseExpectation`; exact successful completion activates the NODES accumulator. The request effect is 1,376 bytes.
- Destination, request kind, and queued-source flags were removed from the effect because they resolve through its canonical request handle or `RequestBook` queue state. A mutation that ignored the queued entry produced simultaneous queued/active ownership and was caught by `RequestBook.assertInvariants`.
- Sessionless sends use the request-owned retry datagram directly. Established-session sends retain one transient ciphertext; their separately retained plaintext is a distinct recovery fact.

## Completed architecture: one Runtime-owned effect lifecycle

The temporary compatibility executor and every Actor-side transport capability have now been removed.

```text
Runtime delivers command | packet | maintenance | completion
    -> Actor performs one bounded synchronous transition
    -> Actor appends move-owned ActorEffect values to one bounded FIFO
    -> Actor returns
    -> Runtime is the sole transport executor
    -> Runtime delivers sent | failed | runtime_stopped exactly once
    -> Actor commits, aborts, or emits bounded follow-up effects
```

`ActorEffect` has five canonical variants:

- `request`: request handle plus packet for PING, FINDNODE, TALKREQ, health, eviction, lookup, ENR refresh, and queued-redrain requests;
- `response`: an exact response handle plus packet for PONG, NODES, and TALKRESP; `ResponseBook` already owns the response permit and recovery material before this effect is published;
- `retry`: exact `RetryHandle` (`RequestHandle` plus non-wrapping retry-send generation) and packet bytes only; `RequestBook.sending_retry` owns the prior phase, prepared future transition, current and replacement permits, next deadline, and retry policy until exact completion;
- `handshake`: unified `HandshakeHandle` plus immutable packet bytes, exactly two fields. The request arm binds request lifetime plus non-wrapping handshake-send generation; the response arm binds response lifetime plus handshake-send generation. The canonical `ActiveRequest.handshake_send` or `ResponseBook` owns compact keys/deadline facts; the active request retains its phase, response accumulator, recovery material, permit, and all other request state in place.
- `whoareyou`: exact `ChallengeHandle` (endpoint plus non-wrapping generation) and immutable packet bytes only. `SessionBook` owns challenge data, triggering nonce, retained datagram, optional remote ENR, permit, TTL, and the canonical `sending_whoareyou` or `live` phase.

### Final measured ownership delta

| Ownership / transition measure | Reviewed first slice | Completed architecture |
| --- | ---: | ---: |
| Production transport executors | 2 (`Runtime.executeRequestEffect` plus Actor compatibility executor) | 1 Runtime executor |
| Direct `Sender.send` sites in Actor/flow production code | 7 (compatibility + response/retry/session paths) | 0 |
| `transport.Sender` capabilities in `Actor.Env` | 1 | 0 |
| Internal tracked compatibility call paths | 6 | 0 |
| Ordered Actor effect queues | request-only | 1 queue for every datagram effect |
| Queued requests reserved simultaneously for redrain | potentially loop-driven | exactly 1 queue head per completion |
| Explicit Runtime-stop completion | implicit ordinary failure | `runtime_stopped` |
| DiscV5 tests after migration | 307 | 429 after request/response/retry/challenge ledger canonicalization, exact admission correlation, compact in-place handshake rollback, and runtime/auth race tracers |
| Bounded effect size | request effect within four packet budgets | staged `ActorEffect` exactly 1,400 bytes; every variant is packet plus semantic handle, including unified handshake at 1,392 bytes, WHOAREYOU at 1,360 bytes, and retry at 1,384 bytes. The project-wide final `<= 1,536` ceiling is intentionally not yet promoted from the staged exact lock. |

### Canonical completion ownership

- **Request `.sent`:** activate the exact `RequestBook` sending generation, record metrics, schedule health work, and emit at most one stable-session FIFO continuation.
- **Request `.failed`:** abort the exact sending generation, release its permit and indexes, and resolve health, eviction, or lookup ownership exactly once.
- **Response `.sent`:** advance only the exact `ResponseBook` generation from `.sending_response` to `.recoverable`; failure or `runtime_stopped` removes that exact generation and releases its canonical permit.
- **Retry `.sent`:** only the exact request generation and retry-send generation may restore `.active`; retained success consumes one attempt/deadline, while fresh success installs the prepared phase and nonce, resets multipart state, swaps the exact permit, and consumes one attempt/deadline. Exact `.failed` or `.runtime_stopped` releases the prepared permit, preserves the prior phase and current permit, and consumes the same one-attempt/deadline policy. Duplicate, stale, canceled, timed-out, key-reused, or post-shutdown completions are no-ops.
- **Request-source handshake publication:** exact preflight checks the active request generation, absence of another handshake send, challenge/recovery identity, current challengeable phase, and checked handshake successor before crypto, randomness, expected-credit commit, or FIFO publication. `beginHandshake` repeats those checks, removes the challenge index, and arms compact `ActiveRequest.handshake_send` in place before publishing the compact effect. Timeout/retry and ordinary response access exclude the canonical request while that substate is armed.
- **Request-source handshake completion:** exact `.sent` advances only matching request and handshake generations to a generation-tagged pending candidate, then records the request metric once. Exact `.failed` or `.runtime_stopped` clears only the compact substate and restores the exact challenge index and prior lane-establishing state; phase, deadline, attempts, response accumulator, permit, and queued intent never moved or changed. FIFO rejection uses the same exact failure transition. Explicit terminalization removes the canonical active request normally. Duplicate, stale, reordered, canceled, timed-out, key-reused, or post-shutdown completions are no-ops.
- **Request candidate promotion:** authenticated candidate-key decryption captures an exact pending view. Promotion must consume that exact request and handshake generation before stable-session installation, authenticated publication, metrics, or lane draining. A stale valid packet cannot promote or erase a newer same-endpoint candidate or replace an existing stable session; the exact newer candidate still promotes once.
- **Response-source handshake `.sent`:** advance only the exact response and handshake generations to a candidate and release the canonical response permit; failure or `runtime_stopped` removes that exact sending phase and releases the permit without creating a candidate.
- **Fresh WHOAREYOU `.sent`:** advance only the exact challenge generation from `sending_whoareyou` to `live`. If the configured live capacity is full, evict only the least-recent live challenge and release its permit. Exact `.failed` or `.runtime_stopped` removes that sending generation and releases its permit. Duplicate, stale, wrong-phase, expired-and-removed, authenticated-removed, or endpoint-reused completions are no-ops. A matching sending entry whose TTL has elapsed but has not yet been pruned remains exact, may transition to `live`, and is removed by subsequent expiry maintenance.
- **WHOAREYOU replay:** publish the existing exact handle and retained packet without changing challenge phase, TTL, recency, permit, generation, or metrics. Sent and failed replay completions are both mutation-free because the canonical challenge is already `live`.
- **Authenticated HANDSHAKE:** look up the live challenge by the full endpoint, retain its exact generation-bearing handle through identity verification and decryption, then remove only that handle before installing stable keys. An old handle cannot remove a newer generation at the same endpoint.
- **Challenge expiry:** bounded maintenance removes every expired sending or live phase and releases each canonical permit exactly once. Late completions are stale.
- **`runtime_stopped`:** Runtime first synthesizes exact completion for every queued effect, including request-source handshake sends, then sweeps residual response/challenge phases, lookups, and all request phases before closing result/event planes. A queued request handshake is rolled back before its canonical active request is terminalized, so challenge/lane indexes and its permit are consumed once and a reliable origin receives exactly one `runtime_stopped` result. Copied post-shutdown completions are no-ops, and unrelated stable sessions remain intact. Lookup work terminates as `runtime_stopped` rather than ordinary failure/repump.

### Ordering, bounds, and late completion policy

- Runtime drains the single FIFO after every command, inbound packet, maintenance turn, and completion-generated continuation.
- Queue storage is preallocated as `max(A, min(P, M + 1))`, where `A` is the active-request limit, `P` is the canonical ingress permit capacity, and `M` is the maximum NODES response chunk count. The supported default remains 1,024 entries and is behaviorally asserted by the Runtime capacity test.
- Request effects are bounded by canonical sending entries, which share the active-request capacity `A`. An atomic authenticated FINDNODE turn is bounded by `M` response chunks plus one eviction probe, while all permit-bearing effects are also bounded by `P`.
- Runtime pops before applying completion and drains before the next command, so the request and atomic-ingress bounds are alternatives rather than additive queue residents. No per-effect allocation occurs.
- Queue redrain emits one head. `.sent` removes that head and may emit exactly the next head only under a stable session.
- Runtime execution is deliberately synchronous in the actor-loop task, but copied, stale, delayed, or reordered completions remain harmless because each migrated family uses its canonical semantic handle: request key plus request generation, retry request generation plus retry-send generation, response endpoint plus nonce plus response generation and handshake send generation, or challenge endpoint plus challenge generation. Generations are checked, never wrapped, and exhausted rather than reused.
- Cancellation during send maps to `runtime_stopped`; ordinary transport failure maps to `failed`; all remaining queued values are synthesized as `runtime_stopped` during terminalization. Runtime then sweeps residual canonical response and challenge phases, making copied post-shutdown completions no-ops.

### Exact ingress-admission authority

Ingress bypass is no longer an IP-level boolean or a count-only promise. Every request, response recovery, and live challenge owns one immutable `PermitHandle` consisting of a slot and non-wrapping permit generation. A permit has at most 17 packet credits, matching both `1 + MAX_NODES_RESPONSE` and `MAX_REQUEST_RETRIES + 1`. Each admitted packet receives one exact `ExpectedCredit` containing its source permit generation and a non-wrapping receipt generation from one of 17 fixed lanes.

An authenticated packet commits only against the canonical owner captured from its correlation source: active request for PONG/NODES/TALKRESP, request challenge preparation, response recovery, or live session challenge. A same-IP receipt may be reassigned to that exact owner under the admission lock. Reassignment consumes the target allowance and restores the live source allowance; a released source is never resurrected. Wrong-IP, stale, released, exhausted, or replaced targets leave the receipt armed and the ledger unchanged so Runtime's unconditional rollback remains authoritative.

Pending request and response candidate generations are revalidated after decrypt/decode and test replacement hooks, before exact credit commit. HANDSHAKE revalidates the captured challenge after signature, decrypt, and decode, then commits before challenge removal, session/peer mutation, event publication, or RPC dispatch. Request- and response-source WHOAREYOU similarly commit after exact source preflight and before recovery transfer or cryptographic work.

Receipts and permits may be copied by bounded Runtime queues and cancellation paths. Local `armed` state prevents ordinary double use, while canonical generation/lane checks make stale copies harmless. Release always disarms its local permit copy. Queue rejection, oversized input, malformed preprocessing, command abort, and shutdown drain all roll back the canonical receipt exactly once; copied late rollbacks are no-ops. Permit and credit generations survive slot recycling and fail on exhaustion rather than wrapping. Acquire, reserve, commit/reassign, rollback, and release allocate no memory after initialization.

Registered all-mode layout locks are: `PermitHandle` 16 bytes, `AdmissionPermit` 16, `ExpectedCredit` 24, `PermitSlot` 200, and `IngressAdmission` 440 in Debug/ReleaseSafe or 416 in ReleaseFast. Supported default capacity is 3,073 permit slots with 614,600 bytes of fixed slot backing. Test-only fingerprints independently lock active receipt lanes, list links, remaining/reserved allowance, free-list state, live counts, and both generation families.

### Challenge ledger layout gates

The registered layout report runs in Debug, ReleaseSafe, and ReleaseFast and distinguishes transport effects from canonical state views:

| Layout | Exact bytes |
| --- | ---: |
| `ChallengeHandle` | 72 |
| `WhoareyouSendEffect` (`handle` plus `packet`, exactly two fields) | 1,360 |
| `ChallengePublication` (pre-publication canonical input, not an effect) | 1,672 |
| `ChallengeView` (canonical read view, not an effect) | 1,752 |
| Stored challenge | 1,688 |
| Challenge LRU node | 1,808 |
| Configured fixture node backing (`C = 3`, physical `C + 1 = 4`) | 7,232 |
| Configured fixture map capacity | 8 |
| `SessionBook` | 384 Debug/ReleaseSafe, 360 ReleaseFast |
| Request `HandshakeHandle` | 96 |
| Unified `HandshakeHandle` | 104 |
| Unified `HandshakeSendEffect` (exactly `handle` plus `packet`) | 1,392 |
| `PendingHandshake` | 40 |
| `ResponseWait` | 48 |
| Request `Phase` | 2,616 |
| `HandshakeSendState` | 56 |
| `ActiveRequest` | 10,496 |
| `StoredRequest` | 11,776 |
| `RequestBook` | 272 Debug/ReleaseSafe, 248 ReleaseFast |
| `ActorEffect` staged union | 1,400 |
| Runtime effect FIFO capacity at supported defaults | 1,024 entries |

Compact effects are forbidden from regaining admission/permit, challenge/preparation source, keys, deadline, plaintext, destination, ENR, or transition ownership. The canonical challenge backing is checked as `C + 1`; configuration rejects `C = 0`, and checked addition rejects overflow before allocation. Request storage remains bounded by `max_active_requests`; this migration adds no map, cache, or allocation.

## Remaining ownership work

Only final integration remains: promote the project-wide `ActorEffect <= 1,536` ceiling while retaining the observed 1,400-byte lock, then perform the final cross-slice integration review. Runtime transport, effect ledgers, and exact expected-credit/admission authority are complete.
