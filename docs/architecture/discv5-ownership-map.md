# DiscV5 State and Effect Ownership

## Architectural rule

Each logical fact has one canonical owner. Indexes may reference that fact, but must not independently represent it. Actor transitions are synchronous and bounded. Runtime owns cancelable I/O and reports completion events to Actor.

## Baseline outbound reliable-request slice

| Logical fact | Current representations / owners |
| --- | --- |
| A reliable result will eventually be published | `Runtime.sendPing()` reserves the request-result outbox; `RuntimeImpl.handleSendPing()` claims or releases it; `RequestOrigin.reliable_api` marks the request; `Actor.publishRequestTerminal()` selects and publishes to the outbox. |
| A request is accepted but not yet active | `RequestBook` owns a generation-tagged `.sending` entry with the compact `ResponseExpectation`, admission permit, recovery state, and indexes. `SendDatagramEffect` carries only its exact `RequestHandle` and packet bytes. |
| An endpoint is establishing a session | `RequestBook.EndpointLane.establishing` stores the exact request handle; the canonical sending or active request owns `awaiting_whoareyou`; the challenge nonce index stores the same handle. |
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
- `handshake`: request-source handshakes still carry their prepared source, candidate keys, clocks, plaintext, and packet; response-source handshakes carry only an exact response/handshake handle plus packet while `ResponseBook` owns their keys, plaintext, permit, and candidate transition;
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
| DiscV5 tests after migration | 307 | 409 after response-, retry-, and challenge-ledger canonicalization |
| Bounded effect size | request effect within four packet budgets | staged `ActorEffect` exactly 4,080 bytes; compact request/response/retry/WHOAREYOU effects are packet plus semantic handle, with WHOAREYOU exactly 1,360 bytes and retry exactly 1,384 bytes; a final `<= 1,536` union ceiling is still required after the remaining legacy request-source handshake is compacted |

### Canonical completion ownership

- **Request `.sent`:** activate the exact `RequestBook` sending generation, record metrics, schedule health work, and emit at most one stable-session FIFO continuation.
- **Request `.failed`:** abort the exact sending generation, release its permit and indexes, and resolve health, eviction, or lookup ownership exactly once.
- **Response `.sent`:** advance only the exact `ResponseBook` generation from `.sending_response` to `.recoverable`; failure or `runtime_stopped` removes that exact generation and releases its canonical permit.
- **Retry `.sent`:** only the exact request generation and retry-send generation may restore `.active`; retained success consumes one attempt/deadline, while fresh success installs the prepared phase and nonce, resets multipart state, swaps the exact permit, and consumes one attempt/deadline. Exact `.failed` or `.runtime_stopped` releases the prepared permit, preserves the prior phase and current permit, and consumes the same one-attempt/deadline policy. Duplicate, stale, canceled, timed-out, key-reused, or post-shutdown completions are no-ops.
- **Request-source handshake `.sent`:** commit the prepared request challenge and candidate keys; failure leaves the challenged request state unchanged.
- **Response-source handshake `.sent`:** advance only the exact response and handshake generations to a candidate and release the canonical response permit; failure or `runtime_stopped` removes that exact sending phase and releases the permit without creating a candidate.
- **Fresh WHOAREYOU `.sent`:** advance only the exact challenge generation from `sending_whoareyou` to `live`. If the configured live capacity is full, evict only the least-recent live challenge and release its permit. Exact `.failed` or `.runtime_stopped` removes that sending generation and releases its permit. Duplicate, stale, wrong-phase, expired-and-removed, authenticated-removed, or endpoint-reused completions are no-ops. A matching sending entry whose TTL has elapsed but has not yet been pruned remains exact, may transition to `live`, and is removed by subsequent expiry maintenance.
- **WHOAREYOU replay:** publish the existing exact handle and retained packet without changing challenge phase, TTL, recency, permit, generation, or metrics. Sent and failed replay completions are both mutation-free because the canonical challenge is already `live`.
- **Authenticated HANDSHAKE:** look up the live challenge by the full endpoint, retain its exact generation-bearing handle through identity verification and decryption, then remove only that handle before installing stable keys. An old handle cannot remove a newer generation at the same endpoint.
- **Challenge expiry:** bounded maintenance removes every expired sending or live phase and releases each canonical permit exactly once. Late completions are stale.
- **`runtime_stopped`:** Runtime first synthesizes exact completion for every queued effect, then sweeps residual response and challenge phases, lookups, and requests before closing result/event planes. Copied post-shutdown completions are no-ops, and unrelated stable sessions remain intact. Lookup work terminates as `runtime_stopped` rather than ordinary failure/repump.

### Ordering, bounds, and late completion policy

- Runtime drains the single FIFO after every command, inbound packet, maintenance turn, and completion-generated continuation.
- Queue storage is preallocated as `max(A, min(P, M + 1))`, where `A` is the active-request limit, `P` is the canonical ingress permit capacity, and `M` is the maximum NODES response chunk count. The supported default remains 1,024 entries and is behaviorally asserted by the Runtime capacity test.
- Request effects are bounded by canonical sending entries, which share the active-request capacity `A`. An atomic authenticated FINDNODE turn is bounded by `M` response chunks plus one eviction probe, while all permit-bearing effects are also bounded by `P`.
- Runtime pops before applying completion and drains before the next command, so the request and atomic-ingress bounds are alternatives rather than additive queue residents. No per-effect allocation occurs.
- Queue redrain emits one head. `.sent` removes that head and may emit exactly the next head only under a stable session.
- Runtime execution is deliberately synchronous in the actor-loop task, but copied, stale, delayed, or reordered completions remain harmless because each migrated family uses its canonical semantic handle: request key plus request generation, retry request generation plus retry-send generation, response endpoint plus nonce plus response generation and handshake send generation, or challenge endpoint plus challenge generation. Generations are checked, never wrapped, and exhausted rather than reused.
- Cancellation during send maps to `runtime_stopped`; ordinary transport failure maps to `failed`; all remaining queued values are synthesized as `runtime_stopped` during terminalization. Runtime then sweeps residual canonical response and challenge phases, making copied post-shutdown completions no-ops.

### Challenge ledger layout gates

The registered layout report runs in Debug, ReleaseSafe, and ReleaseFast and distinguishes transport effects from canonical state views:

| Layout | Exact bytes |
| --- | ---: |
| `ChallengeHandle` | 72 |
| `WhoareyouSendEffect` (`handle` plus `packet`, exactly two fields) | 1,360 |
| `ChallengePublication` (pre-publication canonical input, not an effect) | 1,672 |
| `ChallengeView` (canonical read view, not an effect) | 1,736 |
| Stored challenge | 1,688 |
| Challenge LRU node | 1,808 |
| Configured fixture node backing (`C = 3`, physical `C + 1 = 4`) | 7,232 |
| Configured fixture map capacity | 8 |
| `SessionBook` | 384 Debug/ReleaseSafe, 360 ReleaseFast |
| `ActorEffect` staged union | 4,080 |
| Runtime effect FIFO capacity at supported defaults | 1,024 entries |

The compact WHOAREYOU effect is forbidden from regaining admission, challenge data, nonce, ENR, deadline, destination, or other future-ownership fields. The canonical challenge backing is checked as `C + 1`; configuration rejects `C = 0`, and checked addition rejects overflow before allocation.

## Remaining ownership work

The Runtime-only transport executor and single FIFO are complete. Canonical effect ownership is staged by effect family:

- Retry effects are compact and complete: they carry only exact `RetryHandle` plus `PacketBytes`, while canonical retry future state lives in `RequestBook.sending_retry` and terminal cleanup releases both current and prepared permits.
- Request-source handshake effects still carry prepared request source, candidate keys, clocks, plaintext, and packet; response-source handshakes are already compact and canonical in `ResponseBook`.
- Fresh and replay WHOAREYOU effects are compact and complete: both carry only exact `ChallengeHandle` plus `PacketBytes`, while canonical sending/live state and permits remain in `SessionBook`.
- Request-source handshake send generations and exact admission receipt ownership remain pending staged work.
- Reliable result reservation is represented by Runtime outbox reservation state and `RequestOrigin.reliable_api`; a future consume-and-resolve result capability may consolidate that representation.
- Peer/contact/routing canonicalization is independent of transport execution ownership.
- The final `ActorEffect <= 1,536` compact-union gate is not complete; the exact 4,080-byte staged union remains dominated by the legacy request-source handshake.
- If Runtime transport is later made concurrent or detached, every effect family must retain its exact canonical handle and exhaustion semantics; synchronous execution is not an ownership shortcut.
