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
- `response`: PONG, NODES, and TALKRESP plus the moved response-recovery permit;
- `retry`: retained probes and fresh retry transitions plus any replacement permit;
- `handshake`: request/response challenge source, candidate keys, packet, and completion clocks;
- `whoareyou`: replay-only or fresh challenge state plus its moved challenge permit.

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
| DiscV5 tests after migration | 307 | 313 |
| Bounded effect size | request effect within four packet budgets | full `ActorEffect` union within four packet budgets |

### Canonical completion ownership

- **Request `.sent`:** activate the exact `RequestBook` sending generation, record metrics, schedule health work, and emit at most one stable-session FIFO continuation.
- **Request `.failed`:** abort the exact sending generation, release its permit and indexes, and resolve health, eviction, or lookup ownership exactly once.
- **Response `.sent`:** move the recovery permit into `ResponseBook`; failure releases it.
- **Retry `.sent`:** commit retry deadline/state/permit swap; failure preserves old active state, releases any replacement permit, and advances the retry deadline.
- **Handshake `.sent`:** commit request pending keys or response candidate keys; failure leaves the challenged state unchanged.
- **Fresh WHOAREYOU `.sent`:** install challenge state and moved permit; failure releases it. Replay has no domain mutation.
- **`runtime_stopped`:** Runtime synthesizes completion for every queued effect before Actor terminalization; lookup work terminates as `runtime_stopped` rather than ordinary failure/repump.

### Ordering, bounds, and late completion policy

- Runtime drains the single FIFO after every command, inbound packet, maintenance turn, and completion-generated continuation.
- Queue storage is preallocated as `max(A, min(P, M + 1))`, where `A` is the active-request limit, `P` is the canonical ingress permit capacity, and `M` is the maximum NODES response chunk count.
- Request effects are bounded by canonical sending entries, which share the active-request capacity `A`. An atomic authenticated FINDNODE turn is bounded by `M` response chunks plus one eviction probe, while all permit-bearing effects are also bounded by `P`.
- Runtime pops before applying completion and drains before the next command, so the request and atomic-ingress bounds are alternatives rather than additive queue residents. No per-effect allocation occurs.
- Queue redrain emits one head. `.sent` removes that head and may emit exactly the next head only under a stable session.
- Runtime execution is deliberately synchronous in the actor-loop task, but copied, stale, delayed, or reordered completions remain harmless because the `RequestHandle` key and generation jointly identify ownership. Generations are checked, never wrapped, and exhausted rather than reused.
- Cancellation during send maps to `runtime_stopped`; ordinary transport failure maps to `failed`; all remaining queued values are synthesized as `runtime_stopped` during terminalization.

## Remaining ownership work

The outbound transport redesign is complete. Remaining concerns are separate domains rather than compatibility-executor debt:

- Reliable result reservation is represented by Runtime outbox reservation state and `RequestOrigin.reliable_api`; a future consume-and-resolve result capability may consolidate that representation.
- Peer/contact/routing canonicalization is independent of transport execution ownership.
- If Runtime transport is later made concurrent or detached, the existing request generation identity remains the ownership boundary; any additional registry must preserve exact-handle completion and exhaustion semantics.
