# DiscV5 State and Effect Ownership

## Architectural rule

Each logical fact has one canonical owner. Indexes may reference that fact, but must not independently represent it. Actor transitions are synchronous and bounded. Runtime owns cancelable I/O and reports completion events to Actor.

## Baseline outbound reliable-request slice

| Logical fact | Current representations / owners |
| --- | --- |
| A reliable result will eventually be published | `Runtime.sendPing()` reserves the request-result outbox; `RuntimeImpl.handleSendPing()` claims or releases it; `RequestOrigin.reliable_api` marks the request; `Actor.publishRequestTerminal()` selects and publishes to the outbox. |
| A request is accepted but not yet visible as active | Runtime command queue owns `SendPing`; `RequestBook.PreparedRequest` owns admission and request state during `flow/outbound.dispatch()`; the caller relies on `errdefer` while transport is cancelable. |
| An endpoint is establishing a session | `PreparedRequest.establish`; `RequestBook.EndpointLane.establishing`; active request phase `awaiting_whoareyou`; challenge nonce index. |
| A datagram corresponds to a future request | Stack-local encoded packet and nonce; `RecoveryState`; `PreparedRequest`; only implicit control flow connects them until `commitPrepared()`. |
| Send completion | Represented by control flow crossing `Actor -> flow/outbound -> transport.Sender`; failure is normalized again in Runtime. There is no explicit domain completion event. |
| Cancellation ownership | Runtime task cancellation interrupts `Sender.send`; `errdefer prepared.abort()` repairs Actor-owned admission state; Runtime shutdown then drains/terminalizes other accepted ownership. |

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
| Prepared request, compact response expectation, admission permit, nonce recovery, request key | `SendDatagramEffect` until completion; `RequestBook` materializes full active response state after `.sent`; no owner after `.failed`. |
| Bounded encoded datagram | `SendDatagramEffect`; destination and request kind derive from its owned preparation rather than duplicate fields. |
| Cancelable send operation | Runtime only. |
| Send success/failure | Explicit `SendCompletion` event consumed by Actor exactly once. |
| Active request and endpoint-establishing state | `RequestBook` only, created by applying successful completion. |
| Reliable result reservation | Runtime result plane until command acceptance; active request origin after successful completion; explicit release on preparation/send failure. |

### Slice constraints

- Preserve request ID, packet bytes, nonce, deadline, admission budget, metrics, and queue behavior.
- Actor must not call `transport.Sender.send` on reliable PING, FINDNODE, or TALKREQ command paths.
- Before send completion, the request must not be visible in `RequestBook.active` or endpoint establishment state.
- The effect must own exactly one admission permit before completion.
- `.sent` transfers request ownership into `RequestBook` and records the sent metric.
- `.failed` releases the permit and leaves no active request or endpoint-establishing state.
- Runtime cancellation during send must apply `.failed` before propagating `error.Canceled`.
- Existing direct/internal Actor callers remain behavior-compatible through a temporary synchronous adapter; later slices remove that adapter path by path.

## Acceptance measurements

The slice is accepted only if it:

1. removes transport from the Actor preparation transition for reliable PING, FINDNODE, and TALKREQ;
2. gives the prepared request and packet one bounded owner;
3. replaces implicit send/commit/`errdefer` choreography with one explicit completion transition;
4. does not add another authoritative request or result-reservation fact;
5. preserves focused send-failure, cancellation, session-establishment, request-result, and shutdown behavior;
6. uses one reusable effect boundary for reliable PING, FINDNODE, and TALKREQ.

## Measured outcome

| Narrow measure | Baseline | Final slice |
| --- | ---: | ---: |
| Reliable-command `Sender.send` sites owned by Runtime | 0 | 1 shared executor |
| Reliable-command `Sender.send` sites executed inside Actor/flow orchestration | 1 | 0 |
| Full active response accumulators represented before send | 1 per prepared request | 0 |
| Mirrored effect fields for destination, request kind, and queued source | N/A | 0 |
| Tracked-request `sendTracked` orchestration entry points | 1 | 0 |
| Explicit send-completion domain handlers | 0 | 1 |
| Cancelable sends executed while the Actor-domain transition remains on the call stack | 1 | 0 for reliable commands |
| Bounded effect/action size | rejected 11,864 / 11,872 bytes | 4,112 / 4,120 bytes |

These counts are scoped to the tracked reliable-request send transition; they do not describe response, retry, maintenance, lookup, or shutdown paths.

- Reliable PING, FINDNODE, and TALKREQ now follow `Actor.prepare* -> Runtime.send -> Actor.applySendCompletion`.
- Runtime uses its own transport and admission fields for those commands; the Actor preparation context contains no sender.
- `sendTracked` was removed. Internal health, eviction, and queue-drain paths use the same preparation/completion contract through a synchronous compatibility executor.
- The old `errdefer prepared.abort()` send choreography was replaced by `.failed` completion. A mutation that suppressed failure resolution left the permit live and failed the ownership test.
- The rejected first effect representation was 11,864 bytes and prematurely embedded the full active NODES accumulator. `ResponseExpectation` postpones that accumulator until commit; the final effect is 4,112 bytes and the action union is 4,120 bytes, guarded by a four-packet-budget test.
- Destination, request kind, and queued-source flags were removed from the effect because they derive from its canonical prepared request or `RequestBook` queue state. A mutation that ignored the queued entry produced simultaneous queued/active ownership and was caught by `RequestBook.assertInvariants`.
- Sessionless sends use the request-owned retry datagram directly. Established-session sends retain one transient ciphertext; their separately retained plaintext is a distinct recovery fact.

## Remaining ownership work

This slice is not the complete architecture:

- Reliable result reservation is still represented by Runtime outbox reservation state and `RequestOrigin.reliable_api`; a later consume-and-resolve result capability should consolidate it.
- Internal Actor callers still use a synchronous executor that receives `Env.sender`; later Actor transitions should return bounded effects to Runtime instead.
- Response sends, WHOAREYOU/retry sends, maintenance retries, shutdown terminal publication, peer/contact/routing facts, and lookup/probe lifetimes remain outside this slice.
- A future asynchronous Runtime executor still needs explicit effect identity/generation and late-completion policy. The present executor resolves each value synchronously and exactly once.
