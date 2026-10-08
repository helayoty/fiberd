# Protocol reference

This page is the wire contract of fiberd's [grant](glossary.md#grant) protocol, for anyone writing a caller or a [home](glossary.md#home). Read [architecture.md](architecture.md) first and look up terms in the [glossary](glossary.md). The protobuf schema in [`api/grant/v1/grant.proto`](../api/grant/v1/grant.proto) is the authority, and `tests/conform` is its executable contract.

The protocol answers four questions.

- What capacity has already been authorized.
- Which named [session](glossary.md#session) should be attached, resumed or created.
- How a caller reaches the resulting [fiber](glossary.md#fiber).
- Whether a miss should fall back or retry.

It does not accept an image, command, environment, mount, security context or resource override at [clone](glossary.md#clone) time. Those belong to the admitted [template](glossary.md#template) and grant.

## Signed CapacityGrant

Every Clone request carries a signed CapacityGrant as a JSON Web Token (JWT). The registered claims mirror grant fields.

- `iss` matches `issuer`.
- The single `aud` value matches `audience`.
- `jti` matches `grant_uid`.
- `exp`, when present, matches `lease_expiry`.
- `grant` holds the complete CapacityGrant as protobuf JSON.

The [agent](glossary.md#agent) verifies the signature and these claims offline, as [grant.md](design/grant.md) describes.

The API serves mutual TLS (mTLS), so the token is encrypted on the wire, and a grant bound to the caller's certificate cannot be replayed by another caller. Keep it out of logs, metadata and readable files all the same.

Verification does not reject a token merely because `exp` is in the past. Lease expiry is a capacity event handled by admission and the lease reaper, so it produces a capacity miss rather than `Unauthenticated`. Stale or unavailable key material produces `SHED` when the verifier cannot safely decide.

`exp` and `lease_expiry` are optional. A token and grant with neither value do not expire through these checks. Production [issuers](glossary.md#issuer) set both.

### Grant fields

- `grant_uid` is the stable identifier used by the ledger, [fences](glossary.md#fence) and status stream. It must be a DNS-1123 label, which means lowercase letters, digits and `-`, at most 63 characters, starting and ending with a letter or digit. A grant with any other UID is refused as unauthenticated, because the UID becomes a [cgroup](glossary.md#cgroup) and run-directory name on the home.
- `issuer` identifies the authority that signed the grant.
- `audience` names the home allowed to exercise the grant.
- `template_digest` fixes the pre-admitted OCI template or artifact.
- `tenant` names who the grant belongs to at the issuer, such as a Kubernetes namespace or a Slurm account. It is one path segment of letters, digits, `.`, `_` and `-`, at most 253 characters, starting with a letter or digit. A grant with any other value is refused as unauthenticated. A named [session](glossary.md#session) is filed under its tenant ([artifact.md](design/artifact.md)), so a grant without a tenant runs anonymous fibers only. A named `Clone` or `Park` under it fails with `FailedPrecondition`.
- `fibers.max` limits concurrent running fibers for the grant. Zero means no protocol-level count limit, while the enclosing resource boundary still applies.
- `fibers.warm` is carried through conversion but is not consumed by the runtime. It does not reserve or pre-create a [warm](glossary.md#warm) fiber pool.
- `w_budget_bytes` is the per-fiber [W](glossary.md#w-working-set) ceiling. Zero means unlimited at this layer. Enforcement is described in [resources.md](resources.md).
- `min_tier` is the lowest [tier](glossary.md#tier) the grant accepts. From lowest to highest the tiers are `FIBER_BASIC`, `FIBER_WARM`, `FIBER_CHECKPOINT`, `FIBER_SNAPSHOT` and `FIBER_FABRIC`. `FIBER_FABRIC` is reserved, and no home offers it. A home's tier comes from its [backend](design/backends.md).
- `lease_expiry` is the time after which the home stops holding the grant.
- `policy.durability` selects best-effort or synchronous audit handling.
- `policy.session_class` is the grant's [session class](glossary.md#session-class), which names, within the tenant, the domain its deltas are published and sealed under ([artifact.md](design/artifact.md)). `policy.audit_class` is carried as a label.
- `policy.psi_some_avg10_shed` and `policy.psi_some_avg10_park` override the pressure watermarks when non-zero.
- `policy.isolation` is `UNTRUSTED` or `TRUSTED`, and unset means `UNTRUSTED`. An untrusted grant is admitted only by a home whose runtime isolates tenants from the host kernel (gVisor or Hyperlight). Any other home refuses it with `FailedPrecondition`.
- `policy.endpoint_mode` is the [endpoint mode](glossary.md#endpoint-mode), `DIRECT` or `HANDOFF`, and unset means `DIRECT`. A `DIRECT` fiber listens on its own endpoint. A `HANDOFF` fiber is reached over TLS through the home's [handoff](glossary.md#handoff) listener. A `HANDOFF` grant must be bound to a caller certificate, and an unbound one is refused with `Unauthenticated`. A home that does not hand off connections refuses the grant with `FailedPrecondition` at admission, like a tier gap.
- `device_budget.bytes` and `device_budget.class` are the [device budget](glossary.md#device-budget) and the requested device class. The host enforces the bytes but does not compare the class with the [engine](glossary.md#engine).

## Fibers service

The `Fibers` service has four RPCs.

### Clone

`Clone(CloneRequest) returns (CloneResponse)` resolves a session and returns a dialable fiber.

The request has exactly four fields.

- `grant_jwt` contains the signed grant.
- `session` is an optional stable name. An empty value requests an anonymous fiber.
- `deadline` is an optional absolute timestamp for runtime work.
- `payload` is the optional [payload](glossary.md#payload).

If `deadline` is absent, the runtime supplies a default. The core defaults are 50 milliseconds for CREATE and 2 seconds for RESUME. A deadline already in the past is invalid. The payload is data for the prepared template and is never interpreted as workload configuration by the core.

The response contains these fields.

- `fiber_id` names the active [incarnation](glossary.md#incarnation) for [Park](glossary.md#park) and [Release](glossary.md#release), and it is the [fence](glossary.md#fence) written as a string, such as `g1/1/2`.
- `endpoint` is what callers dial, as returned.
- `fence` is the same fence as three fields, the grant, the agent's [epoch](glossary.md#epoch) and the sequence.
- `kind` is `CREATE`, `ATTACH` or `RESUME`.
- `routing_key` and `server_key_sha256` are set only for a `HANDOFF` fiber. The routing key names the fiber to the home's handoff listener. The key hash is what the caller pins the fiber's TLS key to.

The action depends on the session.

- An empty session produces `CREATE`.
- An unknown named session produces `CREATE`.
- A running named session produces `ATTACH`.
- A parked named session produces `RESUME`.

ATTACH returns the same fiber ID, endpoint and fence. CREATE and RESUME mint a new fence.

The diagram follows action selection and successful completion. [Outcomes](#outcomes) defines refusals and failure caveats.

![After grant verification, admission, thrash budget, and named lookup, Clone selects ATTACH for running state, RESUME for parked state, or CREATE for an unknown name or anonymous request. ATTACH audits and returns the same endpoint and fence without new runtime work. RESUME and CREATE need a slot and no shedding, then runtime work, audit, and commit before returning an endpoint with a new fence. Rejection or unavailable new work refuses the request.](images/clone-resolution.svg)

### Park

`Park(ParkRequest) returns (Empty)` checkpoints the identified running fiber and frees its running slot. A named session keeps the resulting [delta](glossary.md#delta) and can later RESUME. An anonymous fiber has no name through which its delta can be requested.

`sync=true` asks the runtime to complete its synchronous durability path before replying. The exact storage guarantee depends on the configured runtime and artifact store.

Do not Park an anonymous fiber when retained checkpoint files or a reserved TCP port would be unacceptable. The public API has no session handle with which to resume or discard that anonymous parked state.

### Release

`Release(ReleaseRequest) returns (Empty)` terminates the identified running fiber and frees its slot. This home then forgets the session's name, with or without `discard`, so the next Clone of that name is a CREATE.

- A session that was resumed still has the delta it came from on the home's disk. `discard=true` removes it. Without `discard` it stays there, unused.
- On a home with a delta registry, the copy published at the last park is withdrawn when the session resumes, so a Clone after Release does not find and resume that older state ([artifact.md](design/artifact.md)). If the withdrawal failed, a Release with `discard=true` tries again.
- The next park of a resumed session removes the delta it came from, because the new delta supersedes it.

Release looks up a running fiber ID, so the public API cannot use it to discard the delta of an already parked session.

Calling Park or Release with an unknown or old-epoch fiber ID returns `NotFound`. So does a fiber whose grant is bound to another caller's certificate.

### Watch

`Watch(Empty) returns (stream Status)` is the [Watch](glossary.md#watch) stream. It emits the records in an initial snapshot, records after ledger changes, and periodic refreshes. Each `Status` contains only these fields.

- `grant_uid`.
- The number of running fibers.
- The number of parked sessions.
- Aggregate measured `w_used_bytes` for running fibers.
- The latest fence value for the grant.

The stream does not advertise clone rate, desired replicas, warm-pool size, CPU usage or autoscaling decisions. Over mTLS it reports only the caller's own grants.

Snapshot batches are flattened into individual `Status` messages. There is no batch-complete marker or grant-deletion tombstone, and a transition from one grant to zero emits no record. Consumers cannot use Watch alone as an authoritative set-reconciliation protocol.

## Admission completeness

The protobuf request is the complete clone-time authority. The gRPC interceptor rejects unknown protobuf fields, including unknown fields inside nested messages, with `InvalidArgument`. The JSON gateway uses strict protobuf JSON decoding and rejects unknown JSON fields as well.

This rule prevents a caller from smuggling workload-shaping fields that the signed grant and admitted template did not cover.

## Fences and epochs

A fence has three fields.

```text
grant_uid / epoch / seq
```

- `grant_uid` binds the incarnation to one grant.
- `epoch` changes when the agent starts and when its home loses its [scope](glossary.md#scope).
- `seq` advances for each new CREATE or RESUME under the grant.

ATTACH preserves the existing fence. RESUME creates a newer sequence in the same epoch unless an epoch change occurred. Restart and scope loss invalidate all earlier running fiber IDs and fences. A fence orders incarnations but does not authenticate a process, network connection or end user.

## Endpoints

`endpoint` is a URL that callers use without discovering the address family.

```text
unix:///run/fiberd/<grant>/<epoch>-<seq>.sock
tcp://10.0.0.7:30012
tcp://[fd00::7]:30012
```

The supported forms are `unix://` with an absolute path and `tcp://` with a host and port. The configured home and [backend](glossary.md#backend) determine which form can be issued. IPv4 and IPv6 use the same `tcp://` scheme, and IPv6 literals are bracketed.

The endpoint is a transport address, not a separate identity. Address allocation, shared Pod or node addresses, ports and network policy are covered in [networking.md](networking.md).

### Handoff endpoints

For a `HANDOFF` fiber, `endpoint` is the home's handoff listener, the same `tcp://` address for every such fiber. The caller dials it with TLS 1.3 and does three things.

- It sends `<routing_key>.fiberd` as the TLS server name.
- It presents the certificate the grant is bound to.
- It accepts the server only if the base64url SHA-256 of its public key (SubjectPublicKeyInfo) equals `server_key_sha256`.

The home closes the connection without a reply if the server name is unknown, the fiber has ended, or no ClientHello arrives within 1 second. The fiber refuses any client certificate other than the grant's. In Go, `consumer.Fiber.DialHandoff` does all of this. A resumed session keeps its server key, on this home and on any home that shares the handoff key, but it gets a new routing key. Use the one from the latest Clone. The agent's side is in [handoff.md](design/handoff.md).

## Outcomes

The core returns transport-independent outcomes, and the gRPC layer maps them as follows.

- `SHED` becomes `ResourceExhausted`. It includes `Miss{code: SHED, retry_after_s, issuer}`.
- `DEFERRED_FALLBACK` becomes `Unavailable`. It includes `Miss{code: DEFERRED_FALLBACK, issuer, preferred_home}`. `preferred_home` names the [preferred home](glossary.md#preferred-home), set when parked session state should remain on another home.
- A [tier gap](glossary.md#tier-gap) becomes `FailedPrecondition`.
- A malformed request becomes `InvalidArgument`.
- An invalid grant, signature, issuer or audience becomes `Unauthenticated`.
- An unknown fiber becomes `NotFound`.
- A Clone runtime failure or missed deadline becomes `DEFERRED_FALLBACK`, whatever the lane's health. The grant's own task limit is the exception and becomes `SHED`.
- Admission and template-preparation failures become a capacity miss chosen by the lane's health, as below.
- Park and Release runtime failures become `Internal`.
- Audit failures can become `Internal`.

Any other capacity miss, such as an unknown, full, expired or revoked grant, is chosen by the health of the home's [lane](glossary.md#lane).

- When the control plane is healthy, unavailable capacity becomes `DEFERRED_FALLBACK`.
- When the control plane is unavailable, it becomes `SHED`, so callers never queue on a dead control plane.
- Local pressure and the [thrash budget](glossary.md#thrash-budget) always become `SHED`.

Every capacity miss carries a `Miss` detail. `SHED` tells the caller to wait for `retry_after_s` and retry. `DEFERRED_FALLBACK` tells the caller to use its ordinary provisioning path or route to `preferred_home`. [Shed and deferred](glossary.md#shed-and-deferred) says what each asks of the caller.

**Audit order.** Each call writes one audit record, and the calls order it differently against the state change.

- **Clone.** A new fiber's record is written before the ledger counts the fiber as running. A failed record releases the fiber and returns its slot, so an `Internal` from Clone means no fiber was committed. An ATTACH writes its record before it answers.
- **Park and Release.** The ledger changes first and the record follows, so an `Internal` from them can follow a change that already happened.
- **Lost replies.** A Clone whose reply was lost in transit may still have committed, so blindly retrying an anonymous Clone can create another fiber.

## JSON gateway

Starting fiberd with an HTTP address exposes a JSON face over the same core.

- `POST /v1/clone`
- `POST /v1/park`
- `POST /v1/release`
- `GET /v1/status`
- `GET /healthz`

Requests and successful responses use protobuf JSON. Errors use `google.rpc.Status` JSON. The HTTP status follows the gRPC code.

- `InvalidArgument` becomes 400.
- `Unauthenticated` becomes 401.
- `NotFound` becomes 404.
- `FailedPrecondition` becomes 412.
- `ResourceExhausted` becomes 429 and includes `Retry-After` for `SHED`.
- `Unavailable` becomes 503.
- Other failures become 500.

The HTTP status endpoint returns the current status snapshot. The streaming Watch RPC is available only over gRPC.

Both faces share one transport and one caller identity, described in [grant.md](design/grant.md).
