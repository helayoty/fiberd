# The grant protocol

The only cross-environment contract in fiberd is [`api/grant/v1/grant.proto`](../api/grant/v1/grant.proto). A control plane (the **issuer**) signs a `CapacityGrant` once; a **home** (a standalone host, a Kubernetes grant Pod, a Slurm allocation) verifies it offline and mints fibers under it through the `Fibers` service. Nothing on the `Clone` path calls back to the issuer. This page states the wire semantics; the conformance suite (`grant-conform`) is the executable version.

## The grant

| Field | Meaning |
| --- | --- |
| `grant_uid` | identity; also the JWT `jti` |
| `issuer` | OIDC issuer URL of the issuing control plane; verifiers discover the JWKS here; also the JWT `iss` |
| `audience` | the home that may exercise the grant; also the JWT `aud`; a home refuses grants for another audience |
| `template_digest` | OCI digest of the zygote artifact or template image; everything executable is fixed here |
| `fibers.max`, `fibers.warm` | ceiling on running fibers; warm floor to keep pre-forked |
| `w_budget_bytes` | per-fiber dirtied working set ceiling; enforced as cgroup `memory.max`; also the mobility budget |
| `min_tier` | lowest runtime tier that may satisfy the grant |
| `lease_expiry` | the JWT `exp`; revocation is lease non-renewal |
| `policy` | durability (`BEST_EFFORT` / `SYNC`), session and audit class, PSI watermarks |

The grant is carried inside every `CloneRequest` as a JWT. Its verified arrival at a home *is* admission: the home admits it on first sight, warms the template, and never re-checks anything on the warm path.

## The four verbs

```
Clone(grant_jwt, session?, deadline?, payload?) -> fiber_id, endpoint, fence, kind
Park(fiber_id, sync)                            -> ()
Release(fiber_id, discard)                      -> ()
Watch()                                         -> stream Status
```

`Clone` with a `session` is idempotent: the home serializes on the session name and resolves it to `ATTACH` (running: same endpoint, same fence), `RESUME` (parked: restore the delta, fence `seq+1`) or `CREATE` (unknown or anonymous: clone the template, fence `seq+1`). `deadline` bounds the runtime fork or restore; a late fiber is a miss, not a result. `payload` is at most 4096 bytes and is delivered to the fiber as data, never interpreted as configuration.

## Admission completeness

`CloneRequest` has exactly four fields. A request carrying any other field, on gRPC or on the JSON gateway, is rejected with `InvalidArgument` before the handler runs. Protobuf preserves unknown fields on decode, so this is a check, not a silent drop.

## Outcomes

| Outcome | gRPC code | Detail | Caller action |
| --- | --- | --- | --- |
| served | `OK` | `CloneResponse` | use the endpoint until the fence or lease dies |
| **SHED** | `ResourceExhausted` | `Miss{SHED, retry_after_s}` | back off for `retry_after_s`; never queue on a dead control plane |
| **DEFERRED_FALLBACK** | `Unavailable` | `Miss{DEFERRED_FALLBACK, issuer, preferred_home?}` | fall back through `issuer` to the home's ordinary provisioning path; `preferred_home` names where the session's parked state lives, when known |
| tier gap | `FailedPrecondition` | | the grant's `min_tier`, or a parked session, needs a tier this home lacks; the home never substitutes a lesser mechanism |
| malformed | `InvalidArgument` | | payload too large, unknown field, deadline already passed |
| not verified | `Unauthenticated` | | bad signature, wrong audience, undecodable grant |
| no such fiber | `NotFound` | | the fiber id is unknown in this epoch; every id from before a restart is |
| home fault | `Internal` | | runtime or audit failure that is not a capacity question |

The two miss codes are keyed on one question: **is the control plane reachable from this home?** Capacity misses (grant unknown, at `fibers.max`, lease expired, template not ready) are `DEFERRED_FALLBACK` while the grant lane is healthy and `SHED` while it is stale. A home with no health signal fails toward healthy. Budget backpressure is always `SHED`. Every miss carries the `Miss` detail; a bare code is a conformance failure.

## Fences and epochs

A fence is `(grant_uid, epoch, seq)`. `epoch` is the home's incarnation, bumped on every start; `seq` is the fiber incarnation within `(grant, epoch)`. Attach returns the existing fence; resume and create mint `seq+1`. After a restart every prior fence is invalid at once: `Park` or `Release` on a prior-epoch fiber id is `NotFound`, and a new `Clone` returns a fence with a strictly greater `epoch`.

### Scope

Nothing minted for a fiber validates beyond `min(lease, fence)`; that is the only rule the core enforces, in every home. A home that knows more about where it runs (the namespace and service account of a grant Pod, the DRA claim behind a fabric channel, the Slurm job) does not add a third validity term. It turns its scope into the two mechanisms above: **whole-agent scope loss is an epoch bump**, taken in place while the agent lives (`Agent.BumpEpoch`: the epoch is persisted, every running fiber is released with a `scope-revoked` audit record, every prior fence answers `NotFound`, new clones carry the new epoch, parked sessions keep their deltas and resume under it); **per-grant scope loss is a revocation on the grant lane** (`GrantRemoved`: admission stops, fibers drain by lease non-renewal, readiness is withdrawn, and the grant's fabric channel is released). The home's scope claims are visible, not enforced: they are stamped on every audit record (`scope`), so a reader can check namespace integrity against facts the home vouched for. The fence string on the wire never changes.

A grant's **fabric channel** (the devices its engine may drive: a static set on a standalone host, a DRA claim under Kubernetes, the allocation's GRES under Slurm) is provisioned by the home at admission, before the template is warmed, and released with the grant. Nothing per fiber refers to it except through its fence.

## Device budget

`CapacityGrant.device_budget {bytes, class}` is the device-side twin of `w_budget_bytes`: the slice of the engine's device state (its KV cache, its VRAM) one fiber may hold. On the GPU side the CPU side is cloned and the device side is multiplexed: one engine per grant owns the device, and fibers are its clients over the IPC endpoint the home publishes to them as `FIBERD_ENGINE`. The engine, not the kernel, reports each fiber's slice (`DEVICE <fence> <bytes> 0`) and its own occupancy (`DEVICE - <used> <capacity>`) on the zygote channel; the home prices those reports, kills a fiber whose slice exceeds its budget (reason `oom`, like W), and feeds the occupancy into the same pressure ladder as PSI (the higher reading drives the rungs). A park tells the engine `EVICT <fence>` before the CPU checkpoint: devices are renegotiated, never checkpointed, and a resumed fiber reserves again under its new fence (published in the fence file beside its endpoint). A home whose template is not an engine of the grant's class refuses the grant with `FailedPrecondition`, never a silent CPU-only fiber. The reference workload's `--device-mb N` is a simulated engine, so all of this is tested without a GPU; a CUDA engine is a drop-in that speaks the same lines.

## Endpoints

`CloneResponse.endpoint` is a URL the caller dials as given and never inspects:

| Form | When |
|---|---|
| `unix:///run/fiberd/<grant>/<epoch>-<seq>.sock` | callers on the same host (the default; the only form a sandbox backend such as gVisor serves) |
| `tcp://10.0.0.7:30012`, `tcp://[fd00::7]:30012` | callers over the network; an IPv6 literal is bracketed |

Which family a home hands out is **declared per deployment, never discovered**: the standalone home takes `-endpoint-family unix|inet4|inet6` with `-endpoint-host` (the one address the grant's fibers share) and `-endpoint-ports` (one port per live fiber, freed when it ends); the Kubernetes home takes the address from its Pod and the Slurm home from its node. Under a shared address fibers are told apart by port, which is the model for IPv4 and equally for one IPv6 address per grant; network policy is then per grant. A parked fiber keeps its port so the restored listener comes back where it was; a resume on a home whose port is taken fails rather than moving the fiber silently. Per-fiber IPv6 addresses (a delegated prefix per grant, a network namespace per fiber, policy per fiber) are a further policy the protocol leaves room for and this implementation does not build. Conformance case C1 checks every endpoint's form.

## Session mobility

A parked session belongs to a **session domain**, not to a grant: `policy.session_class` when the grant sets one, otherwise `template_digest`. Two grants in the same domain, on any two homes, name the same sessions. Nothing about this is on the wire beyond `preferred_home`; it is an agreement about where parked state lives:

- **Park publishes.** After a park the home pushes the delta (the pages that differ from the zygote's checkpoint, W bytes) as an OCI artifact to the delta registry it was started with, under a repository derived from the domain and a tag derived from the session name; the zygote's parent checkpoint is published beside it by content hash. The manifest annotations carry `w_bytes`, the parent hash, the publishing home and the fence, so a peer can decide without pulling. A publish failure keeps the session parked locally; it is not a park failure.
- **Clone(S) looks before it forks.** A home that does not hold S looks the tag up in the registry. If the delta is within the grant's `w_budget_bytes` (or the home's own mobility cap, whichever is lower) it pulls it, pulls the parent if it lacks it, and then **claims** the session by deleting the tag. A claim that finds the tag already gone lost the race and creates fresh. The response is `RESUME` with a fence from the claiming home's grant.
- **Ownership is the tag.** A home that still has a parked copy of S checks, on the next `Clone(S)`, that the registry tag still points at the digest it published. If a peer has claimed it, the local copy is stale: the home forgets it (audit `migrate-out`) and proceeds as if S were unknown, which usually means asking the registry again.
- **Too large to move** is a miss, not a pull. A delta over the budget yields `DEFERRED_FALLBACK` with `preferred_home` set to the home that published it, so the caller can route the session back to where its state already is. With the grant lane down the same situation is `SHED`.

The W budget is therefore both the per-fiber memory ceiling and the mobility budget: a session can never be more expensive to move than it was allowed to dirty. Registries only need the OCI distribution API with manifest deletion enabled; the home tolerates registries that refuse tag deletes and drop the tag when the manifest goes.

### Platform parity

A checkpoint is a picture of a process on one host. Its pages assume the instruction set; its file-backed mappings assume the exact libc the loader mapped (a checkpoint records offsets and sizes, not the library's bytes); what the kernel let the process have assumes that kernel. So the zygote artifact records the build host's **arch, kernel release and libc** in its config, and every published delta and parent checkpoint carries the same three facts as manifest annotations. A home compares them with its own host in two places:

- before warming a grant from an artifact's images (`PrepareTemplate`): a mismatch refuses the template, so the grant is never ready on that home;
- before taking a session from the registry (`Clone(S)` on a home that lacks S): a mismatch is `DEFERRED_FALLBACK` with `preferred_home` set to the home that parked it, and the session stays published for a compatible home.

The architecture must always match. Kernel and libc are compared at a level the home is started with (`fiberd -parity`): `strict` (the default) wants the identical release string and libc version; `kernel=series` accepts any patch release of the same major.minor; `kernel=off` and `libc=off` skip the fact. Relaxing is the operator's call and their risk: CRIU restores across kernel patch releases in practice, but a libc that differs even by a distribution revision is a different file with different mapping sizes, and a restore into it fails late or corrupts silently. `zygotectl inspect -parity <level>` shows the verdict a home at that level would reach on the current host. The wire protocol is unchanged; parity is a property of homes and artifacts, and only `preferred_home` reflects it.

## Status

`Watch` streams one `Status` per admitted grant on every change and at least once per status interval: `running`, `parked`, `w_used_bytes` (sum of the dirtied working sets of running fibers) and `latest` (the most recently minted fence). It is the only thing a control plane ever sees; never individual fibers.

## Audit

Every state transition writes one record carrying the fence, and the home's scope claims when it has any, to the home's spool before the caller is acked. The events are `admit`, `create`, `attach`, `resume`, `park`, `release`, `oom`, `expire`, `yield` (the pressure ladder took the fiber), `revoke` (the grant was removed on the grant lane), `scope-revoked` (an epoch bump in place), and the mobility events `publish`, `migrate-in` and `migrate-out`. Under `BEST_EFFORT` the record is appended locally and shipped asynchronously; under `SYNC` it is remote before the ack, and a shipping failure fails the call.

## JSON gateway

`fiberd -http=:8485` mounts the same service as `POST /v1/clone`, `/v1/park`, `/v1/release` and `GET /v1/status`, taking and returning protobuf JSON. Errors are the `google.rpc.Status` JSON with the `Miss` detail embedded; HTTP codes follow the gRPC codes (`SHED` is 429 with `Retry-After`, `DEFERRED_FALLBACK` is 503, tier gap is 412).

## Conformance

`grant-conform -target=host:port` runs the cases any home must pass:

| Case | Property |
| --- | --- |
| C1 idempotency | `Clone(S)` twice: second is `ATTACH`, same endpoint and fence |
| C2 fence monotonic | `Park`, `Clone(S)`: `RESUME`, `seq+1`, same `epoch` |
| C3 epoch bump | restart the target: every prior fence rejected; new `epoch` greater |
| C4 revocation by TTL | expired grant: `SHED` with the lane down, `DEFERRED_FALLBACK` with it healthy |
| C5 admission completeness | any field beyond the four: `InvalidArgument` |
| C6 W budget | dirtied working set over `w_budget_bytes`: fiber killed, slot freed, audit record written |
| C7 tier floor | `min_tier` above the target, or a parked session on a sub-checkpoint target: `FailedPrecondition`, never a fresh fork |
| C8 device budget | a grant with `device_budget` is refused with `FailedPrecondition` where the template offers no such device, else a fiber whose engine slice exceeds the budget is killed, its slot freed and an audit record written (payload `device_bytes` drives it) |
| C9 engine loss | the grant's engine (warm template) dies: every running fiber ends and its slot returns, parked sessions survive, and `Clone(S)` on a parked session resumes it once the template is warm again (driven by `-engine-kill-cmd`) |
| C10 scope revocation | the home loses its scope while running (driven by `-scope-cmd`): every running fiber ends, every prior fence is `NotFound`, a new `Clone` carries a strictly greater `epoch`, and a session parked before resumes under it |

## Issuer alternatives

The reference issuer (`grant-issuer`) signs with its own key and publishes it at `<issuer>/.well-known/openid-configuration` and `/openid/v1/jwks`. An integration runs the same issuer inside its own control plane: the Kubernetes example (`examples/kubernetes`) wraps it in a controller whose key lives in a Secret, whose JWKS is served on a Service, and which turns every `CapacityGrant` resource into one grant Pod and one signed grant addressed to it, renewed at half-life. A cluster may instead reuse the API server's service-account issuer, so grants are minted as projected service-account tokens carrying the `grant` claim; homes then discover the JWKS from the cluster issuer. That is acceptable where the API server's signing key may be trusted for capacity, and keeps one PKI; the reference issuer is the default because it is portable across distributions and off-cluster homes.
