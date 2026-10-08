# Networking

fiberd gives every running fiber an endpoint. The surrounding home and
selected backend determine which endpoint families are available, what the
fiber can reach, and where callers can connect.

![In DIRECT TCP mode, the caller exchanges Clone and its result with the agent's control endpoint, then sends workload traffic directly to the selected fiber, bypassing the agent. Fibers share the home address but have distinct ports. HANDOFF uses a different shared-listener path, with TLS terminated by the fiber.](./images/networking.svg)

## Clone returns the data-plane route

The caller first connects to the fiberd agent and sends `Clone`. The agent
creates or resolves one fiber and returns its endpoint.

1. The caller sends `Clone` to the agent's control endpoint.
2. fiberd allocates the fiber's endpoint before starting the workload.
3. The successful response carries that exact endpoint.
4. The caller connects directly to the returned endpoint.

The control endpoint and the fiber endpoint serve different purposes. The
control endpoint accepts fiberd operations such as `Clone`, `Park`, and
`Release`. The fiber endpoint belongs to the workload created from the warm
template.

fiberd does not register individual fibers with a central discovery service.
The caller or router that requested the fiber must retain and use the endpoint
returned by `Clone`.

## Endpoint forms

The home selects one endpoint family when it starts.

- A `unix://` endpoint is a socket under the configured run directory. It is
  intended for callers that can access the same host path.
- A `tcp://` endpoint uses the address declared by the home and one allocated
  port. IPv6 literals are enclosed in brackets.

The default TCP port pool is `30000-32767` unless the home configures another
range. One live fiber holds one port. A parked session retains its port so its
listener can return on the same endpoint after resume. The port is released
when the fiber ends without being parked or when its parked state is
discarded. The current public API cannot address an already parked session for
discard, so deployments need an external retention and garbage-collection
plan to keep ports bounded.

Backend support is not uniform.

- **proc** supports Unix and TCP endpoints. Its TCP fibers use the home's
  network namespace.
- **runc** supports Unix endpoints only. Its fibers run in a network
  namespace with the loopback alone and reach neither the network nor the
  home's loopback.
- **gVisor** currently supports Unix endpoints only and runs with networking
  disabled in the reference backend.
- **Hyperlight** currently supports Unix endpoints only.

The runtime rejects a TCP configuration when the selected backend does not
advertise TCP support.

## IPv4 and IPv6

The endpoint family is an explicit deployment choice.

- `inet4` requires an IPv4 address and produces endpoints such as
  `tcp://10.244.0.8:30001`.
- `inet6` requires an IPv6 address and produces endpoints such as
  `tcp://[fd00::8]:30001`. The brackets separate the IPv6 literal from the
  port.

A dual-stack home does not advertise both families for the same runtime.
fiberd selects the address that matches the configured family, and every TCP
fiber uses that address with its own port.

IPv6 changes the endpoint format, but it does not change the isolation model.
The current implementation does not delegate an IPv6 prefix, allocate an
address to each fiber, or create a network namespace per fiber.

## Fibers share the home address

Under the TCP model, fibers share the home address and differ by port.

```text
tcp://10.244.0.8:30001  fiber A
tcp://10.244.0.8:30002  fiber B
tcp://10.244.0.8:30003  fiber C
```

fiberd does not create any of the following for an individual fiber:

- an IP address
- a network namespace
- a discovery record
- a network-policy object

The endpoint is a route to the fiber, not proof of the fiber's identity. The
workload protocol must provide authentication and encryption when callers
require them, or the grant can use handoff, below.

## Handoff endpoints

A grant with `policy.endpoint_mode: HANDOFF` puts its fibers behind one TLS
listener on the home instead of a port each. Callers reach every such fiber
on the same address, and the TLS server name picks the fiber.

```text
tcp://10.244.0.8:8443  SNI k3x...q7.fiberd  fiber A
tcp://10.244.0.8:8443  SNI p9m...a2.fiberd  fiber B
```

The agent reads only the TLS ClientHello, then passes the connection to the
fiber, which terminates TLS itself. The agent never sees the traffic.

- The fiber accepts only the client certificate the grant is bound to, so
  a handoff grant must be minted with `-bind-cert`.
- The caller pins the fiber's TLS key with `server_key_sha256` from the
  Clone response, so a connection can't reach another fiber unnoticed.
- No fiber holds a port, and the home has one port to expose and police.

Turning it on:

- `-handoff-listen <addr>` opens the listener, for example `:8443`. Without
  it, the home refuses handoff grants with `FailedPrecondition`.
- `-handoff-advertise <host:port>` is the address callers are given. By
  default it is the listen address, with `-endpoint-host` in place of a
  wildcard host, or `127.0.0.1` with a warning when neither is set.
- `-handoff-key <file>` is the 32-byte key each grant's TLS key is derived
  from, a symmetric JWK as `grant-issuer keygen -alg A256GCM` writes it.
  Without it, the home generates `<state>/private/handoff-key.json`. Homes that
  move sessions between them share one, so a resumed session keeps the key
  its caller pinned.
- `grant-issuer mint -endpoint-mode HANDOFF` mints a handoff grant.

Only the `proc` and `runc` backends support handoff. The template must
serve TLS on the connections it is passed. The reference template does so
when it is built with `make zygote`. A build without TLS refuses to start
handoff fibers rather than serve them in plaintext.

## Secure the control path separately

The gRPC API and the JSON gateway require TLS 1.3 with a client certificate,
and every call, including `Park`, `Release`, and `Watch`, acts as the
certificate's subject. Plaintext is available only for development (see
[Security](security.md#control-plane)).

The data endpoint is separate. For a `DIRECT` fiber, fiberd does not
authenticate or encrypt it, so it needs workload-level authentication and
encryption when its network is not fully trusted. A `HANDOFF` fiber gets
both from its TLS connection, as described above.

## Mobility requires compatible endpoint topology

A resumed session currently reuses the exact endpoint stored in its manifest.
A target home must be able to bind and route that source endpoint. This is
usually not true for a source Pod IP on another node, and Unix sockets require
a shared path topology. Cross-home mobility therefore requires an endpoint
design that is valid from both homes; scheme compatibility alone is not
enough.

## Operator implications

- Keep the endpoint returned by `Clone` for as long as the incarnation is
  running.
- Make the home address and fiber port range reachable from the router.
- Apply network policy at the boundary supplied by the home.
- Do not treat an endpoint or port as authentication.

For grant authentication, fences, and workload credentials, see the
[identity model](identity.md). For the process and sandbox relationships, see
the [runtime model](runtime-model.md). For the exact endpoint wire fields, see
the [protocol reference](protocol.md). For Pod addresses, Services,
EndpointSlices, NetworkPolicy, and router reachability, see
[Kubernetes operations](operating-kubernetes.md#networking). For deployment
controls and current blockers, see
[Production readiness](production-readiness.md).
