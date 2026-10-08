# Networking

This page says how a caller reaches a [fiber](glossary.md#fiber) and what an operator must make reachable. It is for anyone planning a [home](glossary.md#home)'s network. Read [architecture.md](architecture.md) first. The endpoint forms per [backend](glossary.md#backend) are in [design/networking.md](design/networking.md), and the [handoff](glossary.md#handoff) mechanism in [design/handoff.md](design/handoff.md).

![The caller sends Clone to the agent and gets back a TCP port on the home address. Fiber A is a proc fiber. It binds its own port, and its traffic bypasses the agent. Fiber B runs on gVisor, runc or Hyperlight. The agent relays its port to the fiber's unix socket and copies bytes without reading them. HANDOFF is a separate path for proc and runc. One shared TLS listener hands each connection to its fiber, which terminates TLS.](./images/networking.svg)

## Clone returns the route

The caller sends [Clone](glossary.md#clone) to the [agent](glossary.md#agent)'s control endpoint, gRPC on port 8484 by default, and gets back one fiber endpoint, which it dials directly. The agent is not on the data path. fiberd registers no fiber with any discovery service, so the caller keeps the endpoint it was given for as long as the incarnation runs.

## One family per home

A home serves one address family, `unix`, `inet4` or `inet6`. The agent defaults to `unix`, while the Kubernetes example's grant Pod defaults to `inet4`. A unix endpoint serves callers on the same host. Under `inet4` or `inet6` every backend gives callers `tcp://<home-ip>:<port>`, with a port per fiber from `30000` to `32767` by default. proc serves TCP itself, and runc, gVisor and Hyperlight fibers are reached through the agent's [relay](glossary.md#relay) ([design/networking.md](design/networking.md)). Under Kubernetes this is how an `UNTRUSTED` grant's fibers are reached over the Pod IP.

## Handoff

A handoff [grant](glossary.md#grant) puts its fibers behind one TLS listener on the home instead of a port each. Only proc and runc support it.

Turn it on with one flag on the agent and one on the grant.

```bash
bin/fiberd ... -handoff-listen :8443
bin/grant-issuer mint ... -endpoint-mode HANDOFF -bind-cert caller.pem
```

Homes that move [sessions](glossary.md#session) between them share one `-handoff-key`, so a resumed session keeps the key its caller pinned. The caller's steps are in [protocol.md](protocol.md#handoff-endpoints).

## Operator notes

- Keep the endpoint returned by Clone while the incarnation runs.
- Make the home address and the fiber port range, or the handoff port, reachable from the callers, or from the router in front of them.
- Apply network policy at the boundary the home supplies, such as the Pod.
- An endpoint is a route, not authentication. Use handoff, or TLS in the workload, when the network is not trusted.
