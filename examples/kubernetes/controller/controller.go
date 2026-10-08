// Package controller is the Kubernetes side of the reference issuer: it
// turns CapacityGrant resources into signed grants and grant Pods. For
// every CapacityGrant it creates the Pod (the agent as PID 1, with the
// readiness gate), mints a JWT addressed to that Pod with the resource's
// uid as the grant uid, projects it into the Pod through a Secret, renews
// it at half-life, and mirrors the Pod's placement and readiness gate
// into the resource's status. The key lives in a Secret; the public half
// is served as a JWKS beside the OIDC discovery document.
//
// It polls rather than watches: a list every few seconds is the same
// shape as the homes' grant lanes, needs no resourceVersion bookkeeping,
// and is more than fast enough for the number of grants a cluster holds.
package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/grant"

	"github.com/helayoty/fiberd/examples/kubernetes/kube"
)

type Controller struct {
	Client *kube.Client
	Issuer *grant.Issuer
	// Poll is the reconcile cadence (default 2s).
	Poll time.Duration
	// Now is for tests.
	Now func() time.Time
}

func (c *Controller) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// EnsureKey loads the issuer's private key from a Secret in ns, creating
// a fresh EdDSA key there when the Secret does not exist.
func EnsureKey(ctx context.Context, client *kube.Client, ns, name string) (*jose.JSONWebKey, error) {
	path := "/api/v1/namespaces/" + ns + "/secrets/" + name
	var sec struct {
		Data map[string][]byte `json:"data"`
	}
	err := client.Get(ctx, path, &sec)
	switch {
	case err == nil:
		raw, ok := sec.Data["key.json"]
		if !ok {
			return nil, fmt.Errorf("secret %s/%s has no key.json", ns, name)
		}
		var k jose.JSONWebKey
		if err := json.Unmarshal(raw, &k); err != nil {
			return nil, fmt.Errorf("secret %s/%s key.json: %w", ns, name, err)
		}
		return &k, nil
	case kube.IsNotFound(err):
		k, err := grant.GenerateKey(jose.EdDSA)
		if err != nil {
			return nil, err
		}
		raw, err := json.Marshal(k)
		if err != nil {
			return nil, err
		}
		sec := map[string]any{
			"apiVersion": "v1", "kind": "Secret",
			"metadata": map[string]any{"name": name, "namespace": ns},
			"data":     map[string][]byte{"key.json": raw},
		}
		if err := client.Create(ctx, "/api/v1/namespaces/"+ns+"/secrets", sec, nil); err != nil {
			if kube.IsConflict(err) {
				return EnsureKey(ctx, client, ns, name) // someone else won
			}
			return nil, err
		}
		log.Printf("controller: generated signing key %s in secret %s/%s", k.KeyID, ns, name)
		return k, nil
	default:
		return nil, err
	}
}

// Run reconciles until ctx ends.
func (c *Controller) Run(ctx context.Context) {
	every := c.Poll
	if every <= 0 {
		every = 2 * time.Second
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		if err := c.Reconcile(ctx); err != nil {
			log.Printf("controller: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Reconcile is one pass over every CapacityGrant in the cluster.
func (c *Controller) Reconcile(ctx context.Context) error {
	var list CapacityGrantList
	if err := c.Client.Get(ctx, "/apis/"+APIVersion+"/"+Resource, &list); err != nil {
		return fmt.Errorf("list capacitygrants: %w", err)
	}
	for i := range list.Items {
		cg := &list.Items[i]
		if cg.Metadata.DeletionTimestamp != "" {
			continue // the garbage collector takes the Pod and the Secret
		}
		if err := c.reconcileOne(ctx, cg); err != nil {
			log.Printf("controller: %s/%s: %v", cg.Metadata.Namespace, cg.Metadata.Name, err)
			// Only the message and the names: a transient error says
			// nothing about the Pod, so placed and ready stay as they were.
			_ = c.patchStatus(ctx, cg, map[string]any{"grantUID": cg.Metadata.UID, "podName": PodName(cg), "message": err.Error()})
		}
	}
	return nil
}

func (c *Controller) podPath(cg *CapacityGrant) string {
	return "/api/v1/namespaces/" + cg.Metadata.Namespace + "/pods/" + PodName(cg)
}

func (c *Controller) secretPath(cg *CapacityGrant) string {
	return "/api/v1/namespaces/" + cg.Metadata.Namespace + "/secrets/" + SecretName(cg)
}

func (c *Controller) reconcileOne(ctx context.Context, cg *CapacityGrant) error {
	lease, err := leaseOf(cg)
	if err != nil {
		return err
	}
	// The grant is checked before anything is made. A Pod for a spec that
	// cannot be minted, or minted but not served, would only sit there.
	now := c.now()
	g, err := grantOf(cg, lease, now)
	if err != nil {
		return err
	}
	// 1. The Pod.
	var p Pod
	switch err := c.Client.Get(ctx, c.podPath(cg), &p); {
	case err == nil && p.Status.Phase == "Failed":
		// A Failed Pod (evicted, or its node lost) never runs again. It is
		// deleted, and the next pass creates a fresh one.
		if err := c.Client.Delete(ctx, c.podPath(cg)); err != nil && !kube.IsNotFound(err) {
			return fmt.Errorf("delete failed pod: %w", err)
		}
		log.Printf("controller: deleted failed grant pod %s/%s", cg.Metadata.Namespace, PodName(cg))
		p = Pod{}
	case err == nil:
	case kube.IsNotFound(err):
		want := BuildPod(cg, c.Issuer.URL, lease)
		if err := c.Client.Create(ctx, "/api/v1/namespaces/"+cg.Metadata.Namespace+"/pods", want, &p); err != nil && !kube.IsConflict(err) {
			return fmt.Errorf("create pod: %w", err)
		}
		log.Printf("controller: created grant pod %s/%s", cg.Metadata.Namespace, PodName(cg))
	default:
		return fmt.Errorf("get pod: %w", err)
	}
	// 2. The grant: minted for that Pod, renewed at half-life. The grant
	// uid is the resource's uid, so a renewal is the same grant with a
	// longer lease.
	st := Status{GrantUID: cg.Metadata.UID, PodName: PodName(cg)}
	renew := true
	if exp, err := time.Parse(time.RFC3339, cg.Status.ExpiresAt); err == nil && cg.Status.GrantUID == cg.Metadata.UID {
		renew = exp.Sub(now) < lease/2
		st.IssuedAt, st.ExpiresAt = cg.Status.IssuedAt, cg.Status.ExpiresAt
	}
	var secExists bool
	var sec struct {
		Metadata kube.ObjectMeta `json:"metadata"`
	}
	switch err := c.Client.Get(ctx, c.secretPath(cg), &sec); {
	case err == nil:
		secExists = true
	case kube.IsNotFound(err):
		renew = true
	default:
		return fmt.Errorf("get secret: %w", err)
	}
	if renew {
		tok, err := c.Issuer.Mint(g)
		if err != nil {
			return fmt.Errorf("mint: %w", err)
		}
		if secExists {
			if err := c.Client.PatchMerge(ctx, c.secretPath(cg), map[string]any{"stringData": map[string]string{GrantsFile: tok}}); err != nil {
				return fmt.Errorf("update secret: %w", err)
			}
		} else {
			obj := map[string]any{
				"apiVersion": "v1", "kind": "Secret",
				"metadata": kube.ObjectMeta{Name: SecretName(cg), Namespace: cg.Metadata.Namespace,
					Labels: map[string]string{GrantLabel: cg.Metadata.Name}, OwnerReferences: ownerOf(cg)},
				"stringData": map[string]string{GrantsFile: tok},
			}
			if err := c.Client.Create(ctx, "/api/v1/namespaces/"+cg.Metadata.Namespace+"/secrets", obj, nil); err != nil && !kube.IsConflict(err) {
				return fmt.Errorf("create secret: %w", err)
			}
		}
		st.IssuedAt = now.UTC().Format(time.RFC3339)
		st.ExpiresAt = g.LeaseExpiry.UTC().Format(time.RFC3339)
		log.Printf("controller: minted grant %s for %s/%s until %s", g.UID, cg.Metadata.Namespace, PodName(cg), st.ExpiresAt)
	}
	// 3. What the Pod says.
	if p.Spec.NodeName != "" {
		st.Placed, st.Node = true, p.Spec.NodeName
	}
	for _, cond := range p.Status.Conditions {
		if cond.Type == ReadyCondition && cond.Status == "True" {
			st.Ready = true
		}
	}
	if p.Status.PodIP != "" {
		st.Endpoint = net.JoinHostPort(p.Status.PodIP, strconv.Itoa(agentPort))
	}
	if st == cg.Status {
		return nil
	}
	return c.patchStatus(ctx, cg, wholeStatus(st))
}

// patchStatus merges st into the resource's status.
func (c *Controller) patchStatus(ctx context.Context, cg *CapacityGrant, st any) error {
	path := "/apis/" + APIVersion + "/namespaces/" + cg.Metadata.Namespace + "/" + Resource + "/" + cg.Metadata.Name + "/status"
	return c.Client.PatchMerge(ctx, path, map[string]any{"status": st})
}

// wholeStatus is st as a merge patch that replaces the whole status. A
// merge patch keeps every field it leaves out, so each field st leaves
// empty is sent as null. Otherwise an old error message, or the node and
// endpoint of a Pod since replaced, would outlive what they described.
func wholeStatus(st Status) map[string]any {
	raw, _ := json.Marshal(st)
	m := map[string]any{}
	_ = json.Unmarshal(raw, &m)
	t := reflect.TypeFor[Status]()
	for i := range t.NumField() {
		name, _, _ := strings.Cut(t.Field(i).Tag.Get("json"), ",")
		if _, ok := m[name]; !ok {
			m[name] = nil
		}
	}
	return m
}

func leaseOf(cg *CapacityGrant) (time.Duration, error) {
	if cg.Spec.Lease == "" {
		return 10 * time.Minute, nil
	}
	d, err := time.ParseDuration(cg.Spec.Lease)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("spec.lease %q: want a positive duration", cg.Spec.Lease)
	}
	return d, nil
}

// isolating holds the spec.pod.runtime values whose backend implements
// backend.Isolator. The agent refuses every Clone of an untrusted grant
// on any other runtime, so such a grant is refused here instead.
var isolating = map[string]bool{"gvisor": true, "hyperlight": true}

// grantOf is the protocol grant a CapacityGrant describes, addressed to
// its Pod (whose node id is its name) and valid for one lease from now.
func grantOf(cg *CapacityGrant, lease time.Duration, now time.Time) (core.Grant, error) {
	w, err := ParseBytes(cg.Spec.WBudget)
	if err != nil {
		return core.Grant{}, fmt.Errorf("spec.wBudget: %w", err)
	}
	tier := core.TierBasic
	if cg.Spec.MinTier != "" {
		if tier, err = core.ParseTier(cg.Spec.MinTier); err != nil {
			return core.Grant{}, fmt.Errorf("spec.minTier: %w", err)
		}
	}
	iso, err := core.ParseIsolation(cg.Spec.Isolation)
	if err != nil {
		return core.Grant{}, fmt.Errorf("spec.isolation: %w", err)
	}
	if iso.Untrusted() && !isolating[runtimeOf(cg.Spec.Pod)] {
		return core.Grant{}, errors.New("spec.isolation UNTRUSTED needs an isolating runtime (gvisor or hyperlight); " +
			"set spec.pod.runtime, or set spec.isolation TRUSTED if the code is trusted")
	}
	var d core.Durability
	switch strings.ToLower(cg.Spec.Durability) {
	case "", "best-effort", "best_effort", "besteffort":
		d = core.BestEffort
	case "sync":
		d = core.Sync
	default:
		return core.Grant{}, fmt.Errorf("spec.durability %q", cg.Spec.Durability)
	}
	g := core.Grant{
		UID: cg.Metadata.UID, Audience: PodName(cg), TemplateDigest: cg.Spec.Template,
		FiberMax: cg.Spec.Fibers.Max, FiberWarm: cg.Spec.Fibers.Warm, WBudgetBytes: w, MinTier: tier,
		LeaseExpiry: now.Add(lease).Truncate(time.Second),
		Policy:      core.Policy{Durability: d, SessionClass: cg.Spec.SessionClass, Isolation: iso},
	}
	if db := cg.Spec.DeviceBudget; db != nil {
		b, err := ParseBytes(db.Bytes)
		if err != nil {
			return core.Grant{}, fmt.Errorf("spec.deviceBudget.bytes: %w", err)
		}
		g.DeviceBudget = core.DeviceBudget{Bytes: b, Class: db.Class}
	}
	return g, nil
}

// ParseBytes reads a byte count with an optional Ki/Mi/Gi (or K/M/G)
// suffix; empty is zero.
func ParseBytes(s string) (uint64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	mult := uint64(1)
	for _, suf := range []struct {
		s string
		m uint64
	}{{"Ki", 1 << 10}, {"Mi", 1 << 20}, {"Gi", 1 << 30}, {"K", 1000}, {"M", 1000 * 1000}, {"G", 1000 * 1000 * 1000}} {
		if strings.HasSuffix(s, suf.s) {
			s, mult = strings.TrimSuffix(s, suf.s), suf.m
			break
		}
	}
	n, err := strconv.ParseUint(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return 0, err
	}
	return n * mult, nil
}
