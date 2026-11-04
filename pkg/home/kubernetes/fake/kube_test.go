package fake_test

import (
	"context"
	"errors"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"

	"github.com/Azure/fiberd/pkg/home/kubernetes/fake"
)

// TestZeroKube checks that the zero value is an empty cluster, where
// every read and patch answers NotFound and nothing is held.
func TestZeroKube(t *testing.T) {
	cases := []struct {
		name string
		call func(k *fake.Kube) error
	}{
		{name: "the Pod", call: func(k *fake.Kube) error {
			_, err := k.GetPod(context.Background(), "ns", "pod")
			return err
		}},
		{name: "the namespace", call: func(k *fake.Kube) error {
			_, err := k.GetNamespace(context.Background(), "ns")
			return err
		}},
		{name: "a claim", call: func(k *fake.Kube) error {
			_, err := k.GetResourceClaim(context.Background(), "ns", "claim")
			return err
		}},
		{name: "the patch", call: func(k *fake.Kube) error {
			return k.PatchPodStatus(context.Background(), "ns", "pod", []byte(`{}`))
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var k fake.Kube
			if err := c.call(&k); !apierrors.IsNotFound(err) {
				t.Fatalf("got %v, want NotFound", err)
			}
			if k.Pod() != nil || len(k.Patches()) != 0 {
				t.Fatal("the zero cluster holds something")
			}
		})
	}
}

// TestZeroKubeSetters checks that the setters work on the zero value.
func TestZeroKubeSetters(t *testing.T) {
	cases := []struct {
		name  string
		set   func(k *fake.Kube)
		claim string
		// wantErr is whether the claim read fails afterwards.
		wantErr bool
	}{
		{name: "a claim added is read", set: func(k *fake.Kube) { k.SetClaim("gpu", false) }, claim: "gpu"},
		{name: "a claim error set is returned", set: func(k *fake.Kube) { k.SetClaimErr("gpu", errors.New("no access")) },
			claim: "gpu", wantErr: true},
		{name: "a claim error cleared on nothing is fine", set: func(k *fake.Kube) { k.SetClaimErr("gpu", nil) }, claim: "gpu", wantErr: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var k fake.Kube
			c.set(&k)
			_, err := k.GetResourceClaim(context.Background(), "ns", c.claim)
			if (err != nil) != c.wantErr {
				t.Fatalf("GetResourceClaim = %v, want an error %v", err, c.wantErr)
			}
			if n := k.Calls("GetResourceClaim"); n != 1 {
				t.Fatalf("calls %d, want 1", n)
			}
		})
	}
}
