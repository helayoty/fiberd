package kubernetes_test

import (
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"

	"github.com/helayoty/fiberd/pkg/home/kubernetes"
)

func group(name, preferred string, versions ...string) metav1.APIGroup {
	g := metav1.APIGroup{Name: name, PreferredVersion: metav1.GroupVersionForDiscovery{Version: preferred}}
	for _, v := range versions {
		g.Versions = append(g.Versions, metav1.GroupVersionForDiscovery{GroupVersion: name + "/" + v, Version: v})
	}
	return g
}

// TestPickResourceClaimVersion checks which resource.k8s.io version is
// read through for every shape of discovery answer.
func TestPickResourceClaimVersion(t *testing.T) {
	cases := []struct {
		name   string
		groups *metav1.APIGroupList
		want   string
		wantOK bool
	}{
		{name: "the preferred version wins", groups: &metav1.APIGroupList{Groups: []metav1.APIGroup{
			group("apps", "v1", "v1"), group("resource.k8s.io", "v1", "v1beta2", "v1")}}, want: "v1", wantOK: true},
		{name: "a beta cluster prefers its beta", groups: &metav1.APIGroupList{Groups: []metav1.APIGroup{
			group("resource.k8s.io", "v1beta1", "v1beta1")}}, want: "v1beta1", wantOK: true},
		{name: "no preferred version takes the first served", groups: &metav1.APIGroupList{Groups: []metav1.APIGroup{
			group("resource.k8s.io", "", "v1beta2", "v1beta1")}}, want: "v1beta2", wantOK: true},
		{name: "a group without versions serves nothing", groups: &metav1.APIGroupList{Groups: []metav1.APIGroup{
			group("resource.k8s.io", "")}}},
		{name: "a cluster without the group", groups: &metav1.APIGroupList{Groups: []metav1.APIGroup{group("apps", "v1", "v1")}}},
		{name: "no answer at all"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := kubernetes.PickResourceClaimVersion(c.groups)
			if got != c.want || ok != c.wantOK {
				t.Fatalf("PickResourceClaimVersion = %q, %v, want %q, %v", got, ok, c.want, c.wantOK)
			}
		})
	}
}

// TestKubeDefaults checks what the client fills in and that the caller's
// configuration is left alone.
func TestKubeDefaults(t *testing.T) {
	cases := []struct {
		name          string
		in            rest.Config
		wantUserAgent func(ua string) bool
		wantTimeout   time.Duration
	}{
		{name: "an empty user agent names fiberd and its home", in: rest.Config{Host: "https://10.0.0.1"},
			wantUserAgent: func(ua string) bool { return strings.HasPrefix(ua, "fiberd/kubernetes ") }, wantTimeout: 30 * time.Second},
		{name: "a given user agent and timeout are kept", in: rest.Config{Host: "https://10.0.0.1", UserAgent: "mine", Timeout: time.Minute},
			wantUserAgent: func(ua string) bool { return ua == "mine" }, wantTimeout: time.Minute},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := c.in
			got := kubernetes.KubeDefaults(&in)
			if !c.wantUserAgent(got.UserAgent) {
				t.Fatalf("UserAgent = %q", got.UserAgent)
			}
			if got.Timeout != c.wantTimeout {
				t.Fatalf("Timeout = %s, want %s", got.Timeout, c.wantTimeout)
			}
			if got.Host != c.in.Host {
				t.Fatalf("Host = %q, want %q", got.Host, c.in.Host)
			}
			if in.UserAgent != c.in.UserAgent || in.Timeout != c.in.Timeout {
				t.Fatal("the caller's configuration was changed")
			}
		})
	}
}
