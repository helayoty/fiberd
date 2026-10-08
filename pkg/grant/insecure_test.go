package grant_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/helayoty/fiberd/pkg/grant"
)

// The insecure JSON verifier skips the signature but not the UID check,
// because the UID still becomes a path segment and part of the zygote line.
func TestInsecureJSONVerifier(t *testing.T) {
	cases := []struct {
		name    string
		token   string
		want    error  // errors.Is target, nil requires success
		wantMsg string // substring of the error, when there is no sentinel
	}{
		{name: "a plain uid verifies", token: `{"grantUid":"g-1"}`},
		{name: "a UUID uid verifies", token: `{"grantUid":"0b8e6c1e-4f5a-4d2b-9c3e-1a2b3c4d5e6f"}`},
		{name: "a substrate uid verifies", token: `{"grantUid":"at-0123abcd"}`},
		{name: "an empty uid is refused", token: `{}`, want: grant.ErrEmptyGrant},
		{name: "a token that is not protobuf JSON is refused", token: `eyJhbGciOi.not.json`, wantMsg: "decode json grant"},
		{name: "an unknown field is refused", token: `{"grantUid":"g-1","admin":true}`, wantMsg: "decode json grant"},
		{name: "an uppercase uid is refused", token: `{"grantUid":"G-1"}`, want: grant.ErrBadUID},
		{name: "a uid with an underscore is refused", token: `{"grantUid":"g_1"}`, want: grant.ErrBadUID},
		{name: "a dot uid is refused", token: `{"grantUid":"."}`, want: grant.ErrBadUID},
		{name: "a dot-dot uid is refused", token: `{"grantUid":".."}`, want: grant.ErrBadUID},
		{name: "a trailing hyphen is refused", token: `{"grantUid":"g1-"}`, want: grant.ErrBadUID},
		{name: "a path-traversal uid is refused", token: `{"grantUid":"../../etc"}`, want: grant.ErrBadUID},
		{name: "a uid with a newline is refused", token: `{"grantUid":"g\nCLONE x"}`, want: grant.ErrBadUID},
		{name: "a 64-character uid is refused", token: `{"grantUid":"` + strings.Repeat("a", 64) + `"}`, want: grant.ErrBadUID},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g, err := grant.InsecureJSONVerifier{}.Verify(context.Background(), []byte(tc.token))
			if tc.wantMsg != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantMsg) {
					t.Fatalf("err = %v, want one containing %q", err, tc.wantMsg)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if tc.want == nil && g.UID == "" {
				t.Fatal("verified grant has no UID")
			}
		})
	}
}
