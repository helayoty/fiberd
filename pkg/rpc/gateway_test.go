package rpc_test

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"

	grantv1 "github.com/helayoty/fiberd/api/grant/v1"
	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/rpc"
)

// errBody is a request body whose read fails part way.
type errBody struct{}

func (errBody) Read([]byte) (int, error) { return 0, errors.New("connection reset") }

// The JSON gateway is the gRPC service over HTTP. One checkpoint-tier
// home and one warm-tier home serve the steps in order. Successes are the
// response message as protojson. Failures are a google.rpc.Status whose
// code picks the HTTP status, and a SHED miss also sets Retry-After.
func TestGateway(t *testing.T) {
	ckpt := newHarness(t, core.TierCheckpoint)
	warm := newHarness(t, core.TierWarm)
	gws := map[*harness]http.Handler{}
	for _, h := range []*harness{ckpt, warm} {
		gws[h] = (&rpc.Gateway{Server: h.server, Health: rpc.HealthFunc(func() uint64 { return 7 }, h.health, core.TierCheckpoint, nil)}).Handler()
	}
	g1 := jsonGrant(t, core.Grant{UID: "g1", Audience: "node-a", FiberMax: 2})
	full := jsonGrant(t, core.Grant{UID: "g2", Audience: "node-a", FiberMax: 1})
	high := jsonGrant(t, core.Grant{UID: "g3", Audience: "node-a", MinTier: core.TierCheckpoint})
	cloneBody := func(grantJWT, extra string) string {
		b, _ := json.Marshal(grantJWT)
		return `{"grantJwt":` + string(b) + extra + `}`
	}
	var fiberID string
	fiber := func(extra string) func() string {
		return func() string { return `{"fiberId":"` + fiberID + `"` + extra + `}` }
	}
	fixed := func(s string) func() string { return func() string { return s } }

	steps := []struct {
		name       string
		home       *harness // nil is the checkpoint home
		before     func()
		method     string
		path       string
		body       func() string
		rawBody    io.Reader // overrides body
		wantStatus int
		wantKind   string // CloneResponse kind on success, "" for CREATE
		wantCode   codes.Code
		wantMiss   *grantv1.MissCode
		wantRetry  string
		wantMsg    string // substring of the status message
		check      func(t *testing.T, body []byte)
	}{
		{name: "a clone creates a fiber", method: "POST", path: "/v1/clone", body: fixed(cloneBody(g1, `,"session":"S"`)),
			wantStatus: http.StatusOK},
		{name: "a clone of the same session attaches", method: "POST", path: "/v1/clone", body: fixed(cloneBody(g1, `,"session":"S"`)),
			wantStatus: http.StatusOK, wantKind: "ATTACH"},
		{name: "the fiber parks", method: "POST", path: "/v1/park", body: fiber(`,"sync":true`), wantStatus: http.StatusOK},
		{name: "the parked session resumes within a deadline", method: "POST", path: "/v1/clone",
			body: func() string {
				return cloneBody(g1, `,"session":"S","deadline":"`+time.Now().Add(time.Minute).UTC().Format(time.RFC3339)+`"`)
			},
			wantStatus: http.StatusOK, wantKind: "RESUME"},
		{name: "the resumed fiber releases", method: "POST", path: "/v1/release", body: fiber(`,"discard":true`), wantStatus: http.StatusOK},
		{name: "releasing it again is 404", method: "POST", path: "/v1/release", body: fiber(""),
			wantStatus: http.StatusNotFound, wantCode: codes.NotFound},
		{name: "parking an unknown fiber is 404", method: "POST", path: "/v1/park", body: fixed(`{"fiberId":"g1/9/9"}`),
			wantStatus: http.StatusNotFound, wantCode: codes.NotFound},
		{name: "a field the protocol does not define is 400", method: "POST", path: "/v1/clone", body: fixed(cloneBody(g1, `,"image":"evil"`)),
			wantStatus: http.StatusBadRequest, wantCode: codes.InvalidArgument, wantMsg: "admission"},
		{name: "a body that is not JSON is 400", method: "POST", path: "/v1/park", body: fixed(`fiberId=x`),
			wantStatus: http.StatusBadRequest, wantCode: codes.InvalidArgument, wantMsg: "admission"},
		{name: "a body that fails to read is 400", method: "POST", path: "/v1/release", rawBody: errBody{},
			wantStatus: http.StatusBadRequest, wantCode: codes.InvalidArgument, wantMsg: "connection reset"},
		{name: "a deadline already passed is 400", method: "POST", path: "/v1/clone",
			body:       fixed(cloneBody(g1, `,"deadline":"2000-01-01T00:00:00Z"`)),
			wantStatus: http.StatusBadRequest, wantCode: codes.InvalidArgument, wantMsg: "deadline"},
		{name: "a grant that does not verify is 401", method: "POST", path: "/v1/clone", body: fixed(cloneBody("{}", "")),
			wantStatus: http.StatusUnauthorized, wantCode: codes.Unauthenticated},
		{name: "a grant above the home's tier is 412", home: warm, method: "POST", path: "/v1/clone", body: fixed(cloneBody(high, "")),
			wantStatus: http.StatusPreconditionFailed, wantCode: codes.FailedPrecondition},
		{name: "the only fiber of a grant is taken", method: "POST", path: "/v1/clone", body: fixed(cloneBody(full, "")),
			wantStatus: http.StatusOK},
		{name: "a full grant with the lane healthy is 503 with a deferred miss", method: "POST", path: "/v1/clone",
			body: fixed(cloneBody(full, "")), wantStatus: http.StatusServiceUnavailable, wantCode: codes.Unavailable,
			wantMiss: ptrMiss(grantv1.MissCode_DEFERRED_FALLBACK)},
		{name: "a full grant with the lane dead is 429 with Retry-After", method: "POST", path: "/v1/clone",
			before: func() { ckpt.health.MarkSync(time.Now().Add(-time.Minute)) },
			body:   fixed(cloneBody(full, "")), wantStatus: http.StatusTooManyRequests, wantCode: codes.ResourceExhausted,
			wantMiss: ptrMiss(grantv1.MissCode_SHED), wantRetry: "3"},
		{name: "status lists the admitted grants", method: "GET", path: "/v1/status", wantStatus: http.StatusOK,
			check: func(t *testing.T, body []byte) {
				var sts []map[string]any
				if err := json.Unmarshal(body, &sts); err != nil {
					t.Fatal(err)
				}
				uids := map[any]bool{}
				for _, st := range sts {
					uids[st["grantUid"]] = true
				}
				if !uids["g1"] || !uids["g2"] || len(sts) != 2 {
					t.Fatalf("status = %s, want g1 and g2", body)
				}
			}},
		{name: "healthz reports epoch, tier and the dead lane", method: "GET", path: "/healthz", wantStatus: http.StatusOK,
			check: func(t *testing.T, body []byte) {
				var m map[string]any
				if err := json.Unmarshal(body, &m); err != nil {
					t.Fatal(err)
				}
				if m["epoch"] != float64(7) || m["tier"] != core.TierCheckpoint.String() || m["grantLaneHealthy"] != false {
					t.Fatalf("healthz = %s", body)
				}
			}},
		{name: "a GET of an RPC is 405", method: "GET", path: "/v1/clone", wantStatus: http.StatusMethodNotAllowed},
	}
	for _, st := range steps {
		t.Run(st.name, func(t *testing.T) {
			if st.before != nil {
				st.before()
			}
			h := st.home
			if h == nil {
				h = ckpt
			}
			body := st.rawBody
			if body == nil && st.body != nil {
				body = strings.NewReader(st.body())
			}
			rec := httptest.NewRecorder()
			gws[h].ServeHTTP(rec, httptest.NewRequest(st.method, st.path, body))
			if rec.Code != st.wantStatus {
				t.Fatalf("status = %d, want %d (%s)", rec.Code, st.wantStatus, rec.Body.String())
			}
			if got := rec.Header().Get("Retry-After"); got != st.wantRetry {
				t.Fatalf("Retry-After = %q, want %q", got, st.wantRetry)
			}
			if rec.Code == http.StatusMethodNotAllowed {
				return
			}
			if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
				t.Fatalf("Content-Type = %q, want application/json", ct)
			}
			switch {
			case st.check != nil:
				st.check(t, rec.Body.Bytes())
			case rec.Code == http.StatusOK && st.path == "/v1/clone":
				var r grantv1.CloneResponse
				if err := protojson.Unmarshal(rec.Body.Bytes(), &r); err != nil {
					t.Fatal(err)
				}
				if r.GetFiberId() == "" || r.GetEndpoint() == "" || r.GetKind().String() != kindName(st.wantKind) {
					t.Fatalf("clone = %v, want a fiber of kind %s", &r, kindName(st.wantKind))
				}
				fiberID = r.GetFiberId()
			case rec.Code == http.StatusOK:
				if strings.TrimSpace(rec.Body.String()) != "{}" {
					t.Fatalf("body = %q, want {}", rec.Body.String())
				}
			default:
				checkStatusBody(t, rec.Body.Bytes(), st.wantCode, st.wantMiss, st.wantMsg)
			}
		})
	}
}

func ptrMiss(c grantv1.MissCode) *grantv1.MissCode { return &c }

func kindName(k string) string {
	if k == "" {
		return grantv1.CloneKind_CREATE.String()
	}
	return k
}

// checkStatusBody decodes a google.rpc.Status JSON body and checks its
// code, its message and the Miss detail when one is wanted.
func checkStatusBody(t *testing.T, body []byte, code codes.Code, miss *grantv1.MissCode, msg string) {
	t.Helper()
	pb := status.New(codes.OK, "").Proto() // an empty google.rpc.Status to decode into
	if err := protojson.Unmarshal(body, pb); err != nil {
		t.Fatalf("body %q is not a google.rpc.Status: %v", body, err)
	}
	st := status.FromProto(pb)
	if st.Code() != code || !strings.Contains(st.Message(), msg) {
		t.Fatalf("status = %v, want code %v with a message containing %q", st, code, msg)
	}
	got, ok := rpc.MissFromError(st.Err())
	switch {
	case miss == nil && ok:
		t.Fatalf("miss = %v, want none", got)
	case miss != nil && (!ok || got.GetCode() != *miss || got.GetIssuer() != "https://issuer.test"):
		t.Fatalf("miss = %v, want a %v miss from the issuer", got, *miss)
	}
}

// TestGatewayHealthz pins the /healthz body and status. Without a Health
// func it is an empty object. A poisoned audit spool is a 503 with the
// word "poisoned", never the fsync error, which names the spool's path.
// A stale lane alone stays 200, so the two read apart.
func TestGatewayHealthz(t *testing.T) {
	fresh := core.NewSourceHealth(10*time.Second, time.Now())
	stale := core.NewSourceHealth(10*time.Second, time.Now().Add(-time.Minute))
	ok := func() error { return nil }
	poisoned := func() error { return errors.New("sync /var/lib/fiberd/private/audit.jsonl: input/output error") }
	cases := []struct {
		name   string
		gw     *rpc.Gateway
		status int
		want   map[string]any
	}{
		{name: "no health func is an empty object", gw: &rpc.Gateway{}, status: http.StatusOK, want: map[string]any{}},
		{name: "no lane and no spool omit their keys", gw: &rpc.Gateway{Health: rpc.HealthFunc(func() uint64 { return 3 }, nil, core.TierWarm, nil)},
			status: http.StatusOK, want: map[string]any{"epoch": float64(3), "tier": core.TierWarm.String()}},
		{name: "a fresh lane and a healthy spool are 200", gw: &rpc.Gateway{Health: rpc.HealthFunc(func() uint64 { return 4 }, fresh, core.TierBasic, ok)},
			status: http.StatusOK, want: map[string]any{"epoch": float64(4), "tier": core.TierBasic.String(), "grantLaneHealthy": true, "audit": "ok"}},
		{name: "a stale lane alone is still 200", gw: &rpc.Gateway{Health: rpc.HealthFunc(func() uint64 { return 5 }, stale, core.TierBasic, ok)},
			status: http.StatusOK, want: map[string]any{"epoch": float64(5), "tier": core.TierBasic.String(), "grantLaneHealthy": false, "audit": "ok"}},
		{name: "a poisoned spool is 503 without the fsync error", gw: &rpc.Gateway{Health: rpc.HealthFunc(func() uint64 { return 6 }, fresh, core.TierBasic, poisoned)},
			status: http.StatusServiceUnavailable,
			want:   map[string]any{"epoch": float64(6), "tier": core.TierBasic.String(), "grantLaneHealthy": true, "audit": "poisoned"}},
		{name: "a stale lane and a poisoned spool are both reported", gw: &rpc.Gateway{Health: rpc.HealthFunc(func() uint64 { return 7 }, stale, core.TierBasic, poisoned)},
			status: http.StatusServiceUnavailable,
			want:   map[string]any{"epoch": float64(7), "tier": core.TierBasic.String(), "grantLaneHealthy": false, "audit": "poisoned"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			tc.gw.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/healthz", nil))
			var got map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatalf("healthz %q: %v", rec.Body.String(), err)
			}
			if rec.Code != tc.status || len(got) != len(tc.want) || rec.Header().Get("Content-Type") != "application/json" ||
				strings.Contains(rec.Body.String(), "/var/lib") {
				t.Fatalf("healthz = %d %v, want %d %v", rec.Code, got, tc.status, tc.want)
			}
			for k, v := range tc.want {
				if got[k] != v {
					t.Fatalf("healthz[%s] = %v, want %v", k, got[k], v)
				}
			}
		})
	}
}
