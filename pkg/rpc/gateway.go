package rpc

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	grantv1 "github.com/helayoty/fiberd/api/grant/v1"
	"github.com/helayoty/fiberd/pkg/core"
)

// Gateway is the thin JSON-over-HTTP face of the same service, mounted
// only when fiberd is started with -http. Requests are protobuf JSON
// (protojson) of the same messages; unknown fields are rejected exactly as
// on gRPC. Errors are the google.rpc.Status JSON with the Miss detail
// embedded, and the HTTP code follows the gRPC code.
type Gateway struct {
	Server *Server
	// Health is served at GET /healthz for readiness polling, with the
	// status WriteHealth picks.
	Health func() map[string]any
}

const maxBody = 64 << 10

func (g *Gateway) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/clone", func(w http.ResponseWriter, r *http.Request) {
		var req grantv1.CloneRequest
		if !g.decode(w, r, &req) {
			return
		}
		resp, err := g.Server.Clone(r.Context(), &req)
		g.reply(w, resp, err)
	})
	mux.HandleFunc("POST /v1/park", func(w http.ResponseWriter, r *http.Request) {
		var req grantv1.ParkRequest
		if !g.decode(w, r, &req) {
			return
		}
		resp, err := g.Server.Park(r.Context(), &req)
		g.reply(w, resp, err)
	})
	mux.HandleFunc("POST /v1/release", func(w http.ResponseWriter, r *http.Request) {
		var req grantv1.ReleaseRequest
		if !g.decode(w, r, &req) {
			return
		}
		resp, err := g.Server.Release(r.Context(), &req)
		g.reply(w, resp, err)
	})
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, r *http.Request) {
		out := make([]json.RawMessage, 0)
		for _, st := range g.Server.visible(r.Context(), g.Server.Agent.Ledger.Statuses()) {
			b, _ := protojson.Marshal(StatusToProto(st))
			out = append(out, b)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		if g.Health == nil {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, "{}\n")
			return
		}
		WriteHealth(w, g.Health())
	})
	return httpCaller(mux)
}

func (g *Gateway) decode(w http.ResponseWriter, r *http.Request, m proto.Message) bool {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody))
	if err != nil {
		g.reply(w, nil, status.Error(codes.InvalidArgument, err.Error()))
		return false
	}
	// protojson rejects unknown fields by default: admission completeness
	// holds on this face too.
	if err := protojson.Unmarshal(body, m); err != nil {
		g.reply(w, nil, status.Error(codes.InvalidArgument, "admission: "+err.Error()))
		return false
	}
	return true
}

func (g *Gateway) reply(w http.ResponseWriter, resp proto.Message, err error) {
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		st, _ := status.FromError(err)
		if miss, ok := MissFromError(err); ok && miss.GetCode() == grantv1.MissCode_SHED {
			w.Header().Set("Retry-After", strconv.Itoa(int(miss.GetRetryAfterS())))
		}
		w.WriteHeader(httpCode(st.Code()))
		b, _ := protojson.Marshal(st.Proto())
		_, _ = w.Write(append(b, '\n'))
		return
	}
	b, err := protojson.Marshal(resp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_, _ = w.Write(append(b, '\n'))
}

func httpCode(c codes.Code) int {
	switch c {
	case codes.OK:
		return http.StatusOK
	case codes.InvalidArgument:
		return http.StatusBadRequest
	case codes.Unauthenticated:
		return http.StatusUnauthorized
	case codes.NotFound:
		return http.StatusNotFound
	case codes.FailedPrecondition:
		return http.StatusPreconditionFailed
	case codes.ResourceExhausted:
		return http.StatusTooManyRequests
	case codes.Unavailable:
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}

// HealthFunc builds the standard /healthz body. It holds the epoch, the
// advertised tier, grant-lane liveness and the audit spool's state. An
// idle lane is not down. Only a stale one is. audit is "ok" or
// "poisoned". The fsync error is logged when it happens and never put in
// the body, which the gateway serves without authentication, since it
// names the spool's path. A nil health or audit omits its key.
func HealthFunc(epoch func() uint64, health *core.SourceHealth, tier core.Tier, audit func() error) func() map[string]any {
	return func() map[string]any {
		m := map[string]any{"epoch": epoch(), "tier": tier.String()}
		if health != nil {
			m["grantLaneHealthy"] = health.Healthy(time.Now())
		}
		if audit != nil {
			m["audit"] = "ok"
			if audit() != nil {
				m["audit"] = "poisoned"
			}
		}
		return m
	}
}

// WriteHealth writes a /healthz body. The status is 503 when the audit
// spool is poisoned, because every Sync operation fails until the agent
// restarts. A probe that sees it restarts the home or drains it. A stale
// grant lane stays 200, since the agent fences it and recovers on its own.
func WriteHealth(w http.ResponseWriter, body map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	if a, ok := body["audit"]; ok && a != "ok" {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	_ = json.NewEncoder(w).Encode(body)
}
