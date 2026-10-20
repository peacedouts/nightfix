package controlplane

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/peacedouts/nightfix/internal/agentapi"
)

// AgentHandler serves the agent gateway. It must be served with the TLS
// config from CA.ServerTLS so client certificates are verified.
func (s *Server) AgentHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /agent/v1/enroll", func(w http.ResponseWriter, r *http.Request) {
		var req agentapi.EnrollRequest
		if !decodeBody(w, r, &req) {
			return
		}
		resp, err := s.Enroll(r.Context(), req)
		s.reply(w, resp, err)
	})
	mux.HandleFunc("POST /agent/v1/enroll/challenge", func(w http.ResponseWriter, r *http.Request) {
		var req agentapi.ChallengeRequest
		if !decodeBody(w, r, &req) {
			return
		}
		resp, err := s.Challenge(r.Context(), req)
		s.reply(w, resp, err)
	})
	authed := func(pattern string, fn func(w http.ResponseWriter, r *http.Request, a agentIdentity)) {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			a, err := s.authenticateAgent(r)
			if err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}
			fn(w, r, a)
		})
	}
	authed("POST /agent/v1/renew", func(w http.ResponseWriter, r *http.Request, a agentIdentity) {
		var req agentapi.RenewRequest
		if decodeBody(w, r, &req) {
			resp, err := s.Renew(r.Context(), a, req)
			s.reply(w, resp, err)
		}
	})
	authed("POST /agent/v1/hello", func(w http.ResponseWriter, r *http.Request, a agentIdentity) {
		var req agentapi.Hello
		if decodeBody(w, r, &req) {
			resp, err := s.Hello(r.Context(), a, req)
			s.reply(w, resp, err)
		}
	})
	authed("POST /agent/v1/poll", func(w http.ResponseWriter, r *http.Request, a agentIdentity) {
		var req agentapi.PollRequest
		if decodeBody(w, r, &req) {
			resp, err := s.Poll(r.Context(), a, req)
			s.reply(w, resp, err)
		}
	})
	authed("POST /agent/v1/heartbeat", func(w http.ResponseWriter, r *http.Request, a agentIdentity) {
		var req agentapi.Heartbeat
		if decodeBody(w, r, &req) {
			s.reply(w, map[string]bool{"ok": true}, s.Heartbeat(r.Context(), a, req))
		}
	})
	authed("POST /agent/v1/attempts/{id}/ack", func(w http.ResponseWriter, r *http.Request, a agentIdentity) {
		var req agentapi.Ack
		if decodeBody(w, r, &req) {
			s.reply(w, map[string]bool{"ok": true}, s.Ack(r.Context(), a, r.PathValue("id"), req))
		}
	})
	authed("POST /agent/v1/attempts/{id}/output", func(w http.ResponseWriter, r *http.Request, a agentIdentity) {
		var req agentapi.OutputBatch
		if decodeBody(w, r, &req) {
			s.reply(w, map[string]bool{"ok": true}, s.Output(r.Context(), a, r.PathValue("id"), req))
		}
	})
	authed("POST /agent/v1/attempts/{id}/result", func(w http.ResponseWriter, r *http.Request, a agentIdentity) {
		var req agentapi.Result
		if decodeBody(w, r, &req) {
			s.reply(w, map[string]bool{"ok": true}, s.Result(r.Context(), a, r.PathValue("id"), req))
		}
	})
	return mux
}

// authenticateAgent maps a verified client certificate to an agent. The TLS
// layer already checked the chain against our CA; here the serial must belong
// to a non-revoked agent and the URI SAN must match it.
func (s *Server) authenticateAgent(r *http.Request) (agentIdentity, error) {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
		return agentIdentity{}, errors.New("client certificate required")
	}
	cert := r.TLS.VerifiedChains[0][0]
	var a agentIdentity
	if err := s.DB.QueryRowContext(r.Context(), `SELECT org_id, agent_id FROM nfx_route_agent($1)`, SerialHex(cert.SerialNumber)).
		Scan(&a.OrgID, &a.AgentID); err != nil {
		return a, errors.New("unknown or revoked agent certificate")
	}
	want := AgentURI(a.OrgID, a.AgentID)
	for _, u := range cert.URIs {
		if u.String() == want {
			return a, nil
		}
	}
	return a, errors.New("certificate identity does not match the agent")
}

func decodeBody(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(io.LimitReader(r.Body, 4<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		http.Error(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return false
	}
	return true
}

// reply writes v as JSON, or maps err to a status code.
func (s *Server) reply(w http.ResponseWriter, v any, err error) {
	if err != nil {
		var he httpError
		if errors.As(err, &he) {
			writeJSON(w, he.code, map[string]string{"error": he.msg})
			return
		}
		if errors.Is(err, errNotFound) || isNoRows(err) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
			return
		}
		s.Log.Error("request failed", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}

var _ = fmt.Sprintf
var _ = strings.TrimSpace
