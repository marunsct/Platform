package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net/http"

	"github.com/google/uuid"

	"github.com/marunsct/Platform/internal/store"
)

// recorder keeps a copy of the response so it can be stored for replays.
type recorder struct {
	http.ResponseWriter
	status int
	body   bytes.Buffer
}

func (r *recorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *recorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	r.body.Write(b)
	return r.ResponseWriter.Write(b)
}

// idempotent makes a POST with an Idempotency-Key safe to retry (technical specification §2): the first request
// runs, its response is stored for 24 hours, and a retry with the same key and body gets the same response
// (`Idempotency-Replayed: true`) without running again. A server error releases the key so the retry runs.
func (s *Server) idempotent(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("Idempotency-Key")
		if r.Method != http.MethodPost || key == "" {
			next.ServeHTTP(w, r)
			return
		}
		if len(key) > 255 {
			problem(w, http.StatusBadRequest, "bad-request", "Idempotency-Key is longer than 255 characters")
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
		if err != nil {
			problem(w, http.StatusRequestEntityTooLarge, "too-large", "request body over 1 MB")
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		h := sha256.New()
		h.Write([]byte(r.Method + " " + r.URL.Path + "\n"))
		h.Write(body)
		p := principalFrom(r.Context())
		principal := p.UserID
		if principal == uuid.Nil {
			principal = p.AppID
		}

		stored, err := s.store.ClaimIdempotencyKey(r.Context(), principal, key, h.Sum(nil))
		switch {
		case errors.Is(err, store.ErrIdempotencyInFlight):
			problem(w, http.StatusConflict, "idempotency-in-flight", err.Error())
			return
		case err != nil:
			s.fail(w, r, err)
			return
		case stored != nil:
			if stored.ContentType != "" {
				w.Header().Set("Content-Type", stored.ContentType)
			}
			w.Header().Set("Idempotency-Replayed", "true")
			w.WriteHeader(stored.Status)
			_, _ = w.Write(stored.Body)
			return
		}

		rec := &recorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)
		ctx := context.WithoutCancel(r.Context())
		if rec.status >= 500 || rec.status == 0 {
			_ = s.store.ReleaseIdempotencyKey(ctx, principal, key)
			return
		}
		if err := s.store.CompleteIdempotencyKey(ctx, principal, key, store.StoredResponse{
			Status: rec.status, Body: rec.body.Bytes(), ContentType: rec.Header().Get("Content-Type"),
		}); err != nil {
			s.log.ErrorContext(ctx, "storing idempotent response", "err", err)
		}
	})
}
