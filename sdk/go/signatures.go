package matura

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// SignatureTolerance is how far a webhook signature's timestamp may be from now.
const SignatureTolerance = 5 * time.Minute

// ErrBadSignature: the webhook is not from Matura, was changed, or is too old (answer 401 and do not apply it).
var ErrBadSignature = errors.New("bad webhook signature")

func mac(secret []byte, t string, body []byte) []byte {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(t + "."))
	m.Write(body)
	return m.Sum(nil)
}

// Sign returns the Matura-Signature header for body, signed at the given time:
// t=<unix>,v1=<hex HMAC-SHA256 of "t.body">.
func Sign(secret []byte, at time.Time, body []byte) string {
	t := strconv.FormatInt(at.Unix(), 10)
	return "t=" + t + ",v1=" + hex.EncodeToString(mac(secret, t, body))
}

// VerifySignature checks a Matura-Signature header (contract §10.2) at now within SignatureTolerance. During a
// secret rotation Matura sends several v1 values; any one matching is enough. Errors wrap ErrBadSignature.
func VerifySignature(secret []byte, header string, body []byte, now time.Time) error {
	return verifySignature(secret, header, body, now, SignatureTolerance)
}

func verifySignature(secret []byte, header string, body []byte, now time.Time, tolerance time.Duration) error {
	if header == "" {
		return fmt.Errorf("%w: missing Matura-Signature", ErrBadSignature)
	}
	var t string
	var sigs []string
	for _, part := range strings.Split(header, ",") {
		k, v, _ := strings.Cut(strings.TrimSpace(part), "=")
		switch k {
		case "t":
			t = v
		case "v1":
			sigs = append(sigs, v)
		}
	}
	ts, err := strconv.ParseInt(t, 10, 64)
	if err != nil || ts < 0 || len(sigs) == 0 {
		return fmt.Errorf("%w: malformed Matura-Signature", ErrBadSignature)
	}
	if d := now.Sub(time.Unix(ts, 0)); d > tolerance || d < -tolerance {
		return fmt.Errorf("%w: signature timestamp is too old or in the future", ErrBadSignature)
	}
	want := mac(secret, t, body)
	ok := false
	for _, s := range sigs {
		// compare every candidate, in constant time
		if got, err := hex.DecodeString(s); err == nil && hmac.Equal(got, want) {
			ok = true
		}
	}
	if !ok {
		return fmt.Errorf("%w: signature does not match", ErrBadSignature)
	}
	return nil
}
