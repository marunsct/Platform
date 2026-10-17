package matura

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"math/big"
	"strings"
)

// JWKS is a JSON Web Key Set, as the realm publishes it.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWK is one public signing key (RSA or EC).
type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid,omitempty"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

var curves = map[string]string{"ES256": "P-256", "ES384": "P-384"}

func (k *JWK) fits(alg string) bool {
	if k.Use != "" && k.Use != "sig" {
		return false
	}
	if k.Alg != "" && k.Alg != alg {
		return false
	}
	if strings.HasPrefix(alg, "ES") {
		return k.Kty == "EC" && k.Crv == curves[alg]
	}
	return k.Kty == "RSA"
}

func b64int(s string) (*big.Int, error) {
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
	if err != nil || len(b) == 0 {
		return nil, errors.New("bad key parameter")
	}
	return new(big.Int).SetBytes(b), nil
}

// PublicKey decodes the key: *rsa.PublicKey or *ecdsa.PublicKey.
func (k *JWK) PublicKey() (crypto.PublicKey, error) {
	switch k.Kty {
	case "RSA":
		n, err := b64int(k.N)
		if err != nil {
			return nil, err
		}
		e, err := b64int(k.E)
		if err != nil || !e.IsInt64() || e.Int64() < 3 || e.Int64() > 1<<31-1 {
			return nil, errors.New("bad RSA exponent")
		}
		if n.BitLen() < 2048 {
			return nil, errors.New("RSA key shorter than 2048 bits")
		}
		return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
	case "EC":
		var curve elliptic.Curve
		var dh ecdh.Curve
		switch k.Crv {
		case "P-256":
			curve, dh = elliptic.P256(), ecdh.P256()
		case "P-384":
			curve, dh = elliptic.P384(), ecdh.P384()
		default:
			return nil, errors.New("unsupported curve " + k.Crv)
		}
		x, err := b64int(k.X)
		if err != nil {
			return nil, err
		}
		y, err := b64int(k.Y)
		if err != nil {
			return nil, err
		}
		size := (curve.Params().BitSize + 7) / 8
		if len(x.Bytes()) > size || len(y.Bytes()) > size {
			return nil, errors.New("bad EC point")
		}
		point := make([]byte, 1+2*size)
		point[0] = 4
		x.FillBytes(point[1 : 1+size])
		y.FillBytes(point[1+size:])
		if _, err := dh.NewPublicKey(point); err != nil { // checks the point is on the curve
			return nil, errors.New("bad EC point")
		}
		return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
	}
	return nil, errors.New("unsupported key type " + k.Kty)
}
