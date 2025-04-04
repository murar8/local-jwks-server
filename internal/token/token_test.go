package token_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/murar8/local-jwks-server/internal/config"
	"github.com/murar8/local-jwks-server/internal/token"
	"github.com/stretchr/testify/assert"
)

func TestFromRawKey(t *testing.T) {
	t.Parallel()

	t.Run("creates a new token service", func(t *testing.T) {
		t.Parallel()

		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		ts, err := token.FromRawKey(key, &config.JWK{Alg: "RS256"})

		assert.NoError(t, err)
		assert.NotNil(t, ts)
	})

	t.Run("returns an error if the key is invalid", func(t *testing.T) {
		t.Parallel()

		ts, err := token.FromRawKey("invalid", &config.JWK{Alg: "RS256"})

		assert.Nil(t, ts)
		assert.Error(t, err)
	})
}

func TestGetKey(t *testing.T) {
	t.Parallel()

	t.Run("returns a JWK key", func(t *testing.T) {
		t.Parallel()

		raw, _ := rsa.GenerateKey(rand.Reader, 2048)
		cfg := &config.JWK{Alg: jwa.RS256, KeyOps: []jwk.KeyOperation{"sign", "verify"}}
		ts, _ := token.FromRawKey(raw, cfg)
		key := ts.GetKey()

		assert.NotNil(t, key)
		assert.Equal(t, cfg.Alg, key.Algorithm())
		assert.Equal(t, cfg.KeyOps, key.KeyOps())
	})
}

func TestGetKeySet(t *testing.T) {
	t.Parallel()

	t.Run("returns a JWK key set", func(t *testing.T) {
		t.Parallel()

		raw, _ := rsa.GenerateKey(rand.Reader, 2048)
		cfg := &config.JWK{Alg: jwa.RS256, KeyOps: []jwk.KeyOperation{"sign", "verify"}}
		ts, _ := token.FromRawKey(raw, cfg)
		set, err := ts.GetKeySet()

		assert.NoError(t, err)
		assert.Equal(t, 1, set.Len())

		key, _ := set.Key(0)

		assert.NotNil(t, key.KeyID())
		assert.Equal(t, "sig", key.KeyUsage())
		assert.Equal(t, cfg.Alg, key.Algorithm())
		assert.Equal(t, cfg.KeyOps, key.KeyOps())

		km, _ := key.AsMap(context.Background())

		// Make sure the private key is not included in the key set.
		assert.Nil(t, km["d"])
		assert.Nil(t, km["p"])
		assert.Nil(t, km["q"])
		assert.Nil(t, km["dp"])
		assert.Nil(t, km["dq"])
		assert.Nil(t, km["qi"])
	})
}

func TestSignToken(t *testing.T) {
	t.Parallel()

	t.Run("returns a signed JWT token", func(t *testing.T) {
		t.Parallel()

		raw, _ := rsa.GenerateKey(rand.Reader, 2048)
		cfg := &config.JWK{Alg: jwa.RS256}
		ts, _ := token.FromRawKey(raw, cfg)
		payload := map[string]interface{}{"sub": "john-doe", "name": "John Doe"}
		token, err := ts.SignToken(payload, nil)
		decoded, _ := jwt.Parse(token, jwt.WithKey(cfg.Alg, raw))

		assert.NoError(t, err)
		assert.Equal(t, payload["sub"], decoded.Subject())
		assert.Equal(t, payload["name"], decoded.PrivateClaims()["name"])
	})

	t.Run("returns an error if the payload is invalid", func(t *testing.T) {
		t.Parallel()

		raw, _ := rsa.GenerateKey(rand.Reader, 2048)
		cfg := &config.JWK{Alg: jwa.RS256}
		ts, _ := token.FromRawKey(raw, cfg)
		payload := map[string]interface{}{"iat": "invalid"}
		token, err := ts.SignToken(payload, nil)

		assert.Nil(t, token)
		assert.Error(t, err)
	})
}
