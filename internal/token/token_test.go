package token_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"strings"
	"testing"

	"encoding/base64"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/murar8/local-jwks-server/internal/config"
	"github.com/murar8/local-jwks-server/internal/token"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFromRawKey(t *testing.T) {
	t.Parallel()

	t.Run("creates a new token service", func(t *testing.T) {
		t.Parallel()

		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		ts, err := token.FromRawKey(key, &config.JWK{Alg: "RS256"})

		require.NoError(t, err)
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

		require.NoError(t, err)
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
		token, err := ts.SignToken(payload)
		decoded, _ := jwt.Parse(token, jwt.WithKey(cfg.Alg, raw))

		require.NoError(t, err)
		assert.Equal(t, payload["sub"], decoded.Subject())
		assert.Equal(t, payload["name"], decoded.PrivateClaims()["name"])
	})

	t.Run("flattens audience when enabled", func(t *testing.T) {
		t.Parallel()

		raw, _ := rsa.GenerateKey(rand.Reader, 2048)
		cfg := &config.JWK{Alg: jwa.RS256, FlattenAudience: true}
		ts, _ := token.FromRawKey(raw, cfg)

		// Create a payload with a single audience value as an array
		payload := map[string]interface{}{
			"sub": "john-doe",
			"aud": []string{"single-audience"},
		}

		tokenBytes, err := ts.SignToken(payload)
		require.NoError(t, err)

		// Parse without validation to check the token
		token, err := jwt.Parse(tokenBytes, jwt.WithVerify(false))
		require.NoError(t, err)

		// Audience should be accessible as an array via the API
		aud := token.Audience()
		assert.Len(t, aud, 1)
		assert.Equal(t, "single-audience", aud[0])

		// Convert the JWT to a string so we can verify the serialized form
		tokenStr := string(tokenBytes)

		// Split the JWT by dots to get the payload section
		parts := strings.Split(tokenStr, ".")
		assert.Len(t, parts, 3, "JWT should have 3 parts")

		// Decode the payload (second part)
		payload64 := parts[1]
		payloadJSON, err := base64.RawURLEncoding.DecodeString(payload64)
		require.NoError(t, err)

		// Parse the payload to a map
		var payloadMap map[string]interface{}
		err = json.Unmarshal(payloadJSON, &payloadMap)
		require.NoError(t, err)

		// Check if "aud" exists and is a string, not an array
		audValue, ok := payloadMap["aud"]
		assert.True(t, ok, "audience should exist in the payload")
		_, isString := audValue.(string)
		assert.True(t, isString, "audience should be flattened to a string")
	})

	t.Run("returns an error if the payload is invalid", func(t *testing.T) {
		t.Parallel()

		raw, _ := rsa.GenerateKey(rand.Reader, 2048)
		cfg := &config.JWK{Alg: jwa.RS256}
		ts, _ := token.FromRawKey(raw, cfg)
		payload := map[string]interface{}{"iat": "invalid"}
		token, err := ts.SignToken(payload)

		assert.Nil(t, token)
		assert.Error(t, err)
	})
}
