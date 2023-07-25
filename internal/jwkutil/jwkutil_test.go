package jwkutil_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/assert"

	"github.com/murar8/local-jwks-server/internal/config"
	"github.com/murar8/local-jwks-server/internal/jwkutil"
)

func TestGenerateRawKey(t *testing.T) {
	rsas := []jwa.SignatureAlgorithm{
		jwa.RS256,
		jwa.RS384,
		jwa.RS512,
		jwa.PS256,
		jwa.PS384,
		jwa.PS512,
	}

	for _, alg := range rsas {
		t.Run(fmt.Sprintf("generates a %s key", alg), func(t *testing.T) {
			key, err := jwkutil.GenerateRawKey(alg)
			assert.NoError(t, err)
			assert.IsType(t, &rsa.PrivateKey{}, key)
		})
	}

	ecdsas := []struct {
		alg   jwa.SignatureAlgorithm
		curve elliptic.Curve
	}{
		{jwa.ES256, elliptic.P256()},
		{jwa.ES384, elliptic.P384()},
		{jwa.ES512, elliptic.P521()},
	}

	for _, tt := range ecdsas {
		t.Run(fmt.Sprintf("generates a %s key", tt.alg), func(t *testing.T) {
			key, err := jwkutil.GenerateRawKey(tt.alg)
			assert.NoError(t, err)
			assert.IsType(t, &ecdsa.PrivateKey{}, key)
			assert.Equal(t, tt.curve, key.(*ecdsa.PrivateKey).Curve)
		})
	}

	t.Run("returns an error for unsupported algorithms", func(t *testing.T) {
		key, err := jwkutil.GenerateRawKey(jwa.HS256)
		assert.Error(t, err)
		assert.Nil(t, key)
	})
}

func TestGenerateKey(t *testing.T) {
	t.Run("generates a JWK key using the provided configuration", func(t *testing.T) {
		key, err := jwkutil.GenerateKey(&config.JWK{
			Alg:    jwa.RS256,
			KeyOps: jwk.KeyOperationList{"sign", "verify"},
		})

		assert.NoError(t, err)
		assert.NotEmpty(t, key.KeyID())
		assert.Equal(t, string(jwk.ForSignature), key.KeyUsage())
		assert.Equal(t, jwa.RS256, key.Algorithm())
		assert.Equal(t, jwk.KeyOperationList{"sign", "verify"}, key.KeyOps())
	})
}

func TestGenerateKeySet(t *testing.T) {
	t.Run("generates a JWK set using the provided configuration", func(t *testing.T) {
		set, err := jwkutil.GenerateKeySet(&config.JWK{
			Alg:    jwa.RS256,
			KeyOps: jwk.KeyOperationList{"sign", "verify"},
		}, 4)

		assert.NoError(t, err)
		assert.Equal(t, set.Len(), 4)
	})
}
