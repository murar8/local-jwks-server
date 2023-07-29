package token_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/stretchr/testify/assert"

	"github.com/murar8/local-jwks-server/internal/token"
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
			key, err := token.GenerateRawKey(alg)
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
			key, err := token.GenerateRawKey(tt.alg)
			assert.NoError(t, err)
			assert.IsType(t, &ecdsa.PrivateKey{}, key)
			assert.Equal(t, tt.curve, key.(*ecdsa.PrivateKey).Curve)
		})
	}

	t.Run("returns an error for unsupported algorithms", func(t *testing.T) {
		key, err := token.GenerateRawKey(jwa.HS256)
		assert.Error(t, err)
		assert.Nil(t, key)
	})
}
