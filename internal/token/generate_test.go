package token_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/murar8/local-jwks-server/internal/token"
	"github.com/stretchr/testify/assert"
)

func TestGenerateRawKey(t *testing.T) {
	t.Parallel()

	rsas := []jwa.SignatureAlgorithm{
		jwa.RS256,
		jwa.RS384,
		jwa.RS512,
		jwa.PS256,
		jwa.PS384,
		jwa.PS512,
	}

	for _, alg := range rsas {
		alg := alg

		t.Run(fmt.Sprintf("generates a %s key", alg), func(t *testing.T) {
			t.Parallel()

			key, err := token.GeneratePrivateKey(alg, 2048)
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
		curve := tt.curve
		alg := tt.alg

		t.Run(fmt.Sprintf("generates a %s key", alg), func(t *testing.T) {
			t.Parallel()

			key, err := token.GeneratePrivateKey(alg, 2048)
			assert.NoError(t, err)
			assert.IsType(t, &ecdsa.PrivateKey{}, key)
			assert.Equal(t, curve, key.(*ecdsa.PrivateKey).Curve)
		})
	}

	t.Run("returns an error for unsupported algorithms", func(t *testing.T) {
		t.Parallel()

		key, err := token.GeneratePrivateKey(jwa.HS256, 2048)
		assert.Nil(t, key)
		assert.ErrorIs(t, err, token.ErrUnsupportedGenAlgorithm)
		assert.EqualError(t, err, "unsupported algorithm for key generation: HS256")
	})
}
