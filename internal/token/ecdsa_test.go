package token_test

import (
	"crypto/elliptic"
	"fmt"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/murar8/local-jwks-server/internal/token"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAlgorithmToECDSACurve(t *testing.T) {
	t.Parallel()

	tests := []struct {
		alg   jwa.SignatureAlgorithm
		curve elliptic.Curve
	}{
		{jwa.ES256, elliptic.P256()},
		{jwa.ES384, elliptic.P384()},
		{jwa.ES512, elliptic.P521()},
	}

	for _, tt := range tests {
		curve := tt.curve
		alg := tt.alg

		t.Run(fmt.Sprintf("returns the curve for %s algorithm", alg), func(t *testing.T) {
			t.Parallel()

			res, err := token.AlgorithmToECDSACurve(alg)
			require.NoError(t, err)
			assert.Equal(t, curve, res)
		})
	}

	t.Run("returns an error for unsupported algorithm", func(t *testing.T) {
		t.Parallel()

		res, err := token.AlgorithmToECDSACurve("RS256")
		assert.Nil(t, res)
		require.ErrorIs(t, err, token.ErrUnsupportedCurve)
		assert.EqualError(t, err, "could not convert algorithm to elliptic curve: RS256")
	})
}
