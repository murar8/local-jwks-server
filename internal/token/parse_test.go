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
	"github.com/stretchr/testify/require"
)

const rsa512TestKey = `
-----BEGIN RSA PRIVATE KEY-----
MIIBOQIBAAJBAIUclyMikuIXtkFZ1yWjcRt+NaWqGDfn5zbEEw46F/uHqWUWswqs
3J1bnUmc+BjLEM+cioTlPbqMHCajQWw2GxECAwEAAQJAT5UOTzVGd+IRVvTtilUz
NGq6jDcrj5EYTUfg1Kqq1/gZi//2ZZRqE7lg8eoyqg9yP9AbaWRFk5KXqSStI/Ht
+QIhAO8IQYSuXNs8T8XS5b1DW2KGjufYAyJZsfgNPrVR9wEfAiEAjo+GEcxzPKNW
//1kZJTy4wQ2ecCGfH61qY51tzu+bc8CIGJQ9wHn5fGW4QjxMeWi6tefmO/rfX6H
fhgU+pIB4KLpAiBpNYauMAKDp9AXD/w9Nqeh3oQNioY17pVG0voRBihdhQIgSDIi
GzoOZasWOZRJduse3wFeP9wmSAxyyrrluxd3bWM=
-----END RSA PRIVATE KEY-----
`

const ec256TestKey = `
-----BEGIN EC PRIVATE KEY-----
MHgCAQEEIQD8Tk826SwYPfaA82boHo7J1XjbAR0gUKlVIPK8DerpuqAKBggqhkjO
PQMBB6FEA0IABC9LFZZFczclEn+7A1+qAr2o1DFEh+ThyMeJ0tRoENn0LihQ31jE
05Gj5UhWnP+849rSmQLwMTHNCde/abTuMMw=
-----END EC PRIVATE KEY-----
`

const ec384TestKey = `
-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDAUt6oI45rJwucrfMvvtFjR2Lvx5pgsXqtUg96WP8rRnayUxRCf0bFn
PIhFajKNQj+gBwYFK4EEACKhZANiAARdsvB4IXzn42Izx7Dw5Tg7Pnl9efaRXlCv
sPSQVUm88kP9+8pMvVLdjfgBH66yjTZ3975yNdGLP4Q7kPF/52aZqDxhAnE1j1vN
PBJA+B+r+VnZ/+lpcPgUxKSKGhFL7E8=
-----END EC PRIVATE KEY-----
`

const ec512TestKey = `
-----BEGIN EC PRIVATE KEY-----
MIHcAgEBBEIAo1PCfsyiNN5meo9e75U9JAvDMb+m3K8ML4j4XSIAjfL3S3RGBfvA
kY0AhSxJd0nQnT5VgGoFCJB158qKoV3TrHqgBwYFK4EEACOhgYkDgYYABAGooQR0
x71P7pSBa5SO1Xl359sV9fOU4mxW9W7sADvDknYU3xmJ+GUyyd/wyKCOj3SAiT4o
//Wa2YwtVdMVASxmfwChh4vjB2LSQGuwRej1EH2zWV5FLGPwNarq5RYMWu8S3i43
+S0eSNCaEnshNR1w7VuJxFsa4MdlDJblUfJUguoTgA==
-----END EC PRIVATE KEY-----
`

func TestParseKey(t *testing.T) {
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
		t.Run(fmt.Sprintf("parses a %s key", alg), func(t *testing.T) {
			t.Parallel()

			key, err := token.ParsePrivateKey([]byte(rsa512TestKey), alg)
			require.NoError(t, err)
			assert.IsType(t, &rsa.PrivateKey{}, key)
		})
	}

	ecdsas := []struct {
		alg   jwa.SignatureAlgorithm
		curve elliptic.Curve
		raw   string
	}{
		{jwa.ES256, elliptic.P256(), ec256TestKey},
		{jwa.ES384, elliptic.P384(), ec384TestKey},
		{jwa.ES512, elliptic.P521(), ec512TestKey},
	}

	for _, tt := range ecdsas {
		curve := tt.curve
		alg := tt.alg
		raw := tt.raw

		t.Run(fmt.Sprintf("generates a %s key", alg), func(t *testing.T) {
			t.Parallel()

			key, err := token.ParsePrivateKey([]byte(raw), alg)
			require.NoError(t, err)
			assert.IsType(t, &ecdsa.PrivateKey{}, key)
			assert.Equal(t, curve, key.(*ecdsa.PrivateKey).Curve)
		})
	}

	t.Run("returns an error for unsupported algorithms", func(t *testing.T) {
		t.Parallel()

		key, err := token.ParsePrivateKey([]byte(rsa512TestKey), jwa.HS256)
		assert.Nil(t, key)
		require.ErrorIs(t, err, token.ErrUnsupportedParseAlgorithm)
		assert.EqualError(t, err, "unsupported algorithm for key parsing: HS256")
	})

	t.Run("returns an error for invalid PEM", func(t *testing.T) {
		t.Parallel()

		key, err := token.ParsePrivateKey([]byte("invalid"), jwa.RS256)
		assert.Nil(t, key)
		require.ErrorIs(t, err, token.ErrInvalidPEM)
		assert.EqualError(t, err, "invalid PEM")
	})

	t.Run("returns an error for invalid RSA key", func(t *testing.T) {
		t.Parallel()

		key, err := token.ParsePrivateKey([]byte(ec256TestKey), jwa.RS256)
		assert.Nil(t, key)
		require.ErrorIs(t, err, token.ErrWrongKeyType)
		assert.EqualError(t, err, "wrong key type: expected RSA private key")
	})

	t.Run("returns an error for invalid ECDSA key", func(t *testing.T) {
		t.Parallel()

		key, err := token.ParsePrivateKey([]byte(rsa512TestKey), jwa.ES256)
		assert.Nil(t, key)
		require.ErrorIs(t, err, token.ErrWrongKeyType)
		assert.EqualError(t, err, "wrong key type: expected ECDSA private key")
	})

	t.Run("returns an error for invalid ECDSA curve", func(t *testing.T) {
		t.Parallel()

		key, err := token.ParsePrivateKey([]byte(ec256TestKey), jwa.ES384)
		assert.Nil(t, key)
		require.ErrorIs(t, err, token.ErrWrongKeyType)
		assert.EqualError(t, err, "wrong key type: expected ES384 curve")
	})
}
