package jwkutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"

	"github.com/murar8/local-jwks-server/internal/config"
)

// GenerateRawKey generates an RSA or ECDSA key based on the provided algorithm.
func GenerateRawKey(alg jwa.SignatureAlgorithm) (interface{}, error) {
	var key interface{}
	var err error

	switch alg {
	case
		jwa.RS256,
		jwa.RS384,
		jwa.RS512,
		jwa.PS256,
		jwa.PS384,
		jwa.PS512:
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	case jwa.ES256:
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case jwa.ES384:
		key, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case jwa.ES512:
		key, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	default:
		err = fmt.Errorf("unsupported algorithm: %s", alg)
	}

	return key, err
}

// GenerateKey generates a random JWK key based on the provided configuration.
func GenerateKey(cfg *config.JWK) (jwk.Key, error) {
	raw, err := GenerateRawKey(cfg.Alg)
	if err != nil {
		return nil, err
	}

	key, err := jwk.FromRaw(raw)
	if err != nil {
		return nil, err
	}

	fields := []struct {
		key string
		val interface{}
	}{
		{jwk.KeyUsageKey, "sig"},
		{jwk.AlgorithmKey, cfg.Alg},
		{jwk.KeyOpsKey, cfg.KeyOps},
	}

	for _, f := range fields {
		if err = key.Set(f.key, f.val); err != nil {
			return nil, err
		}
	}

	if err = jwk.AssignKeyID(key); err != nil {
		return nil, err
	}

	return key, nil
}

// GenerateKeySet generates a JWK set with the provided number of keys.
func GenerateKeySet(cfg *config.JWK, count int) (jwk.Set, error) {
	set := jwk.NewSet()

	for i := 0; i < count; i++ {
		key, err := GenerateKey(cfg)
		if err != nil {
			return nil, err
		}
		pub, err := key.PublicKey()
		if err != nil {
			return nil, err
		}
		if err = set.AddKey(pub); err != nil {
			return nil, err
		}
	}

	return set, nil
}
