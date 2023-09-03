package token

import (
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/murar8/local-jwks-server/internal/config"
)

type Service interface {
	GetKey() jwk.Key
	GetKeySet() (jwk.Set, error)
	SignToken(payload map[string]interface{}) ([]byte, error)
}

type service struct {
	key jwk.Key
}

func FromRawKey(raw interface{}, cfg *config.JWK) (Service, error) {
	key, err := jwk.FromRaw(raw)
	if err != nil {
		return nil, fmt.Errorf("failed to parse key: %w", err)
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
			return nil, fmt.Errorf("failed to set key field: %w", err)
		}
	}

	if err = jwk.AssignKeyID(key); err != nil {
		return nil, fmt.Errorf("failed to assign key ID: %w", err)
	}

	return &service{key}, nil
}

func (s *service) GetKey() jwk.Key {
	return s.key
}

func (s *service) GetKeySet() (jwk.Set, error) {
	pk, err := s.key.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %w", err)
	}

	set := jwk.NewSet()
	_ = set.AddKey(pk)

	return set, nil
}

func (s *service) SignToken(payload map[string]interface{}) ([]byte, error) {
	t := jwt.New()

	for k, v := range payload {
		err := t.Set(k, v)
		if err != nil {
			return nil, fmt.Errorf("failed to set payload: %w", err)
		}
	}

	jwt, err := jwt.Sign(t, jwt.WithKey(s.key.Algorithm(), s.key))
	if err != nil {
		return nil, fmt.Errorf("failed to sign token: %w", err)
	}

	return jwt, nil
}
