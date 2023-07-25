package config_test

import (
	"net"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/assert"

	"github.com/murar8/local-jwks-server/internal/config"
)

func TestNew(t *testing.T) {
	t.Run("creates a new config using default values", func(t *testing.T) {
		cfg, err := config.New()
		assert.NoError(t, err)
		assert.Equal(t, net.IPv4(0, 0, 0, 0), cfg.Server.Addr)
		assert.Equal(t, 8080, cfg.Server.Port)
		assert.Equal(t, jwa.RS256, cfg.JWK.Alg)
		assert.Empty(t, cfg.JWK.KeyOps)
	})

	t.Run("creates a new config using environment variables", func(t *testing.T) {
		t.Setenv("SERVER_ADDR", "127.0.0.1")
		t.Setenv("SERVER_PORT", "3547")
		t.Setenv("JWK_ALG", "RS512")
		t.Setenv("JWK_KEY_OPS", "sign,verify")

		cfg, err := config.New()
		assert.NoError(t, err)
		assert.Equal(t, net.IPv4(127, 0, 0, 1), cfg.Server.Addr)
		assert.Equal(t, 3547, cfg.Server.Port)
		assert.Equal(t, jwa.RS512, cfg.JWK.Alg)
		assert.Equal(t, jwk.KeyOperationList{"sign", "verify"}, cfg.JWK.KeyOps)
	})
}
