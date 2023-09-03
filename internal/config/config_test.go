package config_test

import (
	"net"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/murar8/local-jwks-server/internal/config"
	"github.com/stretchr/testify/assert"
)

//nolint:paralleltest // Test is not parallelizable due to the use of environment variables.
func TestNew(t *testing.T) {
	t.Run("creates a new config using default values", func(t *testing.T) {
		cfg, err := config.New()
		assert.NoError(t, err)
		assert.Equal(t, net.IPv4(0, 0, 0, 0), cfg.Server.Addr)
		assert.Equal(t, 8080, cfg.Server.Port)
		assert.Equal(t, 30*time.Second, cfg.Server.HTTPReqTimeout)
		assert.Equal(t, jwa.RS256, cfg.JWK.Alg)
		assert.Equal(t, "/etc/local-jwks-server/key.pem", cfg.JWK.KeyFile)
		assert.Empty(t, cfg.JWK.KeyOps)
		assert.Equal(t, 2048, cfg.JWK.RsaKeySize)
	})

	t.Run("creates a new config using environment variables", func(t *testing.T) {
		t.Setenv("SERVER_ADDR", "127.0.0.1")
		t.Setenv("SERVER_PORT", "3547")
		t.Setenv("JWK_RSA_KEY_SIZE", "4096")
		t.Setenv("JWK_ALG", "RS512")
		t.Setenv("JWK_KEY_FILE", "/tmp/jwks-private-key")
		t.Setenv("JWK_KEY_OPS", "sign,verify")
		t.Setenv("SERVER_HTTP_REQ_TIMEOUT", "60s")

		cfg, err := config.New()
		assert.NoError(t, err)
		assert.Equal(t, net.IPv4(127, 0, 0, 1), cfg.Server.Addr)
		assert.Equal(t, 3547, cfg.Server.Port)
		assert.Equal(t, 60*time.Second, cfg.Server.HTTPReqTimeout)
		assert.Equal(t, jwa.RS512, cfg.JWK.Alg)
		assert.Equal(t, "/tmp/jwks-private-key", cfg.JWK.KeyFile)
		assert.Equal(t, 4096, cfg.JWK.RsaKeySize)
		assert.Equal(t, jwk.KeyOperationList{"sign", "verify"}, cfg.JWK.KeyOps)
	})

	t.Run("returns an error if environment variables are invalid", func(t *testing.T) {
		t.Setenv("SERVER_PORT", "invalid")
		cfg, err := config.New()
		assert.Nil(t, cfg)
		assert.Error(t, err)
	})
}
