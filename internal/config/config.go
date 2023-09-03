package config

import (
	"fmt"
	"net"
	"time"

	"github.com/caarlos0/env/v9"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

type JWK struct {
	Alg        jwa.SignatureAlgorithm `env:"JWK_ALG,notEmpty" envDefault:"RS256"`
	RsaKeySize int                    `env:"JWK_RSA_KEY_SIZE" envDefault:"2048"`
	KeyFile    string                 `env:"JWK_KEY_FILE"     envDefault:"/etc/local-jwks-server/key.pem"`
	KeyOps     jwk.KeyOperationList   `env:"JWK_KEY_OPS"`
}

type Server struct {
	Addr           net.IP        `env:"SERVER_ADDR,notEmpty"    envDefault:"0.0.0.0"`
	Port           int           `env:"SERVER_PORT,notEmpty"    envDefault:"8080"`
	HTTPReqTimeout time.Duration `env:"SERVER_HTTP_REQ_TIMEOUT" envDefault:"30s"`
}

type Config struct {
	Server Server
	JWK    JWK
}

func New() (*Config, error) {
	cfg := Config{}

	if err := env.Parse(&cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	return &cfg, nil
}
