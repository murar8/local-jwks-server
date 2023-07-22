package config

import (
	"fmt"
	"net"

	"github.com/caarlos0/env/v9"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

type JWK struct {
	Use    jwk.KeyUsageType       `env:"JWK_USE,notEmpty" envDefault:"sig"`
	Alg    jwa.SignatureAlgorithm `env:"JWK_ALG,notEmpty" envDefault:"RS256"`
	KeyOps jwk.KeyOperationList   `env:"JWK_KEY_OPS"`
}

type Server struct {
	Addr net.IP `env:"SERVER_ADDR,notEmpty" envDefault:"0.0.0.0"`
	Port int    `env:"SERVER_PORT,notEmpty" envDefault:"8080"`
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
