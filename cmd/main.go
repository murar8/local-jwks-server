package main

import (
	"log"
	"net"
	"net/http"

	"github.com/murar8/local-jwks-server/internal/config"
	"github.com/murar8/local-jwks-server/internal/handler"
	"github.com/murar8/local-jwks-server/internal/jwkutil"
)

func main() {
	cfg, err := config.New()
	if err != nil {
		log.Fatalf("failed to initialize config: %s", err)
	}

	jwks, err := jwkutil.GenerateKeySet(&cfg.JWK, 1)
	if err != nil {
		log.Fatalf("failed to generate key: %s", err)
	}

	h := handler.New(jwks)

	http.HandleFunc("/.well-known/jwks.json", h.HandleJWKS)
	http.HandleFunc("/jwt/sign", h.HandleSign)

	addr := net.TCPAddr{IP: cfg.Server.Addr, Port: cfg.Server.Port}
	log.Printf("listening on %s", addr.String())
	http.ListenAndServe(addr.String(), nil)
}
