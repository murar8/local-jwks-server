package main

import (
	"log"
	"net"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/murar8/local-jwks-server/internal/config"
	"github.com/murar8/local-jwks-server/internal/handler"
	"github.com/murar8/local-jwks-server/internal/jwkutil"
)

func main() {
	cfg, err := config.New()
	if err != nil {
		log.Fatalf("failed to initialize config: %s", err)
	}

	jwk, err := jwkutil.GenerateKey(&cfg.JWK)
	if err != nil {
		log.Fatalf("failed to generate key: %s", err)
	}

	r := chi.NewRouter()

	r.Use(middleware.AllowContentType("application/json"))
	r.Use(middleware.Heartbeat("/health"))
	r.Use(middleware.RequestID)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	h := handler.New(jwk)
	r.Get("/.well-known/jwks.json", h.HandleJWKS)
	r.Post("/jwt/sign", h.HandleSign)

	addr := net.TCPAddr{IP: cfg.Server.Addr, Port: cfg.Server.Port}
	log.Printf("listening on %s", addr.String())

	if err = http.ListenAndServe(addr.String(), r); err != nil {
		log.Fatalf("failed to start server: %s", err)
	}
}
