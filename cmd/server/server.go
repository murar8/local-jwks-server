package main

import (
	"log"
	"net"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/render"

	"github.com/murar8/local-jwks-server/internal/config"
	"github.com/murar8/local-jwks-server/internal/handler"
	"github.com/murar8/local-jwks-server/internal/token"
)

func main() {
	cfg, err := config.New()
	if err != nil {
		log.Fatalf("failed to initialize config: %s", err)
	}

	raw, err := token.GenerateRawKey(cfg.JWK.Alg)
	if err != nil {
		log.Fatalf("failed to generate key: %s", err)
	}

	tokenService, err := token.FromRawKey(raw, &cfg.JWK)
	if err != nil {
		log.Fatalf("failed to initialize token service: %s", err)
	}

	r := chi.NewRouter()

	r.Use(middleware.AllowContentType("application/json"))
	r.Use(middleware.Heartbeat("/health"))
	r.Use(middleware.RequestID)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(render.SetContentType(render.ContentTypeJSON))

	h := handler.New(tokenService)
	r.Get("/.well-known/jwks.json", h.HandleJWKS)
	r.Post("/jwt/sign", h.HandleSign)

	addr := net.TCPAddr{IP: cfg.Server.Addr, Port: cfg.Server.Port}
	log.Printf("listening on %s", addr.String())

	if err = http.ListenAndServe(addr.String(), r); err != nil {
		log.Fatalf("failed to start server: %s", err)
	}
}
