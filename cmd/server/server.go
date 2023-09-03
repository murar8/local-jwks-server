//nolint:wrapcheck // No need to wrap errors here.
package main

import (
	"log"
	"net"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/render"
	"github.com/murar8/local-jwks-server/internal/config"
	"github.com/murar8/local-jwks-server/internal/handler"
	"github.com/murar8/local-jwks-server/internal/token"
)

func createPrivateKey(cfg *config.JWK) (interface{}, error) {
	keyFile, err := os.ReadFile(cfg.KeyFile)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}

	var privateKey interface{}

	if os.IsNotExist(err) {
		log.Println("key file not found, generating a random key")
		privateKey, err = token.GeneratePrivateKey(cfg.Alg, cfg.RsaKeySize)
	} else {
		log.Printf("using key from %s", cfg.KeyFile)
		privateKey, err = token.ParsePrivateKey(keyFile, cfg.Alg)
	}

	return privateKey, err
}

func createRouter() *chi.Mux {
	router := chi.NewRouter()

	router.NotFound(func(w http.ResponseWriter, r *http.Request) {
		res := &handler.ErrorResponse{Error: "not found", StatusCode: http.StatusNotFound}
		render.Render(w, r, res)
	})
	router.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
		res := &handler.ErrorResponse{Error: "method not allowed", StatusCode: http.StatusMethodNotAllowed}
		render.Render(w, r, res)
	})

	router.Use(middleware.AllowContentType("application/json"))
	router.Use(middleware.Heartbeat("/health"))
	router.Use(middleware.RequestID)
	router.Use(middleware.Logger)
	router.Use(middleware.Recoverer)
	router.Use(render.SetContentType(render.ContentTypeJSON))

	return router
}

func main() {
	cfg, err := config.New()
	if err != nil {
		log.Fatalf("failed to initialize config: %s", err)
	}

	privateKey, err := createPrivateKey(&cfg.JWK)
	if err != nil {
		log.Fatalf("failed to initialize private key: %s", err)
	}

	tokenService, err := token.FromRawKey(privateKey, &cfg.JWK)
	if err != nil {
		log.Fatalf("failed to initialize token service: %s", err)
	}

	router := createRouter()
	handlers := handler.New(tokenService)
	router.Get("/.well-known/jwks.json", handlers.HandleJWKS)
	router.Post("/jwt/sign", handlers.HandleSign)

	addr := net.TCPAddr{IP: cfg.Server.Addr, Port: cfg.Server.Port}
	log.Printf("listening on %s", addr.String())

	server := &http.Server{
		Addr:              addr.String(),
		Handler:           router,
		ReadHeaderTimeout: cfg.Server.HTTPReqTimeout,
	}

	if err = server.ListenAndServe(); err != nil {
		log.Fatalf("failed to start server: %s", err)
	}
}
