// This command is compiled and copied to the docker container for a simple,
// dependency free health check.

package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/murar8/local-jwks-server/internal/config"
)

func main() {
	cfg, err := config.New()
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	url := fmt.Sprintf("http://%s:%d/health", cfg.Server.Addr, cfg.Server.Port)
	res, err := http.Get(url)

	if err != nil || res.StatusCode != http.StatusOK {
		log.Fatalf("health check failed: %v", err)
	}
}
