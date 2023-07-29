// This command is compiled and copied to the docker container for a simple,
// dependency free health check.

package main

import (
	"fmt"
	"log"
	"net"
	"net/http"

	"github.com/murar8/local-jwks-server/internal/config"
)

func main() {
	cfg, err := config.New()
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	host := net.JoinHostPort(cfg.Server.Addr.String(), fmt.Sprint(cfg.Server.Port))
	url := fmt.Sprintf("http://%s/health", host)
	res, err := http.Get(url)
	res.Body.Close()

	if err != nil || res.StatusCode != http.StatusOK {
		log.Fatalf("health check failed: %v", err)
	}
}
