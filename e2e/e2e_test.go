//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
)

var signPath string
var jwksPath string
var healthPath string

func init() {
	signPath, _ = url.JoinPath(os.Getenv("API_URL"), "/jwt/sign")
	jwksPath, _ = url.JoinPath(os.Getenv("API_URL"), "/.well-known/jwks.json")
	healthPath, _ = url.JoinPath(os.Getenv("API_URL"), "/health")
}

func TestHandlers(t *testing.T) {
	var token string
	var keySet jwk.Set

	t.Run("returns a signed JWT", func(t *testing.T) {
		body := `{"sub": "john.doe"}`

		res, err := http.Post(signPath, "application/json", strings.NewReader(body))

		assert.NoError(t, err)
		assert.Equal(t, http.StatusCreated, res.StatusCode)

		var data map[string]string
		err = json.NewDecoder(res.Body).Decode(&data)
		res.Body.Close()
		token = data["jwt"]

		assert.NoError(t, err)
		assert.NotNil(t, token)
	})

	t.Run("the server exposes a valid JWKS endpoint", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		var err error
		keySet, err = jwk.Fetch(ctx, jwksPath)

		assert.NoError(t, err)
		assert.NotNil(t, keySet)
	})

	t.Run("the JWT can be validated against the JWKS endpoint", func(t *testing.T) {
		parsed, err := jwt.Parse([]byte(token), jwt.WithKeySet(keySet))

		assert.NoError(t, err)
		assert.NotNil(t, parsed)
	})
}

func TestHealth(t *testing.T) {
	t.Run("the server exposes a health endpoint", func(t *testing.T) {
		res, err := http.Get(healthPath)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, res.StatusCode)
	})
}
