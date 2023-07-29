package handler_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/murar8/local-jwks-server/internal/config"
	"github.com/murar8/local-jwks-server/internal/handler"
	"github.com/murar8/local-jwks-server/internal/token"
	"github.com/stretchr/testify/assert"
)

type failingTokenService struct{}

func (f *failingTokenService) GetKey() jwk.Key {
	return nil
}

func (f *failingTokenService) GetKeySet() (jwk.Set, error) {
	return nil, fmt.Errorf("failed to build key set")
}

func (f *failingTokenService) SignToken(map[string]interface{}) ([]byte, error) {
	return nil, fmt.Errorf("failed to sign token")
}

func makeTokenService() token.Service {
	cfg := config.JWK{Alg: "RS256", KeyOps: jwk.KeyOperationList{"sign", "verify"}}
	raw, _ := token.GenerateRawKey(cfg.Alg, 2048)
	ts, _ := token.FromRawKey(raw, &cfg)
	return ts
}

func makeHandleJWKSRequest(ts token.Service) *http.Response {
	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()
	h := handler.New(ts)
	h.HandleJWKS(w, req)
	return w.Result()
}

func makeHandleSignRequest(ts token.Service, payload interface{}) *http.Response {
	body, err := json.Marshal(payload)
	if err != nil {
		panic(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/jwt/sign", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h := handler.New(ts)
	h.HandleSign(w, req)
	return w.Result()
}

func TestHandleJWKS(t *testing.T) {
	t.Parallel()

	t.Run(("serializes the supplied JWK set"), func(t *testing.T) {
		t.Parallel()

		ts := makeTokenService()
		res := makeHandleJWKSRequest(ts)

		var data map[string][]map[string]interface{}
		err := json.NewDecoder(res.Body).Decode(&data)
		res.Body.Close()

		assert.NoError(t, err)
		assert.Equal(t, res.StatusCode, http.StatusOK)
		assert.Equal(t, "sig", data["keys"][0]["use"])
		assert.Equal(t, "RSA", data["keys"][0]["kty"])
		assert.Equal(t, "RS256", data["keys"][0]["alg"])
	})

	t.Run(("returns an error if the key set cannot be generated"), func(t *testing.T) {
		t.Parallel()

		ts := &failingTokenService{}
		res := makeHandleJWKSRequest(ts)

		var data map[string]interface{}
		err := json.NewDecoder(res.Body).Decode(&data)
		res.Body.Close()

		assert.NoError(t, err)
		assert.Equal(t, http.StatusInternalServerError, res.StatusCode)
		assert.EqualValues(t, http.StatusInternalServerError, data["statusCode"])
		assert.Equal(t, "failed to build key set", data["error"])
	})
}

func TestHandleSign(t *testing.T) {
	t.Parallel()

	t.Run(("generates a signed jwt with the provided payload"), func(t *testing.T) {
		t.Parallel()

		ts := makeTokenService()
		payload := map[string]interface{}{"sub": "john_doe", "custom": "value"}
		res := makeHandleSignRequest(ts, payload)

		var data map[string]interface{}
		err := json.NewDecoder(res.Body).Decode(&data)
		res.Body.Close()

		assert.NoError(t, err)
		assert.Equal(t, http.StatusCreated, res.StatusCode)

		key := ts.GetKey()

		var raw interface{}
		_ = key.Raw(&raw)

		encoded, _ := (data["jwt"].(string))

		parsed, err := jwt.Parse([]byte(encoded), jwt.WithKey(key.Algorithm(), raw))

		assert.NoError(t, err)
		assert.Equal(t, "john_doe", parsed.Subject())
		assert.Equal(t, "value", parsed.PrivateClaims()["custom"])
	})

	t.Run(("returns bad request status if the payload is invalid"), func(t *testing.T) {
		t.Parallel()

		payload := map[string]interface{}{"iat": "invalid"}
		res := makeHandleSignRequest(makeTokenService(), payload)
		res.Body.Close()

		assert.Equal(t, http.StatusBadRequest, res.StatusCode)
	})

	t.Run(("returns unprocessable entity status if the payload is malformed"), func(t *testing.T) {
		t.Parallel()

		ts := makeTokenService()
		res := makeHandleSignRequest(ts, "invalid")

		var data map[string]interface{}
		err := json.NewDecoder(res.Body).Decode(&data)
		res.Body.Close()

		assert.NoError(t, err)
		assert.Equal(t, http.StatusUnprocessableEntity, res.StatusCode)
		assert.EqualValues(t, http.StatusUnprocessableEntity, data["statusCode"])
		assert.NotNil(t, data["error"])
	})
}
