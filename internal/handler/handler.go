package handler

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/render"
	"github.com/murar8/local-jwks-server/internal/token"
)

type Handler interface {
	HandleJWKS(w http.ResponseWriter, r *http.Request)
	HandleSign(w http.ResponseWriter, r *http.Request)
}

type handler struct {
	tokenService token.Service
}

func New(tokenService token.Service) Handler {
	return &handler{tokenService}
}

func (h *handler) HandleJWKS(w http.ResponseWriter, r *http.Request) {
	if set, err := h.tokenService.GetKeySet(); err != nil {
		res := &ErrorResponse{Error: err.Error(), StatusCode: http.StatusInternalServerError}
		render.Render(w, r, res)
	} else {
		render.JSON(w, r, set)
	}
}

func (h *handler) HandleSign(w http.ResponseWriter, r *http.Request) {
	var payload map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		res := &ErrorResponse{Error: err.Error(), StatusCode: http.StatusUnprocessableEntity}
		render.Render(w, r, res)
		return
	}

	// Extract headers from query parameters
	headers := make(map[string]interface{})
	for k, v := range r.URL.Query() {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}

	signed, err := h.tokenService.SignToken(payload, headers)
	if err != nil {
		res := &ErrorResponse{Error: err.Error(), StatusCode: http.StatusBadRequest}
		render.Render(w, r, res)
		return
	}

	render.Render(w, r, &HandleSignResponse{Jwt: string(signed)})
}
