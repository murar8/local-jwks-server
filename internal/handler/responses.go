package handler

import (
	"net/http"

	"github.com/go-chi/render"
)

type HandleSignResponse struct {
	Jwt string `json:"jwt"`
}

func (h *HandleSignResponse) Render(_ http.ResponseWriter, r *http.Request) error {
	render.Status(r, http.StatusCreated)
	return nil
}

type ErrorResponse struct {
	Error      string `json:"error"`
	StatusCode int    `json:"statusCode"`
}

func (e *ErrorResponse) Render(_ http.ResponseWriter, r *http.Request) error {
	render.Status(r, e.StatusCode)
	return nil
}
