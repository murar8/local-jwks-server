package handler

import (
	"net/http"

	"github.com/go-chi/render"
)

type HandleSignResponse struct {
	Jwt string `json:"jwt"`
}

func (h *HandleSignResponse) Render(w http.ResponseWriter, r *http.Request) error {
	render.Status(r, http.StatusCreated)
	return nil
}

type ErrorResponse struct {
	Error      string `json:"error"`
	StatusCode int    `json:"status_code"`
}

func (e *ErrorResponse) Render(w http.ResponseWriter, r *http.Request) error {
	render.Status(r, e.StatusCode)
	return nil
}
