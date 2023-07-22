package handler

import (
	"encoding/json"
	"net/http"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

type Handler interface {
	HandleJWKS(w http.ResponseWriter, r *http.Request)
	HandleSign(w http.ResponseWriter, r *http.Request)
}

type handler struct {
	key jwk.Key
}

func New(key jwk.Key) Handler {
	return &handler{key}
}

func (h *handler) HandleJWKS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	pk, err := h.key.PublicKey()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	set := jwk.NewSet()
	set.AddKey(pk)

	if err = json.NewEncoder(w).Encode(set); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (h *handler) HandleSign(w http.ResponseWriter, r *http.Request) {
	var payload map[string]string
	err := json.NewDecoder(r.Body).Decode(&payload)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	t := jwt.New()
	for k, v := range payload {
		err := t.Set(k, v)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}

	signed, err := jwt.Sign(t, jwt.WithKey(h.key.Algorithm(), h.key))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)

	body := map[string]string{"jwt": string(signed)}
	if err = json.NewEncoder(w).Encode(body); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
