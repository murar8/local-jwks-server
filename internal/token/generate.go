package token

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwa"
)

var ErrUnsupportedAlgorithm = errors.New("unsupported algorithm")

// GenerateRawKey generates an RSA or ECDSA key based on the provided algorithm.
func GenerateRawKey(alg jwa.SignatureAlgorithm, keySize int) (interface{}, error) {
	var key interface{}
	var err error

	switch alg {
	case
		jwa.RS256,
		jwa.RS384,
		jwa.RS512,
		jwa.PS256,
		jwa.PS384,
		jwa.PS512:
		key, err = rsa.GenerateKey(rand.Reader, keySize)
	case jwa.ES256:
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case jwa.ES384:
		key, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case jwa.ES512:
		key, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	default:
		err = fmt.Errorf("%w: %s", ErrUnsupportedAlgorithm, alg)
	}

	return key, err
}
