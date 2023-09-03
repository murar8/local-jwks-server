package token

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwa"
)

// ErrUnsupportedGenAlgorithm is returned when the algorithm is not supported
// for key generation.
var ErrUnsupportedGenAlgorithm = errors.New("unsupported algorithm for key generation")

// GeneratePrivateKey generates an RSA or ECDSA key based on the provided algorithm.
func GeneratePrivateKey(alg jwa.SignatureAlgorithm, keySize int) (interface{}, error) {
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
	case
		jwa.ES256,
		jwa.ES384,
		jwa.ES512:
		curve, _ := AlgorithmToECDSACurve(alg)
		key, err = ecdsa.GenerateKey(curve, rand.Reader)
	default:
		err = fmt.Errorf("%w: %s", ErrUnsupportedGenAlgorithm, alg)
	}

	return key, err
}
