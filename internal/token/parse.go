package token

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwa"
)

var (
	// ErrInvalidPEM is returned when the PEM file is invalid.
	ErrInvalidPEM = fmt.Errorf("invalid PEM")

	// ErrWrongKeyType is returned when the key type does not match the
	// configured algorithm.
	ErrWrongKeyType = fmt.Errorf("wrong key type")

	// ErrUnsupportedParseAlgorithm is returned when the algorithm is not
	// supported for key parsing.
	ErrUnsupportedParseAlgorithm = errors.New("unsupported algorithm for key parsing")
)

// ParsePrivateKey parses a private key from PEM format.
func ParsePrivateKey(data []byte, alg jwa.SignatureAlgorithm) (interface{}, error) {
	var key interface{}
	var err error

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, ErrInvalidPEM
	}

	key, err = x509.ParsePKCS8PrivateKey(block.Bytes)

	if err != nil {
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	}
	if err != nil {
		key, err = x509.ParseECPrivateKey(block.Bytes)
	}

	switch alg {
	case
		jwa.RS256,
		jwa.RS384,
		jwa.RS512,
		jwa.PS256,
		jwa.PS384,
		jwa.PS512:
		if _, ok := key.(*rsa.PrivateKey); !ok {
			return nil, fmt.Errorf("%w: expected RSA private key", ErrWrongKeyType)
		}
	case
		jwa.ES256,
		jwa.ES384,
		jwa.ES512:
		ecdsaKey, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("%w: expected ECDSA private key", ErrWrongKeyType)
		}
		curve, _ := AlgorithmToECDSACurve(alg)
		if ecdsaKey.Curve != curve {
			return nil, fmt.Errorf("%w: expected %s curve", ErrWrongKeyType, alg)
		}
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedParseAlgorithm, alg)
	}

	return key, err
}
