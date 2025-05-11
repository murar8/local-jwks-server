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
	ErrInvalidPEM = errors.New("invalid PEM")

	// ErrWrongKeyType is returned when the key type does not match the
	// configured algorithm.
	ErrWrongKeyType = errors.New("wrong key type")

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

	if key, err = x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
		if key, err = x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
			if key, err = x509.ParseECPrivateKey(block.Bytes); err != nil {
				return nil, fmt.Errorf("%w: %s", ErrInvalidPEM, "failed to parse private key")
			}
		}
	}

	if err = validateKey(key, alg); err != nil {
		return nil, err
	}

	return key, err
}

func validateKey(key interface{}, alg jwa.SignatureAlgorithm) error {
	var err error

	switch alg {
	case
		jwa.RS256,
		jwa.RS384,
		jwa.RS512,
		jwa.PS256,
		jwa.PS384,
		jwa.PS512:
		if _, ok := key.(*rsa.PrivateKey); !ok {
			err = fmt.Errorf("%w: expected RSA private key", ErrWrongKeyType)
		}
	case
		jwa.ES256,
		jwa.ES384,
		jwa.ES512:
		ecdsaKey, ok := key.(*ecdsa.PrivateKey)
		if ok {
			curve, _ := AlgorithmToECDSACurve(alg)
			if ecdsaKey.Curve != curve {
				err = fmt.Errorf("%w: expected %s curve", ErrWrongKeyType, alg)
			}
		} else {
			err = fmt.Errorf("%w: expected ECDSA private key", ErrWrongKeyType)
		}
	default:
		err = fmt.Errorf("%w: %s", ErrUnsupportedParseAlgorithm, alg)
	}

	return err
}
