package token

import (
	"crypto/elliptic"
	"errors"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwa"
)

// ErrUnsupportedCurve is returned when the algorithm does not have a matching
// elliptic curve.
var ErrUnsupportedCurve = errors.New("could not convert algorithm to elliptic curve")

// AlgorithmToECDSACurve retrieves the elliptic curve for the provided
// algorithm.
func AlgorithmToECDSACurve(alg jwa.SignatureAlgorithm) (elliptic.Curve, error) {
	var curve elliptic.Curve
	var err error

	switch alg {
	case jwa.ES256:
		curve = elliptic.P256()
	case jwa.ES384:
		curve = elliptic.P384()
	case jwa.ES512:
		curve = elliptic.P521()
	default:
		err = fmt.Errorf("%w: %s", ErrUnsupportedCurve, alg)
	}

	return curve, err
}
