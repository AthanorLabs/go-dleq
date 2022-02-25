package secp256k1

import (
	"encoding/hex"

	"github.com/noot/go-dleq/types"
	"github.com/renproject/secp256k1"
)

type Curve = types.Curve
type Point = types.Point
type Scalar = types.Scalar

var _ Curve = &CurveImpl{}
var _ Scalar = &ScalarImpl{}
var _ Point = &PointImpl{}

type CurveImpl struct{}

func NewCurve() Curve {
	return &CurveImpl{}
}

func (c *CurveImpl) BitSize() uint64 {
	return 255
}

func (c *CurveImpl) BasePoint() Point {
	p := &secp256k1.Point{}
	one := secp256k1.NewFnFromU16(1)
	p.BaseExp(&one)
	return &PointImpl{
		inner: p,
	}
}

func (*CurveImpl) AltBasePoint() Point {
	const str = "0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
	b, err := hex.DecodeString(str)
	if err != nil {
		panic(err)
	}

	p := &secp256k1.Point{}
	err = p.SetBytes(b)
	if err != nil {
		panic(err)
	}

	return &PointImpl{
		inner: p,
	}
}

func (c *CurveImpl) NewRandomScalar() Scalar {
	s := secp256k1.RandomFn()
	return &ScalarImpl{
		inner: &s,
	}
}

func (c *CurveImpl) ScalarFrom(uint64) Scalar {
	return nil
}

func (c *CurveImpl) HashToScalar([]byte) (Scalar, error) {
	return nil, nil
}

func (c *CurveImpl) HashToCurve([]byte) Point {
	return nil
}

func (c *CurveImpl) ScalarBaseMul(Scalar) Point {
	return nil
}

func (c *CurveImpl) ScalarMul(Scalar, Point) Point {
	return nil
}

type ScalarImpl struct {
	inner *secp256k1.Fn
}

func (s *ScalarImpl) Add(Scalar) Scalar {
	return nil
}

func (s *ScalarImpl) Mul(Scalar) Scalar {
	return nil
}

func (s *ScalarImpl) Inverse() Scalar {
	return nil
}

func (s *ScalarImpl) Encode() ([]byte, error) {
	return nil, nil
}

func (s *ScalarImpl) Eq(Scalar) bool {
	return false
}

type PointImpl struct {
	inner *secp256k1.Point
}

func (p *PointImpl) Add(Point) Point {
	return nil
}

func (p *PointImpl) Sub(Point) Point {
	return nil
}

func (p *PointImpl) ScalarMul(Scalar) Point {
	return nil
}

func (p *PointImpl) Encode() ([]byte, error) {
	return nil, nil
}
