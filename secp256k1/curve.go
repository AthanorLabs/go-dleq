package secp256k1

import (
	"encoding/hex"

	"github.com/noot/go-dleq/types"
	"github.com/renproject/secp256k1"
	"golang.org/x/crypto/sha3"
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

func (c *CurveImpl) ScalarFrom(in uint16) Scalar {
	s := &secp256k1.Fn{}
	s.SetU16(in)
	return &ScalarImpl{
		inner: s,
	}
}

func (c *CurveImpl) HashToScalar(in []byte) (Scalar, error) {
	// TODO: should hash be 32 or 64 bits?
	h := sha3.Sum256(in)
	s := &secp256k1.Fn{}
	_ = s.SetB32(h[:])
	return &ScalarImpl{
		inner: s,
	}, nil
}

func (c *CurveImpl) ScalarBaseMul(s Scalar) Point {
	ss, ok := s.(*ScalarImpl)
	if !ok {
		panic("invalid scalar; type is not *secp256k1.ScalarImpl")
	}

	p := &secp256k1.Point{}
	p.BaseExp(ss.inner)
	return &PointImpl{
		inner: p,
	}
}

func (c *CurveImpl) ScalarMul(s Scalar, p Point) Point {
	ss, ok := s.(*ScalarImpl)
	if !ok {
		panic("invalid scalar; type is not *secp256k1.ScalarImpl")
	}

	pp, ok := p.(*PointImpl)
	if !ok {
		panic("invalid point; type is not *secp256k1.PointImpl")
	}

	r := &secp256k1.Point{}
	r.Scale(pp.inner, ss.inner)
	return &PointImpl{
		inner: r,
	}
}

type ScalarImpl struct {
	inner *secp256k1.Fn
}

func (s *ScalarImpl) Add(b Scalar) Scalar {
	ss, ok := b.(*ScalarImpl)
	if !ok {
		panic("invalid scalar; type is not *secp256k1.ScalarImpl")
	}

	r := &secp256k1.Fn{}
	r.Add(s.inner, ss.inner)
	return &ScalarImpl{
		inner: r,
	}
}

func (s *ScalarImpl) Sub(b Scalar) Scalar {
	ss, ok := b.(*ScalarImpl)
	if !ok {
		panic("invalid scalar; type is not *secp256k1.ScalarImpl")
	}

	sNeg := &secp256k1.Fn{}
	sNeg.Negate(ss.inner)

	r := &secp256k1.Fn{}
	r.Add(s.inner, sNeg)
	return &ScalarImpl{
		inner: r,
	}
}

func (s *ScalarImpl) Mul(b Scalar) Scalar {
	ss, ok := b.(*ScalarImpl)
	if !ok {
		panic("invalid scalar; type is not *secp256k1.ScalarImpl")
	}

	r := &secp256k1.Fn{}
	r.Mul(s.inner, ss.inner)
	return &ScalarImpl{
		inner: r,
	}
}

func (s *ScalarImpl) Inverse() Scalar {
	r := &secp256k1.Fn{}
	r.Inverse(s.inner)
	return &ScalarImpl{
		inner: r,
	}
}

func (s *ScalarImpl) Encode() ([]byte, error) {
	var b [32]byte
	s.inner.PutB32(b[:])
	return b[:], nil
}

func (s *ScalarImpl) Eq(other Scalar) bool {
	o, ok := other.(*ScalarImpl)
	if !ok {
		panic("invalid scalar; type is not *secp256k1.ScalarImpl")
	}

	return s.inner.Eq(o.inner)
}

func (s *ScalarImpl) IsZero() bool {
	return s.inner.IsZero()
}

type PointImpl struct {
	inner *secp256k1.Point
}

func (p *PointImpl) Add(b Point) Point {
	pp, ok := b.(*PointImpl)
	if !ok {
		panic("invalid point; type is not *secp256k1.PointImpl")
	}

	r := &secp256k1.Point{}
	r.Add(p.inner, pp.inner)
	return &PointImpl{
		inner: r,
	}
}

func (p *PointImpl) Sub(b Point) Point {
	pp, ok := b.(*PointImpl)
	if !ok {
		panic("invalid point; type is not *secp256k1.PointImpl")
	}

	minusOne := &secp256k1.Fn{}
	minusOne.SetU16(1)
	minusOne.Negate(minusOne)
	minusP := &secp256k1.Point{}
	minusP.Scale(pp.inner, minusOne)

	r := &secp256k1.Point{}
	r.Add(p.inner, minusP)
	return &PointImpl{
		inner: r,
	}
}

func (p *PointImpl) ScalarMul(s Scalar) Point {
	ss, ok := s.(*ScalarImpl)
	if !ok {
		panic("invalid scalar; type is not *secp256k1.ScalarImpl")
	}

	r := &secp256k1.Point{}
	r.Scale(p.inner, ss.inner)
	return &PointImpl{
		inner: r,
	}
}

func (p *PointImpl) Encode() ([]byte, error) {
	var b [33]byte
	p.inner.PutBytes(b[:])
	return b[:], nil
}

func (p *PointImpl) IsZero() bool {
	var empty [33]byte
	var b [33]byte
	//zero := &secp256k1.Point{}
	p.inner.PutBytes(b[:])
	return empty == b
	//return p.inner.Eq(zero)
}
