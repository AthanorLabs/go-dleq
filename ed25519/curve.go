package ed25519

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/noot/go-dleq/types"
	"golang.org/x/crypto/sha3"

	"filippo.io/edwards25519"
)

type Curve = types.Curve
type Point = types.Point
type Scalar = types.Scalar

type CurveImpl struct{}

func NewCurve() Curve {
	return &CurveImpl{}
}

func (c *CurveImpl) BitSize() uint64 {
	return 252
}

func (c *CurveImpl) BasePoint() Point {
	return &PointImpl{
		inner: edwards25519.NewGeneratorPoint(),
	}
}

func (c *CurveImpl) AltBasePoint() Point {
	const str = "8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94"
	b, err := hex.DecodeString(str)
	if err != nil {
		panic(err)
	}

	p, err := new(edwards25519.Point).SetBytes(b)
	if err != nil {
		panic(err)
	}

	return &PointImpl{
		inner: p,
	}
}

func (c *CurveImpl) NewRandomScalar() Scalar {
	var b [64]byte
	_, err := rand.Read(b[:])
	if err != nil {
		panic(err)
	}

	s, err := new(edwards25519.Scalar).SetUniformBytes(b[:])
	if err != nil {
		panic(err)
	}

	return &ScalarImpl{
		inner: s,
	}
}

func (c *CurveImpl) ScalarFromBytes(b [32]byte) Scalar {
	s, err := new(edwards25519.Scalar).SetCanonicalBytes(b[:])
	if err != nil {
		panic(err)
	}

	return &ScalarImpl{
		inner: s,
	}
}

func (c *CurveImpl) ScalarFromInt(in uint32) Scalar {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b[:], in)

	bFull := [32]byte{}
	copy(bFull[:4], b)

	return c.ScalarFromBytes(bFull)
}

func (c *CurveImpl) HashToScalar(in []byte) (Scalar, error) {
	h := sha3.Sum512(in)
	s, err := new(edwards25519.Scalar).SetUniformBytes(h[:])
	if err != nil {
		panic(err)
	}

	return &ScalarImpl{
		inner: s,
	}, nil
}

func (c *CurveImpl) ScalarBaseMul(s Scalar) Point {
	ss, ok := s.(*ScalarImpl)
	if !ok {
		panic("invalid scalar; type is not *ed25519.ScalarImpl")
	}

	return &PointImpl{
		inner: new(edwards25519.Point).ScalarBaseMult(ss.inner),
	}
}

func (c *CurveImpl) ScalarMul(s Scalar, p Point) Point {
	ss, ok := s.(*ScalarImpl)
	if !ok {
		panic("invalid scalar; type is not *ed25519.ScalarImpl")
	}

	pp, ok := p.(*PointImpl)
	if !ok {
		panic("invalid point; type is not *ed25519.PointImpl")
	}

	return &PointImpl{
		inner: new(edwards25519.Point).ScalarMult(ss.inner, pp.inner),
	}
}

func (c *CurveImpl) Sign(s Scalar, p Point) ([]byte, error) {
	ss, ok := s.(*ScalarImpl)
	if !ok {
		panic("invalid scalar; type is not *ed25519.ScalarImpl")
	}

	seed := ss.inner.Bytes()

	h := sha512.Sum512(seed[:])
	r, err := edwards25519.NewScalar().SetUniformBytes(h[:])
	if err != nil {
		return nil, fmt.Errorf("failed to set bytes: %w", err)
	}

	R := new(edwards25519.Point).ScalarBaseMult(r)
	A := new(edwards25519.Point).ScalarBaseMult(ss.inner)

	hram := sha512.Sum512(
		append(append(R.Bytes(), A.Bytes()...), p.Encode()...),
	)

	ch, err := edwards25519.NewScalar().SetUniformBytes(hram[:])
	if err != nil {
		return nil, err
	}

	cx := new(edwards25519.Scalar).Multiply(ch, ss.inner)
	sigS := new(edwards25519.Scalar).Add(r, cx)
	return append(R.Bytes(), sigS.Bytes()...), nil
}

func (c *CurveImpl) Verify(pubkey, msgPoint Point, sig []byte) bool {
	pp, ok := pubkey.(*PointImpl)
	if !ok {
		panic("invalid point; type is not *ed25519.PointImpl")
	}

	var RBytes [32]byte
	copy(RBytes[:], sig[:32])
	var sBytes [32]byte
	copy(sBytes[:], sig[32:])

	hram := sha512.Sum512(
		append(append(RBytes[:], pp.inner.Bytes()...), msgPoint.Encode()...),
	)

	ch, err := edwards25519.NewScalar().SetUniformBytes(hram[:])
	if err != nil {
		return false
	}

	R, err := new(edwards25519.Point).SetBytes(RBytes[:])
	if err != nil {
		return false
	}

	s, err := new(edwards25519.Scalar).SetCanonicalBytes(sBytes[:])
	if err != nil {
		return false
	}

	res := new(edwards25519.Point).VarTimeDoubleScalarBaseMult(new(edwards25519.Scalar).Negate(ch), pp.inner, s)
	return res.Equal(R) == 1

}

type ScalarImpl struct {
	inner *edwards25519.Scalar
}

func (s *ScalarImpl) Add(b Scalar) Scalar {
	ss, ok := b.(*ScalarImpl)
	if !ok {
		panic("invalid scalar; type is not *ed25519.ScalarImpl")
	}

	return &ScalarImpl{
		inner: new(edwards25519.Scalar).Add(s.inner, ss.inner),
	}
}

func (s *ScalarImpl) Sub(b Scalar) Scalar {
	ss, ok := b.(*ScalarImpl)
	if !ok {
		panic("invalid scalar; type is not *ed25519.ScalarImpl")
	}

	return &ScalarImpl{
		inner: new(edwards25519.Scalar).Subtract(s.inner, ss.inner),
	}
}

func (s *ScalarImpl) Negate() Scalar {
	return &ScalarImpl{
		inner: new(edwards25519.Scalar).Negate(s.inner),
	}
}

func (s *ScalarImpl) Mul(b Scalar) Scalar {
	ss, ok := b.(*ScalarImpl)
	if !ok {
		panic("invalid scalar; type is not *ed25519.ScalarImpl")
	}

	return &ScalarImpl{
		inner: new(edwards25519.Scalar).Multiply(s.inner, ss.inner),
	}
}

func (s *ScalarImpl) Inverse() Scalar {
	return &ScalarImpl{
		inner: new(edwards25519.Scalar).Invert(s.inner),
	}
}

func (s *ScalarImpl) Encode() []byte {
	return s.inner.Bytes()
}

func (s *ScalarImpl) Eq(b Scalar) bool {
	ss, ok := b.(*ScalarImpl)
	if !ok {
		panic("invalid scalar; type is not *ed25519.ScalarImpl")
	}
	return s.inner.Equal(ss.inner) == 1
}

func (s *ScalarImpl) IsZero() bool {
	return s.inner.Equal(new(edwards25519.Scalar)) == 1
}

type PointImpl struct {
	inner *edwards25519.Point
}

func (p *PointImpl) Copy() Point {
	return &PointImpl{
		inner: new(edwards25519.Point).Set(p.inner),
	}
}

func (p *PointImpl) Add(b Point) Point {
	pp, ok := b.(*PointImpl)
	if !ok {
		panic("invalid point; type is not *ed25519.PointImpl")
	}

	return &PointImpl{
		inner: new(edwards25519.Point).Add(p.inner, pp.inner),
	}
}

func (p *PointImpl) Sub(b Point) Point {
	pp, ok := b.(*PointImpl)
	if !ok {
		panic("invalid point; type is not *ed25519.PointImpl")
	}

	return &PointImpl{
		inner: new(edwards25519.Point).Subtract(p.inner, pp.inner),
	}
}

func (p *PointImpl) ScalarMul(s Scalar) Point {
	ss, ok := s.(*ScalarImpl)
	if !ok {
		panic("invalid scalar; type is not *ed25519.ScalarImpl")
	}

	return &PointImpl{
		inner: new(edwards25519.Point).ScalarMult(ss.inner, p.inner),
	}
}

func (p *PointImpl) Encode() []byte {
	return p.inner.Bytes()
}

func (p *PointImpl) IsZero() bool {
	var zero [32]byte
	zp, err := new(edwards25519.Point).SetBytes(zero[:])
	if err != nil {
		panic(err)
	}
	return p.inner.Equal(zp) == 1
}

func (p *PointImpl) Equals(other Point) bool {
	pp, ok := other.(*PointImpl)
	if !ok {
		panic("invalid point; type is not *ed25519.PointImpl")
	}

	return p.inner.Equal(pp.inner) == 1
}
