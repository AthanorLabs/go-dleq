package secp256k1

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/noot/go-dleq/types"
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
	one := new(secp256k1.ModNScalar)
	one.SetInt(1)

	point := new(secp256k1.JacobianPoint)
	secp256k1.ScalarBaseMultNonConst(one, point)
	point.ToAffine()
	return &PointImpl{
		inner: point,
	}
}

func (*CurveImpl) AltBasePoint() Point {
	const str = "0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
	b, err := hex.DecodeString(str)
	if err != nil {
		panic(err)
	}

	pub, err := secp256k1.ParsePubKey(b)
	if err != nil {
		panic(err)
	}

	point := new(secp256k1.JacobianPoint)
	pub.AsJacobian(point)
	point.ToAffine()
	return &PointImpl{
		inner: point,
	}
}

func (c *CurveImpl) NewRandomScalar() Scalar {
	var b [32]byte
	_, err := rand.Read(b[:])
	if err != nil {
		panic(err)
	}

	s := new(secp256k1.ModNScalar)
	s.SetBytes(&b)
	return &ScalarImpl{
		inner: s,
	}
}

func reverse(in [32]byte) [32]byte {
	rs := [32]byte{}
	for i := 0; i < 32; i++ {
		rs[i] = in[32-i-1]
	}
	return rs
}

// ScalarFromBytes sets a Scalar from LE bytes.
func (c *CurveImpl) ScalarFromBytes(b [32]byte) Scalar {
	s := new(secp256k1.ModNScalar)
	// reverse bytes, since SetBytes takes BE bytes
	in := reverse(b)
	s.SetBytes(&in)
	return &ScalarImpl{
		inner: s,
	}
}

func (c *CurveImpl) ScalarFrom(in uint32) Scalar {
	s := new(secp256k1.ModNScalar)
	s.SetInt(in)
	return &ScalarImpl{
		inner: s,
	}
}

func (c *CurveImpl) HashToScalar(in []byte) (Scalar, error) {
	h := sha3.Sum256(in)
	s := new(secp256k1.ModNScalar)
	_ = s.SetBytes(&h)
	return &ScalarImpl{
		inner: s,
	}, nil
}

func (c *CurveImpl) ScalarBaseMul(s Scalar) Point {
	ss, ok := s.(*ScalarImpl)
	if !ok {
		panic("invalid scalar; type is not *secp256k1.ScalarImpl")
	}

	point := new(secp256k1.JacobianPoint)
	secp256k1.ScalarBaseMultNonConst(ss.inner, point)
	point.ToAffine()
	return &PointImpl{
		inner: point,
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

	point := new(secp256k1.JacobianPoint)
	secp256k1.ScalarMultNonConst(ss.inner, pp.inner, point)
	point.ToAffine()
	return &PointImpl{
		inner: point,
	}
}

// Sign accepts a private key `s` and signs the encoded point `p`.
func (c *CurveImpl) Sign(s Scalar, p Point) ([]byte, error) {
	ss, ok := s.(*ScalarImpl)
	if !ok {
		panic("invalid scalar; type is not *secp256k1.ScalarImpl")
	}

	sk := secp256k1.NewPrivateKey(ss.inner)
	key := sk.ToECDSA()
	msg, err := p.Encode()
	if err != nil {
		return nil, err
	}

	hash := sha256.Sum256(msg)
	return ecdsa.SignASN1(rand.Reader, key, hash[:])
}

func (c *CurveImpl) Verify(pubkey, msgPoint Point, sig []byte) bool {
	pp, ok := pubkey.(*PointImpl)
	if !ok {
		panic("invalid point; type is not *secp256k1.PointImpl")
	}

	pp.inner.ToAffine()
	pub := secp256k1.NewPublicKey(&pp.inner.X, &pp.inner.Y)

	msg, err := msgPoint.Encode()
	if err != nil {
		return false
	}

	hash := sha256.Sum256(msg)
	return ecdsa.VerifyASN1(pub.ToECDSA(), hash[:], sig)
}

type ScalarImpl struct {
	inner *secp256k1.ModNScalar
}

func (s *ScalarImpl) Add(b Scalar) Scalar {
	ss, ok := b.(*ScalarImpl)
	if !ok {
		panic("invalid scalar; type is not *secp256k1.ScalarImpl")
	}

	r := new(secp256k1.ModNScalar).Set(s.inner).Add(ss.inner)
	return &ScalarImpl{
		inner: r,
	}
}

func (s *ScalarImpl) Sub(b Scalar) Scalar {
	ss, ok := b.(*ScalarImpl)
	if !ok {
		panic("invalid scalar; type is not *secp256k1.ScalarImpl")
	}

	sNeg := new(secp256k1.ModNScalar)
	sNeg.NegateVal(ss.inner)

	r := new(secp256k1.ModNScalar).Set(s.inner).Add(sNeg)
	return &ScalarImpl{
		inner: r,
	}
}

func (s *ScalarImpl) Negate() Scalar {
	return &ScalarImpl{
		inner: new(secp256k1.ModNScalar).Set(s.inner).Negate(),
	}
}

func (s *ScalarImpl) Mul(b Scalar) Scalar {
	ss, ok := b.(*ScalarImpl)
	if !ok {
		panic("invalid scalar; type is not *secp256k1.ScalarImpl")
	}

	r := new(secp256k1.ModNScalar).Set(s.inner).Mul(ss.inner)
	return &ScalarImpl{
		inner: r,
	}
}

func (s *ScalarImpl) Inverse() Scalar {
	r := new(secp256k1.ModNScalar)
	r.Set(s.inner).InverseNonConst()
	return &ScalarImpl{
		inner: r,
	}
}

func (s *ScalarImpl) Encode() ([]byte, error) {
	var b [32]byte
	s.inner.PutBytes(&b)
	return b[:], nil
}

func (s *ScalarImpl) Eq(other Scalar) bool {
	o, ok := other.(*ScalarImpl)
	if !ok {
		panic("invalid scalar; type is not *secp256k1.ScalarImpl")
	}

	return s.inner.Equals(o.inner)
}

func (s *ScalarImpl) IsZero() bool {
	return s.inner.IsZero()
}

type PointImpl struct {
	inner *secp256k1.JacobianPoint
}

func (p *PointImpl) Copy() Point {
	r := new(secp256k1.JacobianPoint)
	r.Set(p.inner)
	return &PointImpl{
		inner: r,
	}
}

func (p *PointImpl) Add(b Point) Point {
	pp, ok := b.(*PointImpl)
	if !ok {
		panic("invalid point; type is not *secp256k1.PointImpl")
	}

	r := new(secp256k1.JacobianPoint)
	secp256k1.AddNonConst(p.inner, pp.inner, r)
	r.ToAffine()
	return &PointImpl{
		inner: r,
	}
}

func (p *PointImpl) Sub(b Point) Point {
	pp, ok := b.(*PointImpl)
	if !ok {
		panic("invalid point; type is not *secp256k1.PointImpl")
	}

	minusOne := new(secp256k1.ModNScalar)
	minusOne.SetInt(1)
	minusOne.Negate()
	minusP := new(secp256k1.JacobianPoint)
	secp256k1.ScalarMultNonConst(minusOne, pp.inner, minusP)

	r := new(secp256k1.JacobianPoint)
	secp256k1.AddNonConst(p.inner, minusP, r)
	r.ToAffine()
	return &PointImpl{
		inner: r,
	}
}

func (p *PointImpl) ScalarMul(s Scalar) Point {
	ss, ok := s.(*ScalarImpl)
	if !ok {
		panic("invalid scalar; type is not *secp256k1.ScalarImpl")
	}

	r := new(secp256k1.JacobianPoint)
	secp256k1.ScalarMultNonConst(ss.inner, p.inner, r)
	r.ToAffine()
	return &PointImpl{
		inner: r,
	}
}

func (p *PointImpl) Encode() ([]byte, error) {
	p.inner.ToAffine()
	return secp256k1.NewPublicKey(&p.inner.X, &p.inner.Y).SerializeCompressed(), nil
}

func (p *PointImpl) IsZero() bool {
	zeroFieldVal := new(secp256k1.FieldVal).SetInt(0)
	zero := secp256k1.NewPublicKey(zeroFieldVal, zeroFieldVal)

	p.inner.ToAffine()
	pub := secp256k1.NewPublicKey(&p.inner.X, &p.inner.Y)
	return pub.IsEqual(zero)
}

func (p *PointImpl) Equals(other Point) bool {
	pp, ok := other.(*PointImpl)
	if !ok {
		panic("invalid point; type is not *secp256k1.PointImpl")
	}

	p.inner.ToAffine()
	ppub := secp256k1.NewPublicKey(&p.inner.X, &p.inner.Y)

	pp.inner.ToAffine()
	otherPub := secp256k1.NewPublicKey(&pp.inner.X, &pp.inner.Y)

	return ppub.IsEqual(otherPub)
}
