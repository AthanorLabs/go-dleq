package secp256k1

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/big"

	"github.com/athanorlabs/go-dleq/types"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"golang.org/x/crypto/sha3"
)

type Curve = types.Curve
type Point = types.Point
type Scalar = types.Scalar

var _ Curve = &CurveImpl{}
var _ Scalar = &ScalarImpl{}
var _ Point = &PointImpl{}

type CurveImpl struct {
	order        *big.Int
	basePoint    Point
	altBasePoint Point
}

func NewCurve() Curve {
	orderBytes, err := hex.DecodeString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
	if err != nil {
		panic(err)
	}

	return &CurveImpl{
		order:        new(big.Int).SetBytes(orderBytes),
		basePoint:    basePoint(),
		altBasePoint: altBasePoint(),
	}
}

func basePoint() Point {
	one := new(secp256k1.ModNScalar)
	one.SetInt(1)

	point := new(secp256k1.JacobianPoint)
	secp256k1.ScalarBaseMultNonConst(one, point)
	point.ToAffine()
	return &PointImpl{
		inner: point,
	}
}

func altBasePoint() Point {
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

func (*CurveImpl) BitSize() uint64 {
	return 255
}

func (*CurveImpl) CompressedPointSize() int {
	return 33
}

func (*CurveImpl) DecodeToPoint(in []byte) (Point, error) {
	cp := make([]byte, len(in))
	copy(cp, in)
	pub, err := secp256k1.ParsePubKey(cp)
	if err != nil {
		return nil, err
	}

	r := new(secp256k1.JacobianPoint)
	pub.AsJacobian(r)
	r.ToAffine()
	return &PointImpl{
		inner: r,
	}, nil
}

func (*CurveImpl) DecodeToScalar(in []byte) (Scalar, error) {
	if len(in) != 32 {
		return nil, errors.New("invalid scalar length")
	}

	cp := make([]byte, len(in))
	copy(cp, in)
	s := new(secp256k1.ModNScalar)
	_ = s.SetByteSlice(cp)
	return &ScalarImpl{
		inner: s,
	}, nil
}

func (c *CurveImpl) BasePoint() Point {
	return c.basePoint
}

func (c *CurveImpl) AltBasePoint() Point {
	return c.altBasePoint
}

func (*CurveImpl) NewRandomScalar() Scalar {
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
func (*CurveImpl) ScalarFromBytes(b [32]byte) Scalar {
	s := new(secp256k1.ModNScalar)
	// reverse bytes, since SetBytes takes BE bytes
	in := reverse(b)
	s.SetBytes(&in)
	return &ScalarImpl{
		inner: s,
	}
}

func (*CurveImpl) ScalarFromInt(in uint32) Scalar {
	s := new(secp256k1.ModNScalar)
	s.SetInt(in)
	return &ScalarImpl{
		inner: s,
	}
}

func (c *CurveImpl) HashToScalar(in []byte) (Scalar, error) {
	h := sha3.Sum512(in)
	n := new(big.Int).SetBytes(h[:])
	n = new(big.Int).Mod(n, c.order)
	var reduced [32]byte
	copy(reduced[:], n.Bytes())

	s := new(secp256k1.ModNScalar)
	wasReduced := s.SetBytes(&reduced)
	if wasReduced != 0 {
		panic("hash should not be reduced twice")
	}

	return &ScalarImpl{
		inner: s,
	}, nil
}

func (*CurveImpl) ScalarBaseMul(s Scalar) Point {
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

func (*CurveImpl) ScalarMul(s Scalar, p Point) Point {
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
func (*CurveImpl) Sign(s Scalar, p Point) ([]byte, error) {
	ss, ok := s.(*ScalarImpl)
	if !ok {
		panic("invalid scalar; type is not *secp256k1.ScalarImpl")
	}

	sk := secp256k1.NewPrivateKey(ss.inner)
	key := sk.ToECDSA()
	msg := p.Encode()
	hash := sha256.Sum256(msg)
	return ecdsa.SignASN1(rand.Reader, key, hash[:])
}

func (*CurveImpl) Verify(pubkey, msgPoint Point, sig []byte) bool {
	pp, ok := pubkey.(*PointImpl)
	if !ok {
		panic("invalid point; type is not *secp256k1.PointImpl")
	}

	pp.inner.ToAffine()
	pub := secp256k1.NewPublicKey(&pp.inner.X, &pp.inner.Y)

	msg := msgPoint.Encode()
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

func (s *ScalarImpl) Encode() []byte {
	var b [32]byte
	s.inner.PutBytes(&b)
	return b[:]
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

func (p *PointImpl) Encode() []byte {
	p.inner.ToAffine()
	return secp256k1.NewPublicKey(&p.inner.X, &p.inner.Y).SerializeCompressed()
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
