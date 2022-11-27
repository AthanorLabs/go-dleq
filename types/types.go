package types

type Curve interface {
	BitSize() uint64
	BasePoint() Point
	AltBasePoint() Point
	NewRandomScalar() Scalar
	ScalarFrom(uint32) Scalar
	ScalarFromBytes([32]byte) Scalar
	HashToScalar([]byte) (Scalar, error)
	ScalarBaseMul(Scalar) Point
	ScalarMul(Scalar, Point) Point
	Sign(s Scalar, p Point) ([]byte, error)
	Verify(pubkey, msgPoint Point, sig []byte) bool
}

type Scalar interface {
	Add(Scalar) Scalar
	Sub(Scalar) Scalar
	Negate() Scalar
	Mul(Scalar) Scalar
	Inverse() Scalar
	Encode() ([]byte, error)
	Eq(Scalar) bool
	IsZero() bool
}

type Point interface {
	Copy() Point
	Add(Point) Point
	Sub(Point) Point
	ScalarMul(Scalar) Point
	Encode() ([]byte, error)
	IsZero() bool
	Equals(other Point) bool
}
