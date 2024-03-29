package types

type Curve interface {
	BitSize() uint64
	CompressedPointSize() int
	BasePoint() Point
	AltBasePoint() Point
	NewRandomScalar() Scalar
	ScalarFromInt(uint32) Scalar
	ScalarFromBytes([32]byte) Scalar
	HashToScalar([]byte) (Scalar, error)
	ScalarBaseMul(Scalar) Point
	ScalarMul(Scalar, Point) Point
	Sign(s Scalar, p Point) ([]byte, error)
	Verify(pubkey, msgPoint Point, sig []byte) bool

	// the following two functions MUST copy the byte slice
	// before decoding.
	DecodeToPoint([]byte) (Point, error)
	DecodeToScalar([]byte) (Scalar, error)
}

type Scalar interface {
	Add(Scalar) Scalar
	Sub(Scalar) Scalar
	Negate() Scalar
	Mul(Scalar) Scalar
	Inverse() Scalar
	Encode() []byte
	Eq(Scalar) bool
	IsZero() bool
}

type Point interface {
	Copy() Point
	Add(Point) Point
	Sub(Point) Point
	ScalarMul(Scalar) Point
	Encode() []byte
	IsZero() bool
	Equals(other Point) bool
}
