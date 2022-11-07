package types

type Curve interface {
	BitSize() uint64
	BasePoint() Point
	AltBasePoint() Point
	NewRandomScalar() Scalar
	ScalarFrom(uint16) Scalar
	HashToScalar([]byte) (Scalar, error)
	ScalarBaseMul(Scalar) Point
	ScalarMul(Scalar, Point) Point
}

type Scalar interface {
	Add(Scalar) Scalar
	Sub(Scalar) Scalar
	Mul(Scalar) Scalar
	Inverse() Scalar
	Encode() ([]byte, error)
	Eq(Scalar) bool
	IsZero() bool
}

type Point interface {
	Add(Point) Point
	Sub(Point) Point
	ScalarMul(Scalar) Point
	Encode() ([]byte, error)
	IsZero() bool
}
