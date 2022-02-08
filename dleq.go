package dleq

import (
	"crypto/rand"
)

type Proof struct {
}

type Scalar interface{}
type Point interface{}

type Curve interface {
	BitSize() uint64
	NewScalar() Scalar
	NewPoint() Point
	HashToCurve([]byte) Point
	ScalarBaseMul(Scalar) Point
	ScalarMul(Scalar, Point) Point
}

func NewProof(curveA, curveB Curve) (*Proof, error) {
	bits := min(curveA.BitSize(), curveB.BitSize())

	// generate secret
	x := make([]byte, 32)
	_, err := rand.Read(x)
	if err != nil {
		return nil, err
	}

	toClear := 256 - bits
	x[31] &= 0xff >> toClear

	commitmentsA, err := generateCommitments(curveA, x, bits)
	if err != nil {
		return nil, err
	}

	_ = commitmentsA
	return nil, err
}

func generateCommitments(curve Curve, x []byte, bits uint64) ([]Commitments, error) {
	return []Commitments{}, nil
}

type Commitments struct {
	blindingKey        [32]byte
	commitmentMinusOne Point
	commitment         Point
}

func min(a, b uint64) uint64 {
	if a < b {
		return a
	}

	return b
}
