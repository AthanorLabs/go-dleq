package dleq

import (
	"crypto/rand"
)

type Proof struct {
}

type Scalar interface {
	Add(Scalar) Scalar
	Mul(Scalar) Scalar
	Inverse() Scalar
}

type Point interface {
	Add(Point) Point
	ScalarMul(Scalar) Point
}

type Curve interface {
	BitSize() uint64
	AltBasepoint() Point
	NewScalar() Scalar
	NewRandomScalar() Scalar
	ScalarFrom(uint64) Scalar
	NewPoint() Point
	HashToCurve([]byte) Point
	ScalarBaseMul(Scalar) Point
	ScalarMul(Scalar, Point) Point
}

func NewProof(curveA, curveB Curve) (*Proof, error) {
	bits := min(curveA.BitSize(), curveB.BitSize())

	// generate secret
	x, err := generateRandomBits(bits)
	if err != nil {
		return nil, err
	}

	// generate commitments for each curve
	commitmentsA, err := generateCommitments(curveA, x, bits)
	if err != nil {
		return nil, err
	}

	commitmentsB, err := generateCommitments(curveB, x, bits)
	if err != nil {
		return nil, err
	}

	_ = commitmentsA
	_ = commitmentsB
	return nil, err
}

// generate commitments to x for a curve.
// x is expressed as bits b_0 ... b_n where n == bits.
func generateCommitments(curve Curve, x []byte, bits uint64) ([]*Commitment, error) {
	// make n blinders
	blinders := make([]Scalar, bits)
	commitments := make([]*Commitment, bits)

	// get blinder at i = bits-1
	two := curve.ScalarFrom(2)
	currPowerOfTwo := curve.ScalarFrom(1)
	sum := curve.ScalarFrom(0)

	for i := uint64(0); i < bits; i++ {
		if i == bits-1 {
			// (2^(n-1))^(-1)
			currPowerOfTwoInv := currPowerOfTwo.Inverse()

			// set r_(n-1)
			blinders[i] = currPowerOfTwoInv.Mul(sum)
		} else {
			blinders[i] = curve.NewRandomScalar()

			// r_i * 2^i
			blinderTimesPowerOfTwo := blinders[i].Mul(currPowerOfTwo)

			// sum(r_i * 2^i)
			sum = sum.Add(blinderTimesPowerOfTwo)

			// set 2^(i+1) for next iteration
			currPowerOfTwo = currPowerOfTwo.Mul(two)
		}

		// generate commitment
		// b_i * G' + r_i * G
		b := curve.ScalarFrom(uint64(getBit(x, i)))
		bGp := curve.ScalarMul(b, curve.AltBasepoint())
		rG := curve.ScalarBaseMul(blinders[i])
		commitments[i] = &Commitment{
			blinder:    blinders[i],
			commitment: bGp.Add(rG),
		}
	}

	return commitments, nil
}

type Commitment struct {
	blinder    Scalar
	commitment Point
}

func min(a, b uint64) uint64 {
	if a < b {
		return a
	}

	return b
}

// generateRandomBits generates up to 256 random bits.
func generateRandomBits(bits uint64) ([]byte, error) {
	x := make([]byte, 32)
	_, err := rand.Read(x)
	if err != nil {
		return nil, err
	}

	toClear := 256 - bits
	x[31] &= 0xff >> toClear
	return x, nil
}

// getBit returns the bit at the given index (in little endian)
func getBit(x []byte, i uint64) byte {
	return (x[i/8] >> (i % 8)) & 1
}
