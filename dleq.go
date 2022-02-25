package dleq

import (
	"crypto/rand"
	"errors"
)

type Proof struct {
}

type Scalar interface {
	Add(Scalar) Scalar
	Mul(Scalar) Scalar
	Inverse() Scalar
	Encode() ([]byte, error)
	Eq(Scalar) bool
}

type Point interface {
	Add(Point) Point
	Sub(Point) Point
	ScalarMul(Scalar) Point
	Encode() ([]byte, error)
}

type Curve interface {
	BitSize() uint64
	BasePoint() Point
	AltBasePoint() Point
	NewRandomScalar() Scalar
	ScalarFrom(uint64) Scalar
	HashToScalar([]byte) (Scalar, error)
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

type Commitment struct {
	blinder    Scalar
	commitment Point
}

// generate commitments to x for a curve.
// x is expressed as bits b_0 ... b_n where n == bits.
func generateCommitments(curve Curve, x []byte, bits uint64) ([]*Commitment, error) {
	// make n blinders
	blinders := make([]Scalar, bits)
	commitments := make([]*Commitment, bits)

	// get blinder at i = bits-1
	zero := curve.ScalarFrom(0)
	two := curve.ScalarFrom(2)
	currPowerOfTwo := curve.ScalarFrom(1)
	sum := curve.ScalarFrom(0)

	for i := uint64(0); i < bits; i++ {
		if i == bits-1 {
			// (2^(n-1))^(-1)
			currPowerOfTwoInv := currPowerOfTwo.Inverse()

			// set r_(n-1)
			blinders[i] = currPowerOfTwoInv.Mul(sum)

			sum = sum.Add(blinders[i])
			if !sum.Eq(zero) {
				panic("sum of blinders is not zero")
			}
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
		bGp := curve.ScalarBaseMul(b) // TODO: should this actually be the normal basepoint?
		rG := curve.ScalarMul(blinders[i], curve.AltBasePoint())
		commitments[i] = &Commitment{
			blinder:    blinders[i],
			commitment: bGp.Add(rG),
		}
	}

	return commitments, nil
}

type RingSignature struct {
	eCurveA, eCurveB Scalar
	a0, a1           Scalar
	b0, b1           Scalar
}

func generateRingSignatures(curveA, curveB Curve, x byte, commitmentA, commitmentB Commitment) (*RingSignature, error) {
	j, k := curveA.NewRandomScalar(), curveB.NewRandomScalar()

	switch x {
	case 0:
		eCurveA1, err := hashToCurve(curveA, commitmentA.commitment, commitmentB.commitment,
			j, curveA.BasePoint(), k, curveB.BasePoint())
		if err != nil {
			return nil, err
		}

		eCurveB1, err := hashToCurve(curveB, commitmentA.commitment, commitmentB.commitment,
			j, curveA.BasePoint(), k, curveB.BasePoint())
		if err != nil {
			return nil, err
		}

		a0, b0 := curveA.NewRandomScalar(), curveB.NewRandomScalar()

		commitmentAMinusOne := commitmentA.commitment.Sub(curveA.BasePoint())
		commitmentBMinusOne := commitmentB.commitment.Sub(curveB.BasePoint())

		ecA := commitmentAMinusOne.ScalarMul(eCurveA1)
		ecB := commitmentBMinusOne.ScalarMul(eCurveB1)
		A0 := curveA.ScalarMul(a0, curveA.AltBasePoint())
		B0 := curveB.ScalarMul(b0, curveB.AltBasePoint())

		eCurveA0, err := hashToCurve(curveA, commitmentA.commitment, commitmentB.commitment,
			A0.Sub(ecA), B0.Sub(ecB))
		if err != nil {
			return nil, err
		}

		eCurveB0, err := hashToCurve(curveB, commitmentA.commitment, commitmentB.commitment,
			A0.Sub(ecA), B0.Sub(ecB))
		if err != nil {
			return nil, err
		}

		a1 := j.Add(eCurveA0.Mul(commitmentA.blinder))
		b1 := k.Add(eCurveB0.Mul(commitmentB.blinder))
		return &RingSignature{
			eCurveA: eCurveA0,
			eCurveB: eCurveB0,
			a0:      a0,
			a1:      a1,
			b0:      b0,
			b1:      b1,
		}, nil
	case 1:
		return nil, nil
	default:
		return nil, errors.New("input byte must be 0 or 1")
	}
}

func hashToCurve(curve Curve, elements ...interface{}) (Scalar, error) {
	preimage := []byte{}

	for _, e := range elements {
		switch el := e.(type) {
		case Scalar:
			b, err := el.Encode()
			if err != nil {
				return nil, err
			}

			preimage = append(preimage, b...)
		case Point:
			b, err := el.Encode()
			if err != nil {
				return nil, err
			}

			preimage = append(preimage, b...)
		default:
			return nil, errors.New("input element must be scalar or point")
		}
	}

	return curve.HashToScalar(preimage)
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
