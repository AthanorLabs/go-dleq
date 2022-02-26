package dleq

import (
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/noot/go-dleq/types"
)

type Curve = types.Curve
type Point = types.Point
type Scalar = types.Scalar

type Proof struct {
	commitmentA, commitmentB Point
	ringSig                  *RingSignature
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
	//zero := curve.ScalarFrom(0)
	two := curve.ScalarFrom(2)
	currPowerOfTwo := curve.ScalarFrom(1)
	sum := curve.ScalarFrom(0)

	for i := uint64(0); i < bits; i++ {
		if i == bits-1 {
			// (2^(n-1))^(-1)
			currPowerOfTwoInv := currPowerOfTwo.Inverse()
			fmt.Println(currPowerOfTwo.Encode())

			// set r_(n-1)
			blinders[i] = currPowerOfTwoInv.Mul(sum)

			// sanity check - re-add later
			// lastBlinderTimesPowerOfTwo := blinders[i].Mul(currPowerOfTwo)
			// sum = sum.Add(lastBlinderTimesPowerOfTwo)
			// if !sum.IsZero() {
			// 	b, _ := sum.Encode()
			// 	fmt.Println(b)
			// 	panic("sum of blinders is not zero")
			// }
		} else {
			blinders[i] = curve.NewRandomScalar()

			// r_i * 2^i
			blinderTimesPowerOfTwo := blinders[i].Mul(currPowerOfTwo)

			// sum(r_i * 2^i)
			sum = sum.Add(blinderTimesPowerOfTwo)

			// set 2^(i+1) for next iteration
			currPowerOfTwo = currPowerOfTwo.Mul(two)
			if currPowerOfTwo.IsZero() {
				panic("power of two should not be zero")
			}
		}

		if blinders[i].IsZero() {
			panic("blinder is zero")
		}

		// generate commitment
		// b_i * G' + r_i * G
		b := curve.ScalarFrom(uint16(getBit(x, i)))
		bGp := curve.ScalarBaseMul(b) // TODO: should this actually be the normal basepoint?
		rG := curve.ScalarMul(blinders[i], curve.AltBasePoint())
		commitment := bGp.Add(rG)
		if commitment.IsZero() {
			panic("commitment should not be zero")
		}

		commitments[i] = &Commitment{
			blinder:    blinders[i],
			commitment: commitment,
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
		eCurveA1, err := hashToScalar(curveA, commitmentA.commitment, commitmentB.commitment,
			j, curveA.BasePoint(), k, curveB.BasePoint())
		if err != nil {
			return nil, err
		}

		eCurveB1, err := hashToScalar(curveB, commitmentA.commitment, commitmentB.commitment,
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

		eCurveA0, err := hashToScalar(curveA, commitmentA.commitment, commitmentB.commitment,
			A0.Sub(ecA), B0.Sub(ecB))
		if err != nil {
			return nil, err
		}

		eCurveB0, err := hashToScalar(curveB, commitmentA.commitment, commitmentB.commitment,
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

func hashToScalar(curve Curve, elements ...interface{}) (Scalar, error) {
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
