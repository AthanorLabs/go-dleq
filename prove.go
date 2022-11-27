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

// Proof represents a DLEq proof and commitment to the witness.
type Proof struct {
	CommitmentA, CommitmentB Point
	proofs                   []bitProof
	signatureA, signatureB   signature
}

type signature struct {
	inner []byte
}

// bitProof represents the proof for 1 bit of the witness.
type bitProof struct {
	commitmentA, commitmentB commitment
	ringSig                  *ringSignature
}

type commitment struct {
	blinder    Scalar
	commitment Point
}

type ringSignature struct {
	eCurveA, eCurveB Scalar
	a0, a1           Scalar
	b0, b1           Scalar
}

// GenerateSecretForCurves generates a secret value that has a corresponding
// commitment on both curves.
func GenerateSecretForCurves(curveA, curveB Curve) ([32]byte, error) {
	bits := min(curveA.BitSize(), curveB.BitSize())
	return generateRandomBits(bits)
}

// NewProof returns a new proof for the given secret on the given curves.
func NewProof(curveA, curveB Curve, x [32]byte) (*Proof, error) {
	bits := min(curveA.BitSize(), curveB.BitSize())

	xA := curveA.ScalarFromBytes(x)
	xB := curveB.ScalarFromBytes(x)
	XA := curveA.ScalarBaseMul(xA)
	XB := curveB.ScalarBaseMul(xB)

	// generate commitments for each curve
	commitmentsA, err := generateCommitments(curveA, x[:], bits)
	if err != nil {
		return nil, err
	}

	err = verifyCommitmentsSum(curveA, commitmentsA, XA)
	if err != nil {
		return nil, err
	}

	commitmentsB, err := generateCommitments(curveB, x[:], bits)
	if err != nil {
		return nil, err
	}

	err = verifyCommitmentsSum(curveB, commitmentsB, XB)
	if err != nil {
		return nil, err
	}

	proofs := make([]bitProof, bits)

	for i := 0; i < int(bits); i++ {
		bit := getBit(x[:], uint64(i))
		ringSig, err := generateRingSignature(curveA, curveB, bit, commitmentsA[i], commitmentsB[i])
		if err != nil {
			return nil, err
		}

		proofs[i] = bitProof{
			commitmentA: commitmentsA[i],
			commitmentB: commitmentsB[i],
			ringSig:     ringSig,
		}
	}

	sigA, err := curveA.Sign(xA, XA)
	if err != nil {
		return nil, err
	}

	sigB, err := curveB.Sign(xB, XB)
	if err != nil {
		return nil, err
	}

	return &Proof{
		CommitmentA: XA,
		CommitmentB: XB,
		proofs:      proofs,
		signatureA: signature{
			sigA,
		},
		signatureB: signature{
			sigB,
		},
	}, nil
}

// verifyCommitmentsSum verifies that all the commitments sum to the given point.
func verifyCommitmentsSum(curve Curve, commitments []commitment, point Point) error {
	sum := commitments[0].commitment.Copy()

	two := curve.ScalarFrom(2)
	currPowerOfTwo := curve.ScalarFrom(2)

	for _, c := range commitments[1:] {
		sum = sum.Add(c.commitment.ScalarMul(currPowerOfTwo))
		currPowerOfTwo = currPowerOfTwo.Mul(two)
	}

	if sum.Equals(point) {
		return nil
	}

	return errors.New("commitments do not sum to given point")
}

// generate commitments to x for a curve.
// x is expressed as bits b_0 ... b_n where n == bits.
func generateCommitments(curve Curve, x []byte, bits uint64) ([]commitment, error) {
	// make n blinders
	blinders := make([]Scalar, bits)
	commitments := make([]commitment, bits)

	two := curve.ScalarFrom(2)
	currPowerOfTwo := curve.ScalarFrom(1)

	sum := curve.ScalarFrom(0)

	for i := uint64(0); i < bits; i++ {
		if i == bits-1 {
			// (2^(n-1))^(-1)
			currPowerOfTwoInv := currPowerOfTwo.Inverse()

			// set r_(n-1)
			blinders[i] = sum.Negate().Mul(currPowerOfTwoInv)

			// sanity check
			lastBlinderTimesPowerOfTwo := blinders[i].Mul(currPowerOfTwo)
			sum = sum.Add(lastBlinderTimesPowerOfTwo)
			if !sum.IsZero() {
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
			if currPowerOfTwo.IsZero() {
				panic("power of two should not be zero")
			}
		}

		if blinders[i].IsZero() {
			panic(fmt.Sprintf("blinder %d is zero", i))
		}

		// generate commitment
		// b_i * G' + r_i * G
		b := curve.ScalarFrom(uint32(getBit(x, i)))
		bG := curve.ScalarBaseMul(b)
		rG := curve.ScalarMul(blinders[i], curve.AltBasePoint())
		c := bG.Add(rG)
		if c.IsZero() {
			panic("commitment should not be zero")
		}

		// sanity check, can remove later
		if getBit(x, i) == 0 {
			if !c.Equals(rG) {
				panic("commitment should be rG if bit isn't set")
			}
		}

		commitments[i] = commitment{
			blinder:    blinders[i],
			commitment: c,
		}
	}

	return commitments, nil
}

func generateRingSignature(
	curveA, curveB Curve,
	x byte,
	commitmentA, commitmentB commitment,
) (*ringSignature, error) {
	j, k := curveA.NewRandomScalar(), curveB.NewRandomScalar()

	eA, err := hashToScalar(
		curveA,
		commitmentA.commitment,
		commitmentB.commitment,
		curveA.ScalarMul(j, curveA.AltBasePoint()),
		curveB.ScalarMul(k, curveB.AltBasePoint()),
	)
	if err != nil {
		return nil, err
	}

	eB, err := hashToScalar(
		curveB,
		commitmentA.commitment,
		commitmentB.commitment,
		curveA.ScalarMul(j, curveA.AltBasePoint()),
		curveB.ScalarMul(k, curveB.AltBasePoint()),
	)
	if err != nil {
		return nil, err
	}

	switch x {
	case 0:
		a0, b0 := curveA.NewRandomScalar(), curveB.NewRandomScalar()

		commitmentAMinusOne := commitmentA.commitment.Sub(curveA.BasePoint())
		commitmentBMinusOne := commitmentB.commitment.Sub(curveB.BasePoint())

		ecA := commitmentAMinusOne.ScalarMul(eA)
		ecB := commitmentBMinusOne.ScalarMul(eB)
		A0 := curveA.ScalarMul(a0, curveA.AltBasePoint())
		B0 := curveB.ScalarMul(b0, curveB.AltBasePoint())

		eA0, err := hashToScalar(curveA, commitmentA.commitment, commitmentB.commitment,
			A0.Sub(ecA), B0.Sub(ecB))
		if err != nil {
			return nil, err
		}

		eB0, err := hashToScalar(curveB, commitmentA.commitment, commitmentB.commitment,
			A0.Sub(ecA), B0.Sub(ecB))
		if err != nil {
			return nil, err
		}

		a1 := j.Add(eA0.Mul(commitmentA.blinder))
		b1 := k.Add(eB0.Mul(commitmentB.blinder))
		return &ringSignature{
			eCurveA: eA0,
			eCurveB: eB0,
			a0:      a0,
			a1:      a1,
			b0:      b0,
			b1:      b1,
		}, nil
	case 1:
		a1, b1 := curveA.NewRandomScalar(), curveB.NewRandomScalar()

		ecA := commitmentA.commitment.ScalarMul(eA)
		ecB := commitmentB.commitment.ScalarMul(eB)
		A0 := curveA.ScalarMul(a1, curveA.AltBasePoint())
		B0 := curveB.ScalarMul(b1, curveB.AltBasePoint())

		eA1, err := hashToScalar(curveA, commitmentA.commitment, commitmentB.commitment,
			A0.Sub(ecA), B0.Sub(ecB))
		if err != nil {
			return nil, err
		}

		eB1, err := hashToScalar(curveB, commitmentA.commitment, commitmentB.commitment,
			A0.Sub(ecA), B0.Sub(ecB))
		if err != nil {
			return nil, err
		}

		a0 := j.Add(eA1.Mul(commitmentA.blinder))
		b0 := k.Add(eB1.Mul(commitmentB.blinder))

		return &ringSignature{
			eCurveA: eA,
			eCurveB: eB,
			a0:      a0,
			a1:      a1,
			b0:      b0,
			b1:      b1,
		}, nil
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
func generateRandomBits(bits uint64) ([32]byte, error) {
	x := [32]byte{}
	_, err := rand.Read(x[:])
	if err != nil {
		return x, err
	}

	toClear := 256 - bits
	x[31] &= 0xff >> toClear
	return x, nil
}

// getBit returns the bit at the given index (in little endian)
func getBit(x []byte, i uint64) byte {
	return (x[i/8] >> (i % 8)) & 1
}
