package dleq

import (
	"errors"
	"fmt"
)

// TODO: encode curves into proof somehow?
func (p *Proof) Verify(curveA, curveB Curve) error {
	commitmentsA := make([]Commitment, len(p.proofs))
	for i := range commitmentsA {
		commitmentsA[i] = p.proofs[i].commitmentA
	}

	err := verifyCommitmentsSum(curveA, commitmentsA, p.CommitmentA)
	if err != nil {
		return fmt.Errorf("failed to verify commitment on curve A: %w", err)
	}

	commitmentsB := make([]Commitment, len(p.proofs))
	for i := range commitmentsB {
		commitmentsB[i] = p.proofs[i].commitmentB
	}

	err = verifyCommitmentsSum(curveB, commitmentsB, p.CommitmentB)
	if err != nil {
		return fmt.Errorf("failed to verify commitment on curve B: %w", err)
	}

	// now calculate challenges and verify
	bits := min(curveA.BitSize(), curveB.BitSize())
	for i := uint64(0); i < bits; i++ {
		proof := p.proofs[i]

		aG := curveA.ScalarMul(proof.ringSig.a1, curveA.AltBasePoint())
		eCA := proof.commitmentA.commitment.ScalarMul(proof.ringSig.eCurveA)

		bH := curveB.ScalarMul(proof.ringSig.b1, curveB.AltBasePoint())
		eCB := proof.commitmentB.commitment.ScalarMul(proof.ringSig.eCurveB)

		eA1, err := hashToScalar(
			curveA,
			proof.commitmentA.commitment,
			proof.commitmentB.commitment,
			aG.Sub(eCA),
			bH.Sub(eCB),
		)
		if err != nil {
			return err
		}

		eB1, err := hashToScalar(
			curveB,
			proof.commitmentA.commitment,
			proof.commitmentB.commitment,
			aG.Sub(eCA),
			bH.Sub(eCB),
		)
		if err != nil {
			return err
		}

		commitmentAMinusOne := proof.commitmentA.commitment.Sub(curveA.BasePoint())
		commitmentBMinusOne := proof.commitmentB.commitment.Sub(curveB.BasePoint())

		aG = curveA.ScalarMul(proof.ringSig.a0, curveA.AltBasePoint())
		bH = curveB.ScalarMul(proof.ringSig.b0, curveB.AltBasePoint())
		ecA := commitmentAMinusOne.ScalarMul(eA1)
		ecB := commitmentBMinusOne.ScalarMul(eB1)

		eA0, err := hashToScalar(
			curveA,
			proof.commitmentA.commitment,
			proof.commitmentB.commitment,
			aG.Sub(ecA),
			bH.Sub(ecB),
		)
		if err != nil {
			return err
		}

		eB0, err := hashToScalar(
			curveB,
			proof.commitmentA.commitment,
			proof.commitmentB.commitment,
			aG.Sub(ecA),
			bH.Sub(ecB),
		)
		if err != nil {
			return err
		}

		if !eA0.Eq(proof.ringSig.eCurveA) || !eB0.Eq(proof.ringSig.eCurveB) {
			return errors.New("invalid proof")
		}
	}

	return nil
}
