package dleq

import (
	"bytes"
	"errors"

	"github.com/noot/go-dleq/types"
)

var errInputBytesTooShort = errors.New("input bytes too short")

// Serialize encodes the proof.
func (p *Proof) Serialize() []byte {
	b := append(p.CommitmentA.Encode(), p.CommitmentB.Encode()...)

	// WARN: this assumes the bitlen of the witness is less than 256.
	b = append(b, byte(len(p.proofs)))
	for _, bp := range p.proofs {
		b = append(b, bp.encode()...)
	}

	// WARN: this assumes the signature length is less than 256.
	b = append(b, byte(len(p.signatureA.inner)))
	b = append(b, p.signatureA.inner...)
	b = append(b, byte(len(p.signatureB.inner)))
	b = append(b, p.signatureB.inner...)
	return b
}

func (p *bitProof) encode() []byte {
	b := append(p.commitmentA.commitment.Encode(), p.commitmentB.commitment.Encode()...)
	b = append(b, p.ringSig.eCurveA.Encode()...)
	b = append(b, p.ringSig.eCurveB.Encode()...)
	b = append(b, p.ringSig.a0.Encode()...)
	b = append(b, p.ringSig.a1.Encode()...)
	b = append(b, p.ringSig.b0.Encode()...)
	b = append(b, p.ringSig.b1.Encode()...)
	return b
}

// Deserialize decodes the proof for the given curves.
// The curves must match those passed into `NewProof`.
func (p *Proof) Deserialize(curveA, curveB types.Curve, in []byte) error {
	reader := bytes.NewBuffer(in)

	pointLenA := curveA.CompressedPointSize()
	pointLenB := curveB.CompressedPointSize()

	if len(in) < pointLenA+pointLenB {
		return errInputBytesTooShort
	}

	// WARN: this assumes the groups have an encoded scalar length of 32!
	const scalarLen = 32

	var err error
	p.CommitmentA, err = curveA.DecodeToPoint(reader.Next(pointLenA))
	if err != nil {
		return err
	}

	p.CommitmentB, err = curveB.DecodeToPoint(reader.Next(pointLenB))
	if err != nil {
		return err
	}

	if reader.Len() < 1 {
		return errInputBytesTooShort
	}
	bitProofsLen := reader.Next(1)

	// TODO put bitProofsLen + sigLens first so we know the total expected length?
	minLenRemaining := (int(bitProofsLen[0]) * (pointLenA + pointLenB + scalarLen*6))
	if reader.Len() < minLenRemaining {
		return errInputBytesTooShort
	}

	p.proofs = make([]bitProof, bitProofsLen[0])
	for i := 0; i < int(bitProofsLen[0]); i++ {
		bp := new(bitProof)
		err = bp.decode(reader, curveA, curveB, scalarLen)
		if err != nil {
			return err
		}
		p.proofs[i] = *bp
	}

	if reader.Len() < 1 {
		return errInputBytesTooShort
	}

	sigLen := reader.Next(1)
	if reader.Len() < int(sigLen[0]) {
		return errInputBytesTooShort
	}

	p.signatureA.inner = make([]byte, sigLen[0])
	copy(p.signatureA.inner, reader.Next(int(sigLen[0])))

	if reader.Len() < 1 {
		return errInputBytesTooShort
	}

	sigLen = reader.Next(1)
	if reader.Len() < int(sigLen[0]) {
		return errInputBytesTooShort
	}

	p.signatureB.inner = make([]byte, sigLen[0])
	copy(p.signatureB.inner, reader.Next(int(sigLen[0])))
	return nil
}

func (p *bitProof) decode(r *bytes.Buffer, curveA, curveB types.Curve, scalarLen int) error {
	pointLenA := curveA.CompressedPointSize()
	pointLenB := curveB.CompressedPointSize()

	var err error
	p.commitmentA.commitment, err = curveA.DecodeToPoint(r.Next(pointLenA))
	if err != nil {
		return err
	}

	p.commitmentB.commitment, err = curveB.DecodeToPoint(r.Next(pointLenB))
	if err != nil {
		return err
	}

	p.ringSig.eCurveA, err = curveA.DecodeToScalar(r.Next(scalarLen))
	if err != nil {
		return err
	}

	p.ringSig.eCurveB, err = curveB.DecodeToScalar(r.Next(scalarLen))
	if err != nil {
		return err
	}

	p.ringSig.a0, err = curveA.DecodeToScalar(r.Next(scalarLen))
	if err != nil {
		return err
	}

	p.ringSig.a1, err = curveA.DecodeToScalar(r.Next(scalarLen))
	if err != nil {
		return err
	}

	p.ringSig.b0, err = curveB.DecodeToScalar(r.Next(scalarLen))
	if err != nil {
		return err
	}

	p.ringSig.b1, err = curveB.DecodeToScalar(r.Next(scalarLen))
	if err != nil {
		return err
	}

	return nil
}
