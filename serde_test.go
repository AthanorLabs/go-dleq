package dleq

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/noot/go-dleq/ed25519"
	"github.com/noot/go-dleq/secp256k1"
)

func TestProof_Serde(t *testing.T) {
	curveA := secp256k1.NewCurve()
	curveB := ed25519.NewCurve()
	x, err := GenerateSecretForCurves(curveA, curveB)
	require.NoError(t, err)
	proof, err := NewProof(curveA, curveB, x)
	require.NoError(t, err)
	err = proof.Verify(curveA, curveB)
	require.NoError(t, err)

	ser := proof.Serialize()
	deser := new(Proof)
	err = deser.Deserialize(curveA, curveB, ser)
	require.NoError(t, err)

	require.Equal(t, proof.CommitmentA, deser.CommitmentA)
	require.True(t, proof.CommitmentB.Equals(deser.CommitmentB))
	require.Equal(t, len(proof.proofs), len(deser.proofs))

	for i := range proof.proofs {
		require.Equal(t, proof.proofs[i].commitmentA.commitment, deser.proofs[i].commitmentA.commitment)
		require.True(t, proof.proofs[i].commitmentB.commitment.Equals(deser.proofs[i].commitmentB.commitment))
		require.Equal(t, proof.proofs[i].ringSig.eCurveA, deser.proofs[i].ringSig.eCurveA)
		require.Equal(t, proof.proofs[i].ringSig.eCurveB, deser.proofs[i].ringSig.eCurveB)
		require.Equal(t, proof.proofs[i].ringSig.a0, deser.proofs[i].ringSig.a0)
		require.Equal(t, proof.proofs[i].ringSig.a1, deser.proofs[i].ringSig.a1)
		require.Equal(t, proof.proofs[i].ringSig.b0, deser.proofs[i].ringSig.b0)
		require.Equal(t, proof.proofs[i].ringSig.b1, deser.proofs[i].ringSig.b1)
	}

	require.Equal(t, proof.signatureA, deser.signatureA)
	require.Equal(t, proof.signatureB, deser.signatureB)

	err = deser.Verify(curveA, curveB)
	require.NoError(t, err)
	t.Logf("size of serialized proof: %d bytes", len(ser))
}
