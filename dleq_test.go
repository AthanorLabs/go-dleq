package dleq

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/athanorlabs/go-dleq/ed25519"
	"github.com/athanorlabs/go-dleq/secp256k1"
)

func TestWitnessSize(t *testing.T) {
	curveA := secp256k1.NewCurve()
	curveB := ed25519.NewCurve()
	x, err := GenerateSecretForCurves(curveA, curveB)
	require.NoError(t, err)
	err = checkWitnessSize(x, min(curveA.BitSize(), curveB.BitSize()))
	require.NoError(t, err)

	x = [32]byte{}
	x[31] = 0xff
	err = checkWitnessSize(x, 255)
	require.Error(t, err)

	x = [32]byte{}
	x[30] = 0xff
	err = checkWitnessSize(x, 247)
	require.Error(t, err)

	x = [32]byte{}
	x[30] = 0b00010101
	err = checkWitnessSize(x, 244)
	require.Error(t, err)
	err = checkWitnessSize(x, 245)
	require.NoError(t, err)
}

func TestGenerateCommitments(t *testing.T) {
	curve := secp256k1.NewCurve()
	x, err := generateRandomBits(curve.BitSize())
	require.NoError(t, err)
	commitments, err := generateCommitments(curve, x[:], curve.BitSize())
	require.NoError(t, err)
	require.Equal(t, int(curve.BitSize()), len(commitments))

	X := curve.ScalarBaseMul(curve.ScalarFromBytes(x))
	err = verifyCommitmentsSum(curve, commitments, X)
	require.NoError(t, err)
}

func TestGenerateRingSignature(t *testing.T) {
	curve := secp256k1.NewCurve()
	x, err := generateRandomBits(curve.BitSize())
	require.NoError(t, err)
	commitmentsA, err := generateCommitments(curve, x[:], curve.BitSize())
	require.NoError(t, err)
	require.Equal(t, int(curve.BitSize()), len(commitmentsA))
	commitmentsB, err := generateCommitments(curve, x[:], curve.BitSize())
	require.NoError(t, err)
	require.Equal(t, int(curve.BitSize()), len(commitmentsB))

	for i := 0; i < int(curve.BitSize()); i++ {
		bit := getBit(x[:], uint64(i))
		_, err := generateRingSignature(curve, curve, bit, commitmentsA[i], commitmentsB[i])
		require.NoError(t, err)
	}
}

func TestProveAndVerify(t *testing.T) {
	curveA := secp256k1.NewCurve()
	curveB := ed25519.NewCurve()
	x, err := GenerateSecretForCurves(curveA, curveB)
	require.NoError(t, err)
	proof, err := NewProof(curveA, curveB, x)
	require.NoError(t, err)
	err = proof.Verify(curveA, curveB)
	require.NoError(t, err)
}
