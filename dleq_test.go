package dleq

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/noot/go-dleq/secp256k1"
)

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
	curve := secp256k1.NewCurve()
	proof, err := NewProof(curve, curve)
	require.NoError(t, err)
	err = proof.Verify(curve, curve)
	require.NoError(t, err)
}
