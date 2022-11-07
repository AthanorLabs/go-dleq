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
	commitments, err := generateCommitments(curve, x, curve.BitSize())
	require.NoError(t, err)
	require.Equal(t, int(curve.BitSize()), len(commitments))
}
