# go-dleq

This repo contains an implementation of cross-group discrete logarithm equality as specified in [MRL-0010](https://www.getmonero.org/resources/research-lab/pubs/MRL-0010.pdf). In addition to what's specified in the paper, it contains an additional proof of knowledge of the witness ie. a signature on both curves. Currently, secp256k1 and ed25519 are supported. The library is written such that other curves can be added.

## Usage
```go
import (
	"github.com/noot/go-dleq"
    "github.com/noot/go-dleq/ed25519"
	"github.com/noot/go-dleq/secp256k1"
)

curveA := secp256k1.NewCurve()
curveB := ed25519.NewCurve()
x, err := dleq.GenerateSecretForCurves(curveA, curveB)
if err != nil {
    panic(err)
}

proof, err := dleq.NewProof(curveA, curveB, x)
if err != nil {
    panic(err)
}

err = proof.Verify(curveA, curveB)
if err != nil {
    panic(err)
}
```