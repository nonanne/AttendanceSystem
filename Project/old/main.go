package main

import (
	"bytes"
	"fmt"
	"math/big"
	"os"

	"old/signature/eddsa"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/backend/groth16"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
)

// EdDSA signature verification circuit
// EdDSA署名検証に必要な公開鍵、署名、メッセージ、および追加の条件を格納
type EddsaCircuit struct {
	CurveID   tedwards.ID
	PublicKey eddsa.PublicKey   `gnark:",public"`
	Signature eddsa.Signature   `gnark:",public"`
	Message   frontend.Variable `gnark:",public"`
}

// EdDSA signature verification
// eddsaCircuit 構造体に対して、署名検証回路を定義
func (circuit *EddsaCircuit) Define(api frontend.API) error {
	curve, err := twistededwards.NewEdCurve(api, circuit.CurveID)
	if err != nil {
		return err
	}

	mimc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	// verify the signature in the circuit
	eddsa.Verify(curve, circuit.Signature, circuit.Message, circuit.PublicKey, &mimc)
	// verify dynamically by using inputted message
	expectedMessage := frontend.Variable("INM440")
	api.AssertIsEqual(circuit.Message, expectedMessage)

	return nil
}

// encode the proof and public witness into a format that can be used in solidity contract
func printEthProofs(vk groth16.VerifyingKey, proof groth16.Proof, validPublicWitness witness.Witness) {
	var buf bytes.Buffer
	_proof := proof.(*groth16_bn254.Proof)
	_, err := _proof.WriteRawTo(&buf)
	if err != nil {
		panic(err)
	}
	fpSize := 4 * 8
	proofBytes := buf.Bytes()
	// keep only fpSize * 8 bytes; for now solidity contract doesn't handle the commitment part.
	proofBytes = proofBytes[:32*8]
	if len(proofBytes) != fpSize*8 {
		panic("proofBytes != fpSize*8")
	}

	// public witness to hex
	bPublicWitness, err := validPublicWitness.MarshalBinary()
	if err != nil {
		panic(err)
	}
	// that's quite dirty...
	// first 4 bytes -> nbPublic
	// next 4 bytes -> nbSecret
	// next 4 bytes -> nb elements in the vector (== nbPublic + nbSecret)
	inputBytes := bPublicWitness[12:]
	if len(inputBytes)%fr.Bytes != 0 {
		panic("inputBytes mod fr.Bytes !=0")
	}

	nbPublicInputs := vk.NbPublicWitness()
	fmt.Println("nbPublicInputs:", nbPublicInputs)

	// convert public inputs
	nbInputs := len(inputBytes) / fr.Bytes
	if nbInputs != nbPublicInputs {
		panic("nbInputs != nbPublicInputs")
	}

	//FIXME change 1 to nbPublicInputs
	var input [1]*big.Int
	for i := 0; i < nbInputs; i++ {
		var e fr.Element
		e.SetBytes(inputBytes[fr.Bytes*i : fr.Bytes*(i+1)])
		input[i] = new(big.Int)
		e.BigInt(input[i])
	}

	// solidity contract inputs
	var eth_proof [8]*big.Int

	// proof.Ar, proof.Bs, proof.Krs
	for i := 0; i < 8; i++ {
		eth_proof[i] = new(big.Int).SetBytes(proofBytes[fpSize*i : fpSize*(i+1)])
	}

	fmt.Println("Public Inputs:", input)
	fmt.Println("ProofEth:", eth_proof)
}

func main() {
	// 回路の証明と検証
	// compiles our circuit into a R1CS
	var circuit EddsaCircuit
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		panic(err)
	}
	// groth16 zkSNARK: Setup
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		panic(err)
	}

	// Write solidity smart contract into a file
	f, err := os.Create("./contract.sol")
	if err != nil {
		panic(err)
	}

	vk.ExportSolidity(f)

	// witness definition
	assignment := EddsaCircuit{
		CurveID:   tedwards.BN254,
		PublicKey: eddsa.PublicKey{},
		Signature: eddsa.Signature{},
		Message:   frontend.Variable("INM440"),
	}
	witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	publicWitness, _ := witness.Public()

	// groth16: Prove & Verify
	proof, _ := groth16.Prove(ccs, pk, witness)
	groth16.Verify(proof, vk, publicWitness)

	printEthProofs(vk, proof, publicWitness)

}
