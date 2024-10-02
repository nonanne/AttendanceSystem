package main

/*
#include <stdlib.h>
*/
import "C"
import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"time"
	"unsafe"

	"PROJECT/gnark/signature"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	crypto_tedwards "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/backend/groth16"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	gnark_tedwards "github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
)

// EdDSA signature verification circuit
type EddsaCircuit struct {
	PublicKey gnark_tedwards.Point `gnark:",public"`
	Signature signature.Signature  `gnark:",public"`
	Message   frontend.Variable    `gnark:",public"`
}

// Define the circuit's constraints
func (circuit *EddsaCircuit) Define(api frontend.API) error {
	// cast the public key to the twisted Edwards curve
	curve, err := gnark_tedwards.NewEdCurve(api, twistededwards.BN254)
	if err != nil {
		// error: initializing curve failed
		return fmt.Errorf("Error: initializing curve: %v", err)
	}

	// hash function MiMC
	mimcHash, err := mimc.NewMiMC(api)
	if err != nil {
		// error: initializing MiMC hash failed
		return fmt.Errorf("Error: initializing MiMC hash: %v", err)
	}

	// convert the public key to the gnark twisted Edwards curve
	publicKey := signature.PublicKey{
		A: circuit.PublicKey, // use the public key from the circuit
	}

	// veri
	signature.Verify(curve, circuit.Signature, circuit.Message, publicKey, &mimcHash)

	return nil
}

//export GenerateProofFromGo
func GenerateProofFromGo(publicKeyHex *C.char, signatureHex *C.char, message *C.char) *C.char {
	// convert C strings to Go strings
	pubKeyStr := C.GoString(publicKeyHex)
	sigStr := C.GoString(signatureHex)
	msgStr := C.GoString(message)

	// decode the public key, signature, and message from hex
	publicKeyBytes, err := hex.DecodeString(pubKeyStr)
	if err != nil {
		// error handling: decoding public key hex failed
		return C.CString(fmt.Sprintf("Error: decoding public key hex: %v", err))
	}
	signatureBytes, err := hex.DecodeString(sigStr)
	if err != nil {
		// error handling: decoding signature hex failed
		return C.CString(fmt.Sprintf("Error: decoding signature hex: %v", err))
	}
	messageBytes := []byte(msgStr)

	// rebuild the public key
	var pkAffine crypto_tedwards.PointAffine
	_, err = pkAffine.SetBytes(publicKeyBytes)
	if err != nil {
		// error handling: reconstructing public key failed
		return C.CString(fmt.Sprintf("Error: reconstructing public key: %v", err))
	}

	// convert the public key to the gnark twisted Edwards curve
	publicKey := gnark_tedwards.Point{
		X: pkAffine.X,
		Y: pkAffine.Y,
	}

	// rebuild the signature
	var RAffine crypto_tedwards.PointAffine
	_, err = RAffine.SetBytes(signatureBytes[:32])
	if err != nil {
		// error handling: reconstructing signature R failed
		return C.CString(fmt.Sprintf("Error: reconstructing signature R: %v", err))
	}
	R := gnark_tedwards.Point{
		X: RAffine.X,
		Y: RAffine.Y,
	}
	S := new(big.Int).SetBytes(signatureBytes[32:])

	sig := signature.Signature{
		R: R,
		S: S,
	}

	// generate the proof and verification key using the public key, signature, and message
	proof, vk, publicWitness, err := GenerateProof(publicKey, sig, messageBytes)
	if err != nil {
		// error handling: generating proof failed
		return C.CString(fmt.Sprintf("Error: generating proof: %v", err))
	}
	// print proof, vk, publicWitness
	fmt.Printf("main.go Proof: %+v\n", proof)
	fmt.Printf("main.go Verifying Key (vk): %+v\n", vk)
	fmt.Printf("main.go Public Witness: %+v\n", publicWitness)
	// get eth_proof and input from verification
	eth_proof, input, err := verification(proof, vk, publicWitness)
	if err != nil {
		// error handling: verification failed
		return C.CString(fmt.Sprintf("Error: in verification: %v", err))
	}

	// convert eth_proof and input to strings
	ethProofStrings := make([]string, len(eth_proof))
	for i, bigIntVal := range eth_proof {
		ethProofStrings[i] = bigIntVal.String()
	}

	inputStrings := make([]string, len(input))
	for i, bigIntVal := range input {
		inputStrings[i] = bigIntVal.String()
	}

	// map eth_proof and input to a JSON object
	data := map[string]interface{}{
		"eth_proof": ethProofStrings,
		"input":     inputStrings,
	}

	// serialize the JSON object to a string
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		// error handling: serializing data failed
		return C.CString(fmt.Sprintf("Error: serializing data: %v", err))
	}

	// return the JSON string
	return C.CString(string(jsonBytes))
}

// GenerateProof generates a Groth16 proof and verification key for the EdDSA signature verification circuit
func GenerateProof(publicKey gnark_tedwards.Point, sig signature.Signature, message []byte) (groth16.Proof, groth16.VerifyingKey, witness.Witness, error) {
	startTime := time.Now()
	// Define the circuit
	var circuit EddsaCircuit

	// Compile the circuit
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		// Error: compiling circuit
		return nil, nil, nil, fmt.Errorf("Error: compiling circuit: %v", err)
	}

	// Groth16 setup
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		// Error: Groth16 setup
		return nil, nil, nil, fmt.Errorf("Error: during Groth16 setup: %v", err)
	}

	// Create the witness
	assignment := EddsaCircuit{
		PublicKey: publicKey,
		Signature: sig,
		Message:   message,
	}

	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		// Error: creating witness
		return nil, nil, nil, fmt.Errorf("Error: creating witness: %v", err)
	}

	publicWitness, err := witness.Public()
	if err != nil {
		// error: creating public witness
		return nil, nil, nil, fmt.Errorf("Error: creating public witness: %v", err)
	}
	// create the Solidity contract file for the verification key
	f, err := os.Create("./contract.sol")
	if err != nil {
		// Error: creating Solidity contract file
		return nil, nil, nil, fmt.Errorf("Error: creating Solidity contract file: %v", err)

	}
	defer f.Close()

	vk.ExportSolidity(f)
	fmt.Println("Verification key exported to Solidity contract.sol")

	// Generate the proof
	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		// Error: generating Groth16 proof
		return nil, nil, nil, fmt.Errorf("Error: generating Groth16 proof: %v", err)

	}
	// mesure time elapsed for proof generation
	elapsedTime := time.Since(startTime)
	fmt.Printf("Proof generation took %s\n", elapsedTime)

	return proof, vk, publicWitness, nil
}

// Free the allocated memory
//
//export FreeMemory
func FreeMemory(pointer unsafe.Pointer) {
	C.free(pointer)
}

// Helper function to extract eth_proof and input
func printEthProofs(vk groth16.VerifyingKey, proof groth16.Proof, validPublicWitness witness.Witness) ([]*big.Int, [8]*big.Int) {
	var buf bytes.Buffer
	_proof := proof.(*groth16_bn254.Proof)
	_, err := _proof.WriteRawTo(&buf)
	if err != nil {
		// error: writing proof to buffer
		panic(fmt.Errorf("Error: writing proof to buffer: %v", err))
	}
	fpSize := 4 * 8
	proofBytes := buf.Bytes()
	// keep only fpSize * 8 bytes; for now solidity contract doesn't handle the commitment part.
	proofBytes = proofBytes[:32*8]
	if len(proofBytes) != fpSize*8 {
		// error: proofBytes != fpSize*8
		panic("proofBytes != fpSize*8")
	}

	// public witness to hex
	bPublicWitness, err := validPublicWitness.MarshalBinary()
	if err != nil {
		// error: marshalling public witness
		panic(fmt.Errorf("Error: marshalling public witness: %v", err))
	}
	// public witness to hex
	inputBytes := bPublicWitness[12:]
	if len(inputBytes)%fr.Bytes != 0 {
		// error: inputBytes mod fr.Bytes !=0
		panic("inputBytes mod fr.Bytes !=0")
	}

	nbPublicInputs := vk.NbPublicWitness()
	fmt.Println("nbPublicInputs:", nbPublicInputs)

	// convert public inputs
	nbInputs := len(inputBytes) / fr.Bytes
	if nbInputs != nbPublicInputs {
		// error: nbInputs != nbPublicInputs
		panic("nbInputs != nbPublicInputs")
	}

	//FIXME change 1 to nbPublicInputs
	input := make([]*big.Int, nbInputs)
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

	fmt.Println("Main.go: Public Inputs:", input)
	fmt.Println("Main.go: ProofEth:", eth_proof)

	// return input and eth_proof
	return input, eth_proof
}

// verification function to verify the proof and return eth_proof and input for the Solidity contract
func verification(proof groth16.Proof, vk groth16.VerifyingKey, publicWitness witness.Witness) ([8]*big.Int, []*big.Int, error) {
	// verify the proof
	err := groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		// error: proof verification failed
		fmt.Println("Error: Proof verification failed:", err)
	} else {
		fmt.Println("Proof successfully verified!")
	}
	// get eth_proof and input from verification
	input, eth_proof := printEthProofs(vk, proof, publicWitness)

	// return eth_proof and input
	return eth_proof, input, nil
}

func main() {}
