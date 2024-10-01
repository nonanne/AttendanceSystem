package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	// library for EdDSA signature generation
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
	"github.com/consensys/gnark-crypto/hash"
)

// struct for attendance data
type AttendanceData struct {
	UserID string `json:"userId"`
	Date   string `json:"date"`
	Module string `json:"module"`
}

// struct for signed attendance data
type SignedAttendanceData struct {
	UserID    string `json:"userId"`
	Date      string `json:"date"`
	Module    string `json:"module"`
	PublicKey string `json:"publicKey"`
	Signature string `json:"signature"`
}

var privateKey *eddsa.PrivateKey

// initialize: EdDSA key pair generation
func init() {
	var err error
	privateKey, err = eddsa.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("Error: Failed to generate EdDSA key: %v", err)
	}
	publicKey := privateKey.Public()
	fmt.Printf("Private Key: %x\n", privateKey.Bytes())
	fmt.Printf("Public Key: %x\n", publicKey.Bytes())
}

// main function
func main() {
	http.HandleFunc("/sign-attendance", generateSignatureMessage)
	log.Println("Attendance Monitor Server started at :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

// generateSignatureMessage: POST /sign-attendance
func generateSignatureMessage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		// error handling: reading request body failed
		http.Error(w, "Error: reading request body", http.StatusInternalServerError)
		return
	}

	var attendanceData AttendanceData
	err = json.Unmarshal(body, &attendanceData)
	if err != nil {
		// error handling: JSON parsing error
		http.Error(w, "Error: parsing JSON", http.StatusBadRequest)
		return
	}

	fmt.Printf("Received UserID: %s, Date: %s, Module: %s\n", attendanceData.UserID, attendanceData.Date, attendanceData.Module)

	_, err = time.Parse("20060102", attendanceData.Date)
	if err != nil {
		// error handling: invalid date format
		http.Error(w, "Error: Invalid date format. Use YYYYMMDD", http.StatusBadRequest)
		return
	}

	// signed message = date + userID + module
	message := []byte(fmt.Sprintf("%s%s%s",
		attendanceData.Date, attendanceData.UserID, attendanceData.Module))
	// select hash function for EdDSA signature generation (MIMC_BN254)
	h := hash.MIMC_BN254.New()

	// time measurement: EdDSA signature generation
	startTime := time.Now()
	// generate EdDSA signature for the message
	signature, err := privateKey.Sign(message, h)
	if err != nil {
		// error handling: EdDSA signature generation failed
		http.Error(w, "Error: signing the message", http.StatusInternalServerError)
		return
	}
	// time measurement: elapsed time
	elapsed := time.Since(startTime)
	fmt.Printf("Time: EdDSA signature generation took %s\n", elapsed)

	signedData := SignedAttendanceData{
		UserID:    attendanceData.UserID,
		Date:      attendanceData.Date,
		Module:    attendanceData.Module,
		PublicKey: fmt.Sprintf("%x", privateKey.Public().Bytes()),
		Signature: fmt.Sprintf("%x", signature),
	}

	fmt.Printf("Signed Data:\n")
	fmt.Printf("  UserID: %s\n", signedData.UserID)
	fmt.Printf("  Date: %s\n", signedData.Date)
	fmt.Printf("  Module: %s\n", signedData.Module)
	fmt.Printf("  PublicKey: %s\n", signedData.PublicKey)
	fmt.Printf("  Signature: %s\n", signedData.Signature)

	// error handling: JSON encoding error
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(signedData); err != nil {
		http.Error(w, "Error: encoding JSON response", http.StatusInternalServerError)
	}
}
