package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/schemes"
	"golang.org/x/crypto/hkdf"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	_ "os"
)

func ReadKeyFromFile(filename string) ([]byte, error) {
	buff, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", filename, err)
	}
	return buff, nil
}

type EncryptRequest struct {
	Plaintext string `json:"plaintext"`
}

type EncryptResponse struct {
	Ciphertext string `json:"ciphertext"`
}

type DecryptRequest struct {
	Ciphertext string `json:"ciphertext"`
}

type DecryptResponse struct {
	Plaintext string `json:"plaintext"`
}

var scheme = schemes.ByName("Kyber512-X25519")
var pk kem.PublicKey
var sk kem.PrivateKey

func encryptHandler(w http.ResponseWriter, r *http.Request) {
	var req EncryptRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Encrypt the plaintext
	ciphertext, ss, err := scheme.Encapsulate(pk)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Derive a symmetric key from the shared secret
	key, err := deriveKey(ss, scheme.SharedKeySize()) // 32 bytes for AES-256
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	ciphertextSymmetric := gcm.Seal(nonce, nonce, []byte(req.Plaintext), nil)
	fullCiphertext := append(ciphertext, ciphertextSymmetric...)

	resp := EncryptResponse{
		Ciphertext: base64.StdEncoding.EncodeToString(fullCiphertext),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func decryptHandler(w http.ResponseWriter, r *http.Request) {
	var req DecryptRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Decode the base64 ciphertext
	fullCiphertext, err := base64.StdEncoding.DecodeString(req.Ciphertext)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Extract the encapsulated key part
	ciphertext := fullCiphertext[:scheme.CiphertextSize()]
	ciphertextSymmetric := fullCiphertext[scheme.CiphertextSize():]

	// Decrypt the ciphertext to get the shared secret
	sharedSecret, err := scheme.Decapsulate(sk, ciphertext)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Derive a symmetric key from the shared secret
	key, err := deriveKey(sharedSecret, 32) // 32 bytes for AES-256
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertextSymmetric) < nonceSize {
		http.Error(w, "ciphertext too short", http.StatusInternalServerError)
		return
	}

	nonce, ciphertextSymmetric := ciphertextSymmetric[:nonceSize], ciphertextSymmetric[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertextSymmetric, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	resp := DecryptResponse{
		Plaintext: string(plaintext),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func main() {
	// Load and decode public key
	pkBuff, err := ReadKeyFromFile("public.key")
	if err != nil {
		log.Fatalf("Error reading public key: %v\n", err)
	}

	pkDecode, err := base64.StdEncoding.DecodeString(string(pkBuff))
	if err != nil {
		log.Fatalf("Error decoding public key: %v\n", err)
	}

	pk, err = scheme.UnmarshalBinaryPublicKey(pkDecode)
	if err != nil {
		log.Fatalf("Error unmarshaling public key: %v\n", err)
	}

	// Load and decode private key
	skBuff, err := ReadKeyFromFile("private.key")
	if err != nil {
		log.Fatalf("Error reading private key: %v\n", err)
	}

	skDecode, err := base64.StdEncoding.DecodeString(string(skBuff))
	if err != nil {
		log.Fatalf("Error decoding private key: %v\n", err)
	}

	sk, err = scheme.UnmarshalBinaryPrivateKey(skDecode)
	if err != nil {
		log.Fatalf("Error unmarshaling private key: %v\n", err)
	}

	http.HandleFunc("/encrypt", encryptHandler)
	http.HandleFunc("/decrypt", decryptHandler)

	fmt.Println("Starting server on :4000...")
	log.Fatal(http.ListenAndServe(":4000", nil))
}

func deriveKey(sharedSecret []byte, keyLength int) ([]byte, error) {
	hkdf := hkdf.New(sha256.New, sharedSecret, nil, nil)
	key := make([]byte, keyLength)
	_, err := io.ReadFull(hkdf, key)
	if err != nil {
		return nil, err
	}
	return key, nil
}
