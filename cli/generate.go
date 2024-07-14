package main

import (
	"encoding/base64"
	"fmt"
	"github.com/cloudflare/circl/kem/schemes"
	"io/ioutil"
	"os"
)

func SaveKeyToFile(filename string, key []byte) error {
	return ioutil.WriteFile(filename, key, 0644)
}

func main() {
	meth := "Kyber512-X25519" // Kyber768-X448 Kyber1024-X448

	argCount := len(os.Args[1:])

	if argCount > 0 {
		meth = os.Args[1]
	}

	scheme := schemes.ByName(meth)

	pk, sk, err := scheme.GenerateKeyPair()
	if err != nil {
		fmt.Printf("Error generating key pair: %v\n", err)
		return
	}

	// Save keys to files
	ppk, err := pk.MarshalBinary()
	if err != nil {
		fmt.Printf("Error marshalling public key: %v\n", err)
		return
	}

	psk, err := sk.MarshalBinary()
	if err != nil {
		fmt.Printf("Error marshalling private key: %v\n", err)
		return
	}

	strPPK := base64.StdEncoding.EncodeToString(ppk)
	err = SaveKeyToFile("public.key", []byte(strPPK))
	if err != nil {
		fmt.Printf("Error saving public key to file: %v\n", err)
		return
	}

	strPSK := base64.StdEncoding.EncodeToString(psk)
	err = SaveKeyToFile("private.key", []byte(strPSK))
	if err != nil {
		fmt.Printf("Error saving private key to file: %v\n", err)
		return
	}

	fmt.Printf("\nMethod: %s \n", meth)
	fmt.Printf("Public Key (pk) = %X (first 32 bytes)\n", ppk[:32])
	fmt.Printf("Private key (sk) = %X (first 32 bytes)\n", psk[:32])

	fmt.Printf("\n\nLength of Public Key (pk) = %d bytes \n", len(ppk))
	fmt.Printf("Length of Secret Key (sk)  = %d  bytes\n", len(psk))
}
