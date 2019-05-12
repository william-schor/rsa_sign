package main;

import (
	"fmt"
	"os"
	"path/filepath"
	"io/ioutil"
	"crypto"
 	"crypto/sha256"
 	"crypto/rand"
 	"crypto/rsa"
 	"encoding/pem"
 	"encoding/hex"
 	"crypto/x509"
 	"errors"
 	"strings"
)


const (
	usage = "Usage: [-c <file to check> <public key>, -getBook, -genkey, -setkey <key>, -key <temp key> <in> <out>, <in> <out>]"
	appendText = "\n\n------------------------------------------\n"
)

var addressBook = "$HOME/.keys" // This can be set at compile time
var privateKeyPath = addressBook + "/me/private.key" 
var publicKeyPath = addressBook + "/me/public.key"

func main() {

	if len(os.Args) < 2 {
		usageHandler()
	}

	mode := os.Args[1]
	in   := ""
	out  := ""

	switch mode {
	case "-c":
		if len(os.Args) < 5 {
			usageHandler() // exits
		}

		checkSign(os.Args[2], os.Args[3], os.Args[4]) 
		os.Exit(0)

	case "-key":
		if len(os.Args) < 5 {
			usageHandler() // exits
		}
		privateKeyPath = os.Args[2]
		in, _ = filepath.Abs(os.Args[3])
		out, _ = filepath.Abs(os.Args[4])
	
	case "-getBook":
		fmt.Println("Current address book:", addressBook)
		os.Exit(0)

	case "-genkey":
		genKey()
		fmt.Println("Keys generated")
		os.Exit(0)

	default:
		if len(os.Args) < 3 {
			usageHandler()
		}
		in, _ = filepath.Abs(os.Args[1])
		out, _ = filepath.Abs(os.Args[2])	
	}

	contents, err := ioutil.ReadFile(in)
	check(err)
	sum := sha256.Sum256(contents)

	privateKeyImported := readPrivateKey()
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKeyImported, crypto.SHA256, sum[:])
	check(err)

	f, errO := os.OpenFile(out, os.O_WRONLY|os.O_CREATE, 0664);
	check(errO)
	_, errW := f.Write(contents)
	_, errW = f.Write([]byte(appendText)) 
	check(errW)
	_, errW = f.Write([]byte(Encode(signature)))
	check(errW)
	_, errW = f.Write([]byte("\n")) 
	check(errW)

	f.Close()

}


func Encode(src []byte) string {
	dst := make([]byte, hex.EncodedLen(len(src)))
	hex.Encode(dst, src)

	return string(dst)

}


func Decode(str string) []byte {
	src := []byte(str)
	dst := make([]byte, hex.DecodedLen(len(src)))
	n, err := hex.Decode(dst, src)
	check(err)

	return dst[:n]
}



func usageHandler() {
	fmt.Println(usage)
	os.Exit(0)
}

func check(err error) {
	if err != nil {
		panic(err)
	}
	return
}



func checkSign(infile string, signature string, keyFile string) {
	infile, _ = filepath.Abs(infile)
	contents, err := ioutil.ReadFile(infile)
	check(err)
	contents = contents[:len(contents)-558]
	signBytes := Decode(signature)
	if keyFile[0] == '*' {
		// keyFile is a path
		keyFile, err = filepath.Abs(keyFile[1:])
		check(err)
	} else {
		files, err := ioutil.ReadDir(addressBook)
		check(err)
		
		for _, file := range files {
			
			if strings.Contains(file.Name(), keyFile) {
				keyFile = filepath.Join(addressBook, file.Name())
				break
			}
		}

	}
	publicKey := readPublicKey(keyFile)
	hashed := sha256.Sum256([]byte(contents))



	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed[:], signBytes)
	
	if err != nil {
		fmt.Println("\nVerfication Failed!\n")
		return
	}

	fmt.Println("\nSignature Verified.\n")

}


func genKey() {
	privKey, pubKey := GenerateRsaKeyPair()
	
	privKeyString := ExportRsaPrivateKeyAsPemStr(privKey)
	pubKeyString, err := ExportRsaPublicKeyAsPemStr(pubKey)
	check(err)
	
	writeTo(privateKeyPath, privKeyString)
	writeTo(publicKeyPath, pubKeyString)
	
}


func readPrivateKey() *rsa.PrivateKey {
	contents, err := ioutil.ReadFile(privateKeyPath)
	check(err)

	contentString := string(contents)

	privKey, errRSA := ParseRsaPrivateKeyFromPemStr(contentString)
	check(errRSA)

	return privKey
}

func readPublicKey(filename string) *rsa.PublicKey {
	filename, _ = filepath.Abs(filename)
	contents, err := ioutil.ReadFile(filename)
	check(err)

	contentString := string(contents)

	pubKey, errRSA := ParseRsaPublicKeyFromPemStr(contentString)
	check(errRSA)

	return pubKey
}

func GenerateRsaKeyPair() (*rsa.PrivateKey, *rsa.PublicKey) {
    privkey, _ := rsa.GenerateKey(rand.Reader, 2048)
    return privkey, &privkey.PublicKey
}

func ExportRsaPrivateKeyAsPemStr(privkey *rsa.PrivateKey) string {
    privkey_bytes := x509.MarshalPKCS1PrivateKey(privkey)
    privkey_pem := pem.EncodeToMemory(
            &pem.Block{
                    Type:  "RSA PRIVATE KEY",
                    Bytes: privkey_bytes,
            },
    )
    return string(privkey_pem)
}

func ParseRsaPrivateKeyFromPemStr(privPEM string) (*rsa.PrivateKey, error) {
    block, _ := pem.Decode([]byte(privPEM))
    if block == nil {
            return nil, errors.New("failed to parse PEM block containing the key")
    }

    priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
    if err != nil {
            return nil, err
    }

    return priv, nil
}

func ExportRsaPublicKeyAsPemStr(pubkey *rsa.PublicKey) (string, error) {
    pubkey_bytes, err := x509.MarshalPKIXPublicKey(pubkey)
    if err != nil {
            return "", err
    }
    pubkey_pem := pem.EncodeToMemory(
            &pem.Block{
                    Type:  "RSA PUBLIC KEY",
                    Bytes: pubkey_bytes,
            },
    )

    return string(pubkey_pem), nil
}

func ParseRsaPublicKeyFromPemStr(pubPEM string) (*rsa.PublicKey, error) {
    block, _ := pem.Decode([]byte(pubPEM))
    if block == nil {
            return nil, errors.New("failed to parse PEM block containing the key")
    }

    pub, err := x509.ParsePKIXPublicKey(block.Bytes)
    if err != nil {
            return nil, err
    }

    switch pub := pub.(type) {
    case *rsa.PublicKey:
            return pub, nil
    default:
            break // fall through
    }
    return nil, errors.New("Key type is not RSA")
}


func writeTo(filename string, contents string) {
	filename, _ = filepath.Abs(filename)
	f, err := os.Create(filename)
	check(err)
	_, err = f.Write([]byte(contents))
	check(err)
}







