package main;

import (
	"fmt"
	"os"
	"path/filepath"
	"io"
	"io/ioutil"
	"crypto"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/rand"
	"crypto/rsa"
	"crypto/aes"
	"encoding/pem"
	"encoding/hex"
	"crypto/x509"
	"errors"
	"flag"
	"bytes"
)


const (
	usage = "Usage: [-c <file to check> <public key>, -getBook, -genkey, -setkey <key>, -key <temp key> <in> <out>, -E <public key> <infile> <outfile>, -d <in> <out>, <in> <out>]"
	titleBar = "\n\n------------------------------------------\n"
)

var addressBook = "$HOME/.keys" // This can be set at compile time
var myPrivateKey = filepath.Join(addressBook, "me/private.key") 
var myPublicKey = filepath.Join(addressBook, "me/public.key")
func main() {

	keyPtr := flag.String("key", "PATH TO KEY", "Usage: sign -key <temp private key> <file to sign> <outfile>")
	cPtr := flag.Bool("c", false, "Usage: sign -c <file to check> <public key>")
	dPtr := flag.Bool("d", false, "Usage: sign -d <file to decrypt> <outfile>")

	EPtr := flag.String("E", "NAME OF RECIPIENT", "Usage: sign -E <name of recipient> <file to sign and encrypt> <outfile>")

	getBookPtr := flag.Bool("getBook", false, "Usage: sign -getBook (prints current filepath of address book.")
	genkeyPtr := flag.Bool("genkey", false, "Usage: sign -genkey (generates an RSA key pair to addrBook/me/(public || private).key")
	
	flag.Parse()

	tail := flag.Args()
	vec := []bool{*cPtr, *getBookPtr, *genkeyPtr, *dPtr}

	if !sum(vec) {
		usageHandler()
		// exits
	}

	var in string
	var out string
	var encryptionKeyPath string
	encrypt := false
	found := false

	if *cPtr {
		checkSign(tail[0], tail[1], tail[2])
		os.Exit(0)

	} else if *getBookPtr {
		fmt.Println("The current address book is:", addressBook)
		os.Exit(0)

	} else if *genkeyPtr {
		genRSAKey()
		fmt.Println("Keys generated.")
		os.Exit(0)
	} else if *dPtr {
		if len(tail) != 3 {
			usageHandler()
		}
		in, _ = filepath.Abs(tail[0])
		keyCipher := tail[1]
		out, _ = filepath.Abs(tail[2])
		decryptionRunner(in, out, keyCipher)
		os.Exit(0)
	}

	if *keyPtr != "PATH TO KEY" {
		if *EPtr != "NAME OF RECIPIENT" {
			usageHandler()
		}

		myPrivateKey, _ = filepath.Abs(*keyPtr)
	}

	if *EPtr != "NAME OF RECIPIENT" {
		if *keyPtr != "PATH TO KEY" {
			usageHandler()
		}

		if len(tail) != 2 {
			usageHandler()
		}
		keyAsFullPath, _ := filepath.Abs(*EPtr)
		if !exists(keyAsFullPath){
			found, encryptionKeyPath = searchName(*EPtr)
			if !found {
				fmt.Println("Name not found in address book.")
				os.Exit(0)
			}
		} else {
			encryptionKeyPath = keyAsFullPath
		}

		in, _ = filepath.Abs(tail[0])
		out, _ = filepath.Abs(tail[1])
		encrypt = true

	} else {
		in, _ = filepath.Abs(tail[0])
		out, _ = filepath.Abs(tail[1])
	}

	contents, err := ioutil.ReadFile(in)
	check(err)
	sum := sha256.Sum256(contents)

	privateKeyImported := readPrivateKey()
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKeyImported, crypto.SHA256, sum[:])
	check(err)

	totalContents := concatAppend(contents, []byte(titleBar), []byte(Encode(signature)), []byte("\n"))
	// encrypt, if need be
	var keyCipher []byte
	var symmetricKey []byte

	if encrypt {
		symmetricKey, keyCipher = genSymKey(encryptionKeyPath)
		totalContents = encryptSymmetric(totalContents, symmetricKey)
	}

	f, errO := os.OpenFile(out, os.O_WRONLY|os.O_CREATE, 0664);
	check(errO)
	
	var errW error
	if encrypt {
		_, errW = f.Write([]byte(titleBar))
		check(errW)	
		_, errW = f.Write([]byte(Encode(totalContents)))
		check(errW)
		_, errW = f.Write([]byte(titleBar))
		check(errW)
		_, errW = f.Write([]byte(Encode(keyCipher)))
		check(errW)
		_, errW = f.Write([]byte("\n"))
		check(errW)
	} else {
		_, errW = f.Write([]byte(string(totalContents)))
		check(errW)
	}

	f.Close()
}


func decryptionRunner(in string, out string, keyCipher string) {
	
	contents, err := ioutil.ReadFile(in)
	check(err)

	contents = Decode(string(contents[45:len(contents)-558]))
	keyBytes := Decode(keyCipher)

	recoveredKey := decryptRSA(keyBytes, myPrivateKey)

	plaintext := decryptSymmetric(contents, recoveredKey)
	

	f, errO := os.OpenFile(out, os.O_WRONLY|os.O_CREATE, 0664);
	check(errO)
	_, errW := f.Write(plaintext)
	check(errW)
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func sum(v []bool) bool {
	x := b2i(v[0])
	for _, s :=range v[1:] {
		x += b2i(s)
	}
	return x < 2
}

func concatAppend(slices... []byte) []byte {
    var tmp []byte
    for _, s := range slices {
        tmp = append(tmp, s...)
    }
    return tmp
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

func exists(path string) bool {
    _, err := os.Stat(path)
    return err == nil
}

func searchName(keyFile string) (bool, string) {
	files, err := ioutil.ReadDir(addressBook)
	check(err)
		
	for _, file := range files {
		index := len(file.Name()) - 4
		if index < 1 {
			continue
		}
		if keyFile == file.Name()[:index] {
			keyFile = filepath.Join(addressBook, file.Name())
			return true, keyFile
		}
	}

	return false, ""
}

func checkSign(infile string, signature string, keyFile string) {

	contents, err := ioutil.ReadFile(infile)
	check(err)
	contents = contents[:len(contents)-558]
	signBytes := Decode(signature)
	found := false

	keyAsPath, _ := filepath.Abs(keyFile)

	if !exists(keyAsPath) {
		found, keyFile = searchName(keyFile)
		if !found {
			fmt.Println("Name not found in address book.")
			return 
		}
	} else {
		keyFile = keyAsPath
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


func genRSAKey() {
	privKey, pubKey := GenerateRsaKeyPair()
	
	privKeyString := ExportRsaPrivateKeyAsPemStr(privKey)
	pubKeyString, err := ExportRsaPublicKeyAsPemStr(pubKey)
	check(err)
	
	writeTo(myPrivateKey, privKeyString)
	writeTo(myPublicKey, pubKeyString)	
}


func readPrivateKey() *rsa.PrivateKey {
	contents, err := ioutil.ReadFile(myPrivateKey)
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

func encryptRSA(plaintext []byte, key_full_path string) []byte {
	//get the public key of the Recipient
	key := readPublicKey(key_full_path)
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, key, plaintext, nil)
	check(err)
	return ciphertext
}

func decryptRSA(ciphertext []byte, key_full_path string) []byte {
	key := readPrivateKey()
	plaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, key, ciphertext, nil)
	check(err)
	return plaintext
}

func encryptSymmetric(plaintext []byte, symmetricKey []byte) []byte {
	block, err := aes.NewCipher(symmetricKey)
	check(err)

	plaintext = PKCS5Padding(plaintext, aes.BlockSize)

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	_, err = io.ReadFull(rand.Reader, iv)
	check(err)

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)

	return ciphertext
}

func decryptSymmetric(ciphertext []byte, symmetricKey[]byte) []byte {
	
	block, err := aes.NewCipher(symmetricKey)
	check(err)

	if len(ciphertext) < aes.BlockSize {
		panic("Ciphertext too short. Must include initalization vector.")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	if len(ciphertext)%aes.BlockSize != 0 {
		panic("Ciphertext is not a multiple of the block size.")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	// decrypts in place
	mode.CryptBlocks(ciphertext, ciphertext)
	plaintext := PKCS5Trimming(ciphertext)
	
	return plaintext
}

func genSymKey(publicKeyFile string) ([]byte, []byte) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	check(err)
	keyCipher := encryptRSA(key, publicKeyFile)

	return key, keyCipher
}

func PKCS5Padding(text []byte, blockSize int) []byte {
	padding := blockSize - len(text)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(text, padtext...)
}

func PKCS5Trimming(text []byte) []byte {
	padding := text[len(text)-1]
	return text[:len(text)-int(padding)]
}




