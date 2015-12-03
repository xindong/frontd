package openssl

import (
	"bytes"
	"fmt"
	"os/exec"
	"testing"
)

func TestDecryptFromString(t *testing.T) {
	// > echo -n "hallowelt" | openssl aes-256-cbc -pass pass:z4yH36a6zerhfE5427ZV -a -salt
	// U2FsdGVkX19ZM5qQJGe/d5A/4pccgH+arBGTp+QnWPU=

	opensslEncrypted := []byte("U2FsdGVkX19ZM5qQJGe/d5A/4pccgH+arBGTp+QnWPU=")
	passphrase := []byte("z4yH36a6zerhfE5427ZV")

	o := New()

	data, err := o.DecryptString(passphrase, opensslEncrypted)

	if err != nil {
		t.Fatalf("Test errored: %s", err)
	}

	if string(data) != "hallowelt" {
		t.Errorf("Decryption output did not equal expected output.")
	}
}

func TestEncryptToDecrypt(t *testing.T) {
	plaintext := []byte("hallowelt")
	passphrase := []byte("z4yH36a6zerhfE5427ZV")

	o := New()

	enc, err := o.EncryptString(passphrase, plaintext)
	if err != nil {
		t.Fatalf("Test errored at encrypt: %s", err)
	}

	dec, err := o.DecryptString(passphrase, enc)
	if err != nil {
		t.Fatalf("Test errored at decrypt: %s", err)
	}

	if !bytes.Equal(dec, plaintext) {
		t.Errorf("Decrypted text did not match input.")
	}
}

func TestEncryptToOpenSSL(t *testing.T) {
	plaintext := []byte("hallowelt")
	passphrase := []byte("z4yH36a6zerhfE5427ZV")

	o := New()

	enc, err := o.EncryptString(passphrase, plaintext)
	if err != nil {
		t.Fatalf("Test errored at encrypt: %s", err)
	}

	// WTF? Without "echo" openssl tells us "error reading input file"
	cmd := exec.Command("/bin/bash", "-c", fmt.Sprintf("echo \"%s\" | openssl aes-256-cbc -k %s -d -a", string(enc), passphrase))

	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	err = cmd.Run()
	if err != nil {
		t.Errorf("OpenSSL errored: %s", err)
	}

	if !bytes.Equal(out.Bytes(), plaintext) {
		t.Errorf("OpenSSL output did not match input.\nOutput was: %s", out.String())
	}
}
