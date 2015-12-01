package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"testing"

	"github.com/Luzifer/go-openssl"
)

const (
	_echoServerAddr      = "127.0.0.1:62863"
	_expectAESCiphertext = "U2FsdGVkX1+PqIIh7bvAe9ZscV5xSpTavV42LOBLlj3lNxmVh10xl2jQV6mD2KKW"
	_secret              = "p0S8rX680*48"
)

func servEcho() {
	l, err := net.Listen("tcp", _echoServerAddr)
	if err != nil {
		fmt.Println("Error listening:", err.Error())
		os.Exit(1)
	}
	// Close the listener when the application closes.
	defer l.Close()
	fmt.Println("Listening on " + _echoServerAddr)
	for {
		// Listen for an incoming connection.
		conn, err := l.Accept()
		if err != nil {
			fmt.Println("Error accepting: ", err.Error())
			os.Exit(1)
		}
		// Handle connections in a new goroutine.
		go io.Copy(conn, conn)
	}
}

func init() {
	// start echo server
	go servEcho()

	// start listen
	os.Setenv("SECRET", _secret)

	go main()
}

func TestDecryptAES(t *testing.T) {
	plaintext := _echoServerAddr

	o := openssl.New()

	dec, err := o.DecryptString(_secret, _expectAESCiphertext)
	if err != nil {
		panic(err)
	}
	if string(dec) != plaintext {
		panic(errors.New("not match"))
	}
}

func TestDecrypt(*testing.T) {
	// * test decryption
	net.Dial("tcp", "127.0.0.1:"+_DefaultPort)

	// * test decryption with extra bytes in packet and check data
}

// * benchmark 100, 1000 connect with 1k 10k 100k 1m data
// with echo server with random hanging
// * test latency
// * test throughput
// * test copy-on-write performance BackendAddrCache
// * test memory footprint
