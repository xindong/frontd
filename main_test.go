package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/xindong/frontd/aes256cbc"
	"github.com/xindong/frontd/reuse"
)

var (
	_echoServerAddr      = []byte("127.0.0.1:62863")
	_httpServerAddr      = []byte("127.0.0.1:62865")
	_expectAESCiphertext = []byte("U2FsdGVkX19KIJ9OQJKT/yHGMrS+5SsBAAjetomptQ0=")
	_secret              = []byte("p0S8rX680*48")
	_defaultFrontdAddr   = "127.0.0.1:" + strconv.Itoa(_DefaultPort)
)

var (
	// use -reuse with go test enable SO_REUSEPORT
	// go test -parallel 6553 -benchtime 60s -bench BenchmarkEchoParallel -reuse
	// but it seems will not working with single backend addr because of
	// http://stackoverflow.com/questions/14388706/socket-options-so-reuseaddr-and-so-reuseport-how-do-they-differ-do-they-mean-t
	reuseTest = flag.Bool("reuse", false, "test reuseport dialer")
)

func TestMain(m *testing.M) {
	flag.Parse()
	if *reuseTest {
		fmt.Println("testing SO_REUSEPORT")
	}

	// start echo server
	go servEcho()

	// start listen
	os.Setenv("SECRET", string(_secret))

	go main()

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
		if len(r.Header["X-Forwarded-For"]) > 0 {
			w.Write([]byte(r.Header["X-Forwarded-For"][0]))
		}
	})
	go http.ListenAndServe(string(_httpServerAddr), nil)

	rand.Seed(time.Now().UnixNano())

	// TODO: better way to wait for server to start
	time.Sleep(time.Second)
	os.Exit(m.Run())
}

func servEcho() {
	l, err := net.Listen("tcp", string(_echoServerAddr))
	if err != nil {
		fmt.Println("Error listening:", err.Error())
		os.Exit(1)
	}
	// Close the listener when the application closes.
	defer l.Close()
	fmt.Println("Listening on " + string(_echoServerAddr))
	for {
		// Listen for an incoming connection.
		c, err := l.Accept()
		if err != nil {
			fmt.Println("Error accepting: ", err.Error())
			os.Exit(1)
		}
		// Handle connections in a new goroutine.
		go func(c net.Conn) {
			defer c.Close()

			_, err := io.Copy(c, c)
			switch err {
			case io.EOF:
				err = nil
				return
			case nil:
				return
			}
			panic(err)
		}(c)
	}
}

func encryptText(plaintext, passphrase []byte) ([]byte, error) {
	o := aes256cbc.New()

	return o.Encrypt(passphrase, plaintext)
}

func randomBytes(n int) []byte {

	b := make([]byte, n)
	// A src.Int63() generates 63 random bits, enough for letterIdxMax characters!
	for i := 0; i < n; i++ {
		b[i] = byte(rand.Int())
	}

	return b
}

func testEchoRound(conn net.Conn) {
	conn.SetDeadline(time.Now().Add(time.Second * 10))

	n := rand.Int()%2048 + 10
	out := randomBytes(n)
	n0, err := conn.Write(out)
	if err != nil {
		panic(err)
	}

	rcv := make([]byte, n)
	n1, err := io.ReadFull(conn, rcv)
	if err != nil && err != io.EOF {
		panic(err)
	}
	if !bytes.Equal(out[:n0], rcv[:n1]) {
		fmt.Println("out: ", n0, "in:", n1)

		fmt.Println("out: ", hex.EncodeToString(out), "in:", hex.EncodeToString(rcv))
		panic(errors.New("echo server reply is not match"))
	}
}

func testProtocol(cipherAddr []byte) {
	// * test decryption
	var conn net.Conn
	var err error
	if *reuseTest {
		conn, err = reuseport.Dial("tcp", "127.0.0.1:0", _defaultFrontdAddr)
	} else {
		conn, err = net.Dial("tcp", _defaultFrontdAddr)
	}

	if err != nil {
		panic(err)
	}
	defer conn.Close()

	_, err = conn.Write(cipherAddr)
	if err != nil {
		panic(err)
	}

	_, err = conn.Write([]byte("\n"))
	if err != nil {
		panic(err)
	}

	for i := 0; i < 5; i++ {
		testEchoRound(conn)
	}
}

func TestHTTPServer(t *testing.T) {
	cipherAddr, err := encryptText(_httpServerAddr, _secret)
	if err != nil {
		panic(err)
	}

	client := &http.Client{}
	req, _ := http.NewRequest("GET", "http://"+string(_defaultFrontdAddr), nil)
	req.Header.Set(string(_cipherRequestHeader), string(cipherAddr))
	req.Header.Set("X-Forwarded-For", "8.8.8.8, 8.8.4.4")
	res, err := client.Do(req)
	if err != nil {
		panic(err)
	}

	b, err := ioutil.ReadAll(res.Body)
	if err != nil {
		panic(err)
	}

	if !bytes.HasPrefix(b, []byte("OK127.0.0.1")) {
		t.Fail()
	}
}

func TestTextDecryptAES(t *testing.T) {
	o := aes256cbc.New()

	dec, err := o.Decrypt(_secret, _expectAESCiphertext)
	if err != nil {
		panic(err)
	}
	if !bytes.Equal(dec, _echoServerAddr) {
		panic(errors.New("not match"))
	}
}

func TestEchoServer(t *testing.T) {
	var conn net.Conn
	var err error
	if *reuseTest {
		conn, err = reuseport.Dial("tcp", "127.0.0.1:0", string(_echoServerAddr))
	} else {
		conn, err = net.Dial("tcp", string(_echoServerAddr))
	}
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	n := rand.Int() % 10
	for i := 0; i < n; i++ {
		testEchoRound(conn)
	}
}

func TestProtocolDecrypt(*testing.T) {
	b, err := encryptText(_echoServerAddr, _secret)
	if err != nil {
		panic(err)
	}
	testProtocol(b)
}

// TODO: more test with and with out x-forwarded-for

// TODO: test decryption with extra bytes in packet and check data

// TODO: test decryption with seperated packet simulate loss connection and check data

// TODO: benchmark 100, 1000 connect with 1k 10k 100k 1m data

func BenchmarkEncryptText(b *testing.B) {
	s1 := randomBytes(255)
	s2 := randomBytes(32)
	for i := 0; i < b.N; i++ {
		_, err := encryptText(s1, s2)
		if err != nil {
			panic(err)
		}
	}
}

func BenchmarkDecryptText(b *testing.B) {
	for i := 0; i < b.N; i++ {
		o := aes256cbc.New()
		_, err := o.Decrypt(_secret, _expectAESCiphertext)
		if err != nil {
			panic(err)
		}
	}
}

func BenchmarkEcho(b *testing.B) {
	for i := 0; i < b.N; i++ {
		TestEchoServer(&testing.T{})
	}
}

func BenchmarkLatency(b *testing.B) {
	cipherAddr, err := encryptText(_echoServerAddr, _secret)
	if err != nil {
		panic(err)
	}

	for i := 0; i < b.N; i++ {
		testProtocol(cipherAddr)
	}
}

func BenchmarkNoHitLatency(b *testing.B) {
	for i := 0; i < b.N; i++ {
		TestProtocolDecrypt(&testing.T{})
	}
}

func BenchmarkEchoParallel(b *testing.B) {

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			TestEchoServer(&testing.T{})
		}
	})
}

func BenchmarkLatencyParallel(b *testing.B) {
	cipherAddr, err := encryptText(_echoServerAddr, _secret)
	if err != nil {
		panic(err)
	}
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			testProtocol(cipherAddr)
		}
	})
}

func BenchmarkNoHitLatencyParallel(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			TestProtocolDecrypt(&testing.T{})
		}
	})
}

// with echo server with random hanging
// * benchmark latency
// * benchmark throughput
// * benchmark copy-on-write performance BackendAddrCache
// * benchmark memory footprint
