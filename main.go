package main

import (
	"bufio"
	"io"
	"log"
	"net"
	"os"
	"runtime"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/Luzifer/go-openssl"
)

const (
	// max open file should at least be
	_MaxOpenfile              = uint64(1024 * 1024 * 1024)
	_MaxBackendAddrCacheCount = 1024 * 1024
	_DefaultPort              = "4043"
	_MTU                      = 1500
)

var (
	_SecretPassphase string
	_OpenSSL         = openssl.New()
)

var (
	_BackendAddrCacheMutex sync.Mutex
	_BackendAddrCache      atomic.Value
	_BufioReaderPool       sync.Pool
)

type backendAddrMap map[string]string

func init() {
	_BackendAddrCache.Store(make(backendAddrMap))
}

func decryptBackendAddr(line []byte) (string, error) {
	// Try to check cache
	m1 := _BackendAddrCache.Load().(backendAddrMap)
	addr, ok := m1[string(line)]
	if ok {
		return addr, nil
	}
	// Try to decrypt it (AES)
	plaintext, err := _OpenSSL.DecryptString(_SecretPassphase, string(line))
	if err != nil {
		return "", err
	}
	addr = string(plaintext)
	cacheBackendAddr(string(line), addr)
	return addr, nil
}

func cacheBackendAddr(key, val string) {
	_BackendAddrCacheMutex.Lock()
	defer _BackendAddrCacheMutex.Unlock()

	m1 := _BackendAddrCache.Load().(backendAddrMap)
	// double check
	if _, ok := m1[key]; ok {
		return
	}

	m2 := make(backendAddrMap)
	// flush cache if there is way too many
	if len(m1) < _MaxBackendAddrCacheCount {
		// copy-on-write
		for k, v := range m1 {
			m2[k] = v // copy all data from the current object to the new one
		}
	}
	m2[key] = val
	_BackendAddrCache.Store(m2) // atomically replace the current object with the new one
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	os.Setenv("GOTRACEBACK", "crash")

	var lim syscall.Rlimit
	syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim)
	if lim.Cur < _MaxOpenfile || lim.Max < _MaxOpenfile {
		lim.Cur = _MaxOpenfile
		lim.Max = _MaxOpenfile
		syscall.Setrlimit(syscall.RLIMIT_NOFILE, &lim)
	}

	_SecretPassphase = os.Getenv("SECRET")

	ListenAndServe()
}

func ListenAndServe() {
	l, err := net.Listen("tcp", ":"+_DefaultPort)
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()
	for {
		conn, err := l.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go handleConn(conn)
	}
}

func handleConn(c net.Conn) {
	defer func() {
		c.Close()
		if r := recover(); r != nil {
			log.Println("Recovered in", r, ":", string(debug.Stack()))
		}
	}()

	// TODO: get rid of bufio.Reader
	// TODO: use binary protocol if first byte is 0x00

	// Read first line
	rdr, ok := _BufioReaderPool.Get().(*bufio.Reader)
	if ok {
		rdr.Reset(c)
	} else {
		rdr = bufio.NewReader(c)
		defer _BufioReaderPool.Put(rdr)
	}
	line, isPrefix, err := rdr.ReadLine()
	if err != nil || isPrefix {
		log.Println(err)
		c.Write([]byte{0x04})
		return
	}

	// Try to check cache
	addr, err := decryptBackendAddr(line)
	if err != nil {
		c.Write([]byte{0x06})
		return
	}

	// TODO: check if addr is allowed

	// Build tunnel
	backend, err := net.Dial("tcp", addr)
	if err != nil {
		// handle error
		switch err := err.(type) {
		case net.Error:
			if err.Timeout() {
				c.Write([]byte{0x01})
				log.Println(err)
				return
			}
		}
		log.Println(err)
		c.Write([]byte{0x02})
		return
	}
	defer backend.Close()

	// Start transfering data
	go pipe(c, backend)
	pipe(backend, rdr)
}

// pipe upstream and downstream
func pipe(dst io.Writer, src io.Reader) {
	defer func() {
		if r := recover(); r != nil {
			log.Println("Recovered in", r, ":", string(debug.Stack()))
		}
	}()

	_, err := io.Copy(dst, src)

	switch err {
	case io.EOF:
		err = nil
		return
	case nil:
		return
	}
	// log.Println("pipe:", n, err)
}
