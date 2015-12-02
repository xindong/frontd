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
	_MaxOpenfile              uint64 = 1024 * 1024 * 1024
	_MaxBackendAddrCacheCount int    = 1024 * 1024
	_DefaultPort              string = "4043"
)

var (
	_SecretPassphase string
)

var (
	_BackendAddrCacheMutex = new(sync.Mutex)
	_BackendAddrCache      atomic.Value
)

type backendAddrMap map[string]string

func init() {
	_BackendAddrCache.Store(make(backendAddrMap))
}

func readBackendAddrCache(key string) (string, bool) {
	m1 := _BackendAddrCache.Load().(backendAddrMap)

	val, ok := m1[key]
	return val, ok
}

func writeBackendAddrCache(key, val string) {
	_BackendAddrCacheMutex.Lock()
	defer _BackendAddrCacheMutex.Unlock()

	m1 := _BackendAddrCache.Load().(backendAddrMap)
	m2 := make(backendAddrMap) // create a new value

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

// pipe upstream and downstream
func pipe(dst io.Writer, src io.Reader, quit chan struct{}) {
	defer func() {
		if r := recover(); r != nil {
			log.Println("Recovered in", r, ":", string(debug.Stack()))
		}
	}()
	defer func() {
		quit <- struct{}{}
	}()

	_, err := io.Copy(dst, src)
	if err != nil {
		// handle error
		log.Println(err)
	}
}

// TCPServer is handler for all tcp queries
func TCPServer(l net.Listener) {
	defer l.Close()
	for {
		// Wait for a connection.
		conn, err := l.Accept()
		if err != nil {
			log.Fatal(err)
		}
		// Handle the connection in a new goroutine.
		// The loop then returns to accepting, so that
		// multiple connections may be served concurrently.
		go func(c net.Conn) {
			defer func() {
				if r := recover(); r != nil {
					log.Println("Recovered in", r, ":", string(debug.Stack()))
				}
			}()
			defer c.Close()

			// TODO: use binary protocol if first byte is 0x00

			// Read first line
			rdr := bufio.NewReader(c)
			line, isPrefix, err := rdr.ReadLine()
			if err != nil || isPrefix {
				// handle error
				log.Println(err)
				c.Write([]byte{0x04})
				return
			}

			// Try to check cache
			addr, ok := readBackendAddrCache(string(line))
			if !ok {
				// Try to decrypt it (AES)
				o := openssl.New()
				plaintext, err := o.DecryptString(string(_SecretPassphase), string(line))
				if err != nil {
					log.Println("DecryptString", string(line), err)
					c.Write([]byte{0x06})
					return
				}
				addr = string(plaintext)
				// Write to cache
				writeBackendAddrCache(string(line), string(addr))
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
			quit := make(chan struct{})

			go pipe(c, backend, quit)
			go pipe(backend, c, quit)

			<-quit

		}(conn)
	}
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	os.Setenv("GOTRACEBACK", "crash")

	lim := syscall.Rlimit{}
	syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim)
	if lim.Cur < _MaxOpenfile || lim.Max < _MaxOpenfile {
		lim.Cur = _MaxOpenfile
		lim.Max = _MaxOpenfile
		syscall.Setrlimit(syscall.RLIMIT_NOFILE, &lim)
	}

	_SecretPassphase = os.Getenv("SECRET")

	ln, err := net.Listen("tcp", ":"+_DefaultPort)
	if err != nil {
		log.Fatal(err)
	}

	TCPServer(ln)
}
