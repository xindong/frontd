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
	"syscall"
)

const (
	// max open file should at least be
	_MaxOpenfile uint64 = 128000

	_DefaultPort = "4043"
)

func logError(v ...interface{}) {
	// TODO: log error but with a rate limit and a rate record
}

var (
	// TODO: cache with expiration
	// TODO: flush cache if it's too much
	_BackendAddrCacheMutex = new(sync.RWMutex)
	_BackendAddrCache      map[string]string
)

func readBackendAddrCache(key string) (string, bool) {
	_BackendAddrCacheMutex.RLock()
	defer _BackendAddrCacheMutex.RUnlock()

	val, ok := _BackendAddrCache[key]
	return val, ok
}

func writeBackendAddrCache(key, val string) {
	_BackendAddrCacheMutex.Lock()
	defer _BackendAddrCacheMutex.Unlock()

	_BackendAddrCache[key] = val
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
					// TODO: log error
					logError("Recovered in", r, ":", string(debug.Stack()))
				}
			}()
			defer c.Close()

			rdr := bufio.NewReader(c)
			// Read first line
			line, isPrefix, err := rdr.ReadLine()
			if err != nil || isPrefix {
				// handle error
				log.Panicln(err)
			}

			// Try to check cache
			addr, ok := readBackendAddrCache(string(line))
			if !ok {
				// TODO: Try to decrypt it

				// TODO: Write to cache

			}
			// TODO: Build tunnel

			backend, err := net.Dial("tcp", addr)
			if err != nil {
				// handle error
				log.Panicln(err)
			}

			defer backend.Close()

			// TODO: Start transfering data
			go func() {
				defer func() {
					if r := recover(); r != nil {
						// TODO: log error
						logError("Recovered in", r, ":", string(debug.Stack()))
					}
				}()

				_, err := io.Copy(c, backend)
				// handle error
				log.Panicln(err)
			}()
			_, err = io.Copy(backend, c)
			// handle error
			log.Panicln(err)

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

	ln, err := net.Listen("tcp", ":" + _DefaultPort)
	if err != nil {
		log.Fatal(err)
	}

	go TCPServer(ln)

	// TODO: Wait for exit signal
}
