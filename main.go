package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
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
	_MaxOpenfile              uint64 = 1024 * 1024
	_MaxBackendAddrCacheCount int    = 1024 * 1024
	_DefaultPort                     = "4043"
)

var (
	_SecretPassphase []byte
	_Salt            []byte
)

func logError(v ...interface{}) {
	// TODO: log error but with a rate limit and a rate record
}

var (
	// TODO: cache with expiration. maybe?
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

	// flush cache if there is way too many
	if len(_BackendAddrCache) > _MaxBackendAddrCacheCount {
		_BackendAddrCache = make(map[string]string)
	}

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
				// Try to decode it (base64)
				data, err := base64.StdEncoding.DecodeString(str)
				if err != nil {
					log.Panicln("error:", err)
					return
				}

				// Try to decrypt it (AES)
				block, err := aes.NewCipher(_SecretPassphase)
				if err != nil {
					log.Panicln("error:", err)
				}
				if len(data) < aes.BlockSize {
					log.Panicln("error:", errors.New("ciphertext too short"))
				}
				iv := data[:aes.BlockSize]
				text = data[aes.BlockSize:]
				cfb := cipher.NewCFBDecrypter(block, iv)
				cfb.XORKeyStream(text, text)

				// Check and remove the salt
				if len(text) < len(_Salt) {
					log.Panicln("error:", errors.New("salt check failed"))
				}

				addrLength := len(text) - len(_Salt)
				if text[addrLength:] != _Salt {
					log.Panicln("error:", errors.New("salt not match"))
				}

				addr = text[:addrLength]

				// Write to cache
				writeBackendAddrCache(line, addr)
			}

			// Build tunnel
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

	ln, err := net.Listen("tcp", ":"+_DefaultPort)
	if err != nil {
		log.Fatal(err)
	}

	go TCPServer(ln)

	// TODO: Wait for exit signal
}
