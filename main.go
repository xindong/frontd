package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	_ "net/http/pprof"

	"github.com/xindong/frontd/aes256cbc"
)

const (
	// max open file should at least be
	_MaxOpenfile              = uint64(1024 * 1024 * 1024)
	_MaxBackendAddrCacheCount = 1024 * 1024
)

var (
	_hdrCipherOrigin   = []byte("x-cipher-origin")
	_hdrForwardedFor   = []byte("x-forwarded-for")
	_maxHTTPHeaderSize = 4096 * 2
	_minHTTPHeaderSize = 32
)

var (
	_SecretPassphase []byte
	_Aes256CBC       = aes256cbc.New()
)

var (
	_BackendAddrCacheMutex sync.Mutex
	_BackendAddrCache      atomic.Value
)

var (
	_DefaultPort        = 4043
	_BackendDialTimeout = 5
	_ConnReadTimeout    = time.Second * 30
)

type backendAddrMap map[string][]byte

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	os.Setenv("GOTRACEBACK", "crash")

	_BackendAddrCache.Store(make(backendAddrMap))

	var lim syscall.Rlimit
	syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim)
	if lim.Cur < _MaxOpenfile || lim.Max < _MaxOpenfile {
		lim.Cur = _MaxOpenfile
		lim.Max = _MaxOpenfile
		syscall.Setrlimit(syscall.RLIMIT_NOFILE, &lim)
	}

	_SecretPassphase = []byte(os.Getenv("SECRET"))

	mhs, err := strconv.Atoi(os.Getenv("MAX_HTTP_HEADER_SIZE"))
	if err == nil && mhs > _minHTTPHeaderSize {
		_maxHTTPHeaderSize = mhs
	}

	bt, err := strconv.Atoi(os.Getenv("BACKEND_TIMEOUT"))
	if err == nil && bt > 0 {
		_BackendDialTimeout = bt
	}

	connReadTimeout, err := strconv.Atoi(os.Getenv("CONN_READ_TIMEOUT"))
	if err == nil && connReadTimeout >= 0 {
		_ConnReadTimeout = time.Second * time.Duration(connReadTimeout)
	}

	listenPort, err := strconv.Atoi(os.Getenv("LISTEN_PORT"))
	if err == nil && listenPort > 0 && listenPort <= 65535 {
		_DefaultPort = listenPort
	}

	pprofPort, err := strconv.Atoi(os.Getenv("PPROF_PORT"))
	if err == nil && pprofPort > 0 && pprofPort <= 65535 {
		go func() {
			log.Println(http.ListenAndServe(":"+strconv.Itoa(pprofPort), nil))
		}()
	}

	listenAndServe()

	log.Println("Exiting")
}

func listenAndServe() {
	l, err := net.Listen("tcp", ":"+strconv.Itoa(_DefaultPort))
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()
	var tempDelay time.Duration
	for {
		conn, err := l.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}
				if max := 1 * time.Second; tempDelay > max {
					tempDelay = max
				}
				time.Sleep(tempDelay)
				continue
			}
			log.Fatal(err)
		}
		tempDelay = 0
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

	rdr := bufio.NewReader(c)

	addr, err := handleBinaryHdr(rdr, c)
	if err != nil {
		if err != io.EOF {
			log.Println("x", err)
		}
		return
	}

	var header *bytes.Buffer
	if addr == nil {
		// Read first line
		line, isPrefix, err := rdr.ReadLine()
		if err != nil || isPrefix {
			log.Println(err)
			writeErrCode(c, []byte("4104"), false)
			return
		}

		cipherAddr := line

		// check if it's HTTP request
		if bytes.Contains(line, []byte("HTTP")) {
			header = bytes.NewBuffer(line)
			header.Write([]byte("\n"))

			cipherAddr, err = handleHTTPHdr(rdr, c, header)
			if err != nil {
				log.Println(err)
				return
			}
		}

		// base64 decode
		dbuf := make([]byte, base64.StdEncoding.DecodedLen(len(cipherAddr)))
		n, err := base64.StdEncoding.Decode(dbuf, cipherAddr)
		if err != nil {
			writeErrCode(c, []byte("4106"), false)
			return
		}

		addr, err = backendAddrDecrypt(dbuf[:n])
		if err != nil {
			writeErrCode(c, []byte("4106"), false)
			return
		}
	}

	// TODO: check if addr is allowed

	// Build tunnel
	err = tunneling(string(addr), rdr, c, header)
	if err != nil {
		log.Println(err)
	}
}

func writeErrCode(c net.Conn, errCode []byte, httpws bool) {
	switch httpws {
	case true:
		fmt.Fprintf(c, "HTTP/1.1 %s Error\nConnection: Close", errCode)
	default:
		c.Write(errCode)
	}
}

func handleBinaryHdr(rdr *bufio.Reader, c net.Conn) (addr []byte, err error) {
	// use binary protocol if first byte is 0x00
	b, err := rdr.ReadByte()
	if err != nil {
		// TODO: how to cause error to test this?
		writeErrCode(c, []byte("4103"), false)
		return nil, err
	}
	if b == byte(0x00) {
		// binary protocol
		blen, err := rdr.ReadByte()
		if err != nil || blen == 0 {
			writeErrCode(c, []byte("4103"), false)
			return nil, err
		}
		p := make([]byte, blen)
		n, err := io.ReadFull(rdr, p)
		if n != int(blen) {
			// TODO: how to cause error to test this?
			writeErrCode(c, []byte("4109"), false)
			return nil, err
		}

		// decrypt
		addr, err := backendAddrDecrypt(p)
		if err != nil {
			writeErrCode(c, []byte("4106"), false)
			return nil, err
		}

		return addr, err
	}

	rdr.UnreadByte()
	return nil, nil
}

func handleHTTPHdr(rdr *bufio.Reader, c net.Conn, header *bytes.Buffer) (addr []byte, err error) {
	hdrXff := "X-Forwarded-For: " + ipAddrFromRemoteAddr(c.RemoteAddr().String())

	var cipherAddr []byte
	for {
		line, isPrefix, err := rdr.ReadLine()
		if err != nil || isPrefix {
			log.Println(err)
			writeErrCode(c, []byte("4107"), true)
			return nil, err
		}

		if bytes.HasPrefix(bytes.ToLower(line), _hdrCipherOrigin) {
			// copy instead of point
			cipherAddr = []byte(string(bytes.TrimSpace(line[(len(_hdrCipherOrigin) + 1):])))
			continue
		}

		if bytes.HasPrefix(bytes.ToLower(line), _hdrForwardedFor) {
			hdrXff = hdrXff + ", " + string(bytes.TrimSpace(line[(len(_hdrForwardedFor)+1):]))
			continue
		}

		if len(bytes.TrimSpace(line)) == 0 {
			// end of HTTP header
			if len(cipherAddr) == 0 {
				writeErrCode(c, []byte("4108"), true)
				return nil, errors.New("empty http cipher address header")
			}
			if len(hdrXff) > 0 {
				header.Write([]byte(hdrXff))
				header.Write([]byte("\n"))
			}
			header.Write(line)
			header.Write([]byte("\n"))
			break
		}

		header.Write(line)
		header.Write([]byte("\n"))

		if header.Len() > _maxHTTPHeaderSize {
			writeErrCode(c, []byte("4108"), true)
			return nil, errors.New("http header size overflowed")
		}
	}

	return cipherAddr, nil
}

// tunneling to backend
func tunneling(addr string, rdr *bufio.Reader, c net.Conn, header *bytes.Buffer) error {
	backend, err := dialTimeout("tcp", addr, time.Second*time.Duration(_BackendDialTimeout))
	if err != nil {
		// handle error
		switch err := err.(type) {
		case net.Error:
			if err.Timeout() {
				writeErrCode(c, []byte("4101"), false)
				return err
			}
		}
		writeErrCode(c, []byte("4102"), false)
		return err
	}
	defer backend.Close()

	if header != nil {
		header.WriteTo(backend)
	}

	// Start transfering data
	go pipe(c, backend, c, backend)
	pipe(backend, rdr, backend, c)

	return nil
}

func dialTimeout(network, address string, timeout time.Duration) (conn net.Conn, err error) {
	m := int(timeout / time.Second)
	for i := 0; i < m; i++ {
		conn, err = net.DialTimeout(network, address, timeout)
		if err == nil || !strings.Contains(err.Error(), "can't assign requested address") {
			break
		}
		time.Sleep(time.Second)
	}
	return
}

func backendAddrDecrypt(key []byte) ([]byte, error) {
	// Try to check cache
	m1 := _BackendAddrCache.Load().(backendAddrMap)
	k1 := string(key)
	addr, ok := m1[k1]
	if ok {
		return addr, nil
	}

	// Try to decrypt it (AES)
	addr, err := _Aes256CBC.Decrypt(_SecretPassphase, key)
	if err != nil {
		return nil, err
	}

	backendAddrList(k1, addr)
	return addr, nil
}

func backendAddrList(key string, val []byte) {
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

// Request.RemoteAddress contains port, which we want to remove i.e.:
// "[::1]:58292" => "[::1]"
func ipAddrFromRemoteAddr(s string) string {
	idx := strings.LastIndex(s, ":")
	if idx == -1 {
		return s
	}
	return s[:idx]
}

// pipe upstream and downstream
func pipe(dst io.Writer, src io.Reader, dstconn, srcconn net.Conn) {
	defer func() {
		if r := recover(); r != nil {
			log.Println("Recovered in", r, ":", string(debug.Stack()))
		}
	}()

	// only close dst when done
	defer dstconn.Close()

	buf := make([]byte, 2*4096)
	for {
		srcconn.SetReadDeadline(time.Now().Add(_ConnReadTimeout))
		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[0:nr])
			if ew != nil {
				break
			}
			if nr != nw {
				break
			}
		}
		if neterr, ok := er.(net.Error); ok && neterr.Timeout() {
			continue
		}
		if er == io.EOF {
			break
		}
		if er != nil {
			break
		}
	}
}
