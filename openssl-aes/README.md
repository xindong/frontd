# forked from Luzifer / go-openssl

`go-openssl` is a small library wrapping the `crypto/aes` functions in a way the output is compatible to OpenSSL. For all encryption / decryption processes AES256 is used so this library will not be able to decrypt messages generated with other than `openssl aes-256-cbc`. If you're using CryptoJS to process the data you also need to use AES256 on that side.

## Installation

```
go get github.com/Luzifer/go-openssl
```

## Usage example

Check the test cases for the usage. They're quite simple as you don't need any special knowledge about OpenSSL and/or AES256.

## Testing

To execute the tests for this library you need to be on a system having `/bin/bash` and `openssl` available as the compatibility of the output is tested directly against the `openssl` binary. The library itself should be usable on all operating systems supported by Go and `crypto/aes`.
