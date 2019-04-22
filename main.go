package main

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcutil/base58"
)

var tStart time.Time
var done = make(chan struct{})

func main() {
	var search = ""
	var threads = runtime.GOMAXPROCS(0)
	var caseSensitive = false
	tStart = time.Now()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	args := os.Args
	if len(args) == 2 {
		search = args[1]
	} else if len(args) == 3 || len(args) == 4 {
		search = args[1]
		i, err := strconv.Atoi(args[2])
		if err != nil {
			log.Fatalf("Incorrect arguments.\n %s prefix [threads] [caseSensitive]\n", args[0])
		}
		if i > 0 && i < threads {
			threads = i
		}

		if len(args) == 4 {
			b, err := strconv.ParseBool(args[3])
			if err != nil {
				log.Fatalf("Incorrect arguments.\n %s prefix [threads] [caseSensitive]\n", args[0])
			}
			caseSensitive = b
		}

	} else {
		log.Fatalf("Incorrect arguments.\n %s prefix [threads] [caseSensitive]\n", args[0])
	}

	if search[0] != 'V' {
		log.Fatal("Prefix must start with V")
	}

	if !validBase58(search) {
		log.Fatalln("Invalid base58 in search prefix")
	}

	if len(search) > 25 {
		log.Fatalln("Search prefix too long")
	}

	fmt.Printf("Starting search for [%s] with %d threads caseSensitive=%t\n", search, threads, caseSensitive)
	for i := 0; i < threads; i++ {
		go testLoop(search, i, caseSensitive)
	}

	select {
	case <-sig:
		close(done)
	case <-done:
	}
}

func testLoop(search string, thread int, caseSensitive bool) {
	if !caseSensitive {
		search = strings.ToLower(search)
	}

	t := time.Now()
loop:
	for i := 1; ; i++ {
		select {
		case <-done:
			break loop
		default:
			keyPair, err := btcec.NewPrivateKey(btcec.S256())
			if err != nil {
				panic(err)
			}

			addr := addressFromKeyNoChecksum(keyPair)

			match := false
			if caseSensitive && strings.HasPrefix(addr, search) {
				match = true
			} else if !caseSensitive && strings.HasPrefix(strings.ToLower(addr), search) {
				match = true
			}

			if match {
				dumpKey(keyPair)
				close(done)
			}

			if i%100000 == 0 {
				fmt.Printf("loop %d: %d addr/sec\n", thread, 100000*time.Second.Nanoseconds()/time.Since(t).Nanoseconds())
				t = time.Now()
			}
		}
	}
}

func dumpKey(key *btcec.PrivateKey) {
	addr := addressFromKeyChecksum(key)
	prvKey := base64.StdEncoding.EncodeToString(encodePrivateKey(key))
	pubKey := base64.StdEncoding.EncodeToString(encodePublicKey(key.PubKey()))

	b := []byte(fmt.Sprintf(walletTemplate, addr, addr, pubKey, prvKey))

	fmt.Printf("Search completed in %s\n", time.Since(tStart))
	fmt.Printf("Address: %s\n", addr)
	fmt.Printf("Pubkey:  %s\n", pubKey)
	fmt.Printf("PrvKey:  %s\n", prvKey)

	err := ioutil.WriteFile(addr+".dat", b, 0655)
	if err != nil {
		log.Fatal("error writing wallet file", err)
	} else {
		fmt.Printf("Wallet file written to %s.dat\n", addr)
	}
}

var privateTemplate = []byte{0x30, 0x3E, 0x02, 0x01, 0x00, 0x30, 0x10, 0x06,
	0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
	0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x0A, 0x04,
	0x27, 0x30, 0x25, 0x02, 0x01, 0x01, 0x04, 0x20}

func encodePrivateKey(key *btcec.PrivateKey) []byte {
	// template + 32byte key
	return append(privateTemplate, key.Serialize()...)
}

var publicTemplate = []byte{0x30, 0x56, 0x30, 0x10, 0x06, 0x07, 0x2A, 0x86,
	0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00,
	0x0A, 0x03, 0x42, 0x00}

func encodePublicKey(key *btcec.PublicKey) []byte {
	// template + 0x04 + 32 byte X + 32 byte Y
	return append(publicTemplate, key.SerializeUncompressed()...)
}

func addressFromKeyNoChecksum(key *btcec.PrivateKey) string {
	hash := sha256.Sum256(encodePublicKey(key.PubKey()))
	return "V" + base58.Encode(hash[:])[:24]
}

func addressFromKeyChecksum(key *btcec.PrivateKey) string {
	b58 := addressFromKeyNoChecksum(key)
	checksumHash := sha256.Sum256([]byte(b58))
	checksumB58 := base58.Encode(checksumHash[:])
	return b58 + checksumB58[:5]
}

func validBase58(s string) bool {
	for _, c := range s {
		if !((c >= '1' && c <= '9') ||
			(c >= 'a' && c <= 'z') ||
			(c >= 'A' && c <= 'Z')) {
			return false
		}
		if c == 'I' || c == 'O' || c == 'l' {
			return false
		}
	}
	return true
}

const walletTemplate = `{
  "version": 2,
  "keyType": 1,
  "locked": false,
  "defaultAddress": "%s",
  "addresses": [
    {
      "address": "%s",
      "publicKey": "%s,
      "cipher": {
        "cipherText": "%s"
      }
    }
  ]
}`
