package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
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
	tStart = time.Now()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	args := os.Args
	if len(args) == 2 {
		search = args[1]
	} else if len(args) == 3 {
		search = args[1]
		i, err := strconv.Atoi(args[2])
		if err != nil {
			log.Fatalf("Incorrect arguments.\n %s prefix [threads]\n", args[0])
		}
		if i > 0 && i < threads {
			threads = i
		}
	} else {
		log.Fatalf("Incorrect arguments.\n %s prefix [threads]\n", args[0])
	}

	search = strings.ToLower(search)
	if search[0] != 'v' {
		log.Fatal("Prefix must start with V")
	}
	search = search[1:] // strip v

	l := len(search) * 5 / 3
	if l > 31 || l < 1 {
		log.Fatalf("Prefix [%s] is impossible.\n", search)
	}

	for _, c := range search {
		if !((c >= '1' && c <= '9') || (c >= 'a' && c <= 'z')) {
			log.Fatalf("Invalid character [%c] in prefix.\n", c)
		}
	}

	fmt.Printf("Starting search for case-insensitive [V%s] with %d threads\n", search, threads)
	for i := 0; i < threads; i++ {
		go testLoop(int64(l), search, i)
	}

	select {
	case <-sig:
		close(done)
	case <-done:
	}
}

func testLoop(l int64, search string, thread int) {
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

			serializedPubkey := keyPair.PubKey().SerializeUncompressed()
			hash := sha256.Sum256(serializedPubkey)
			b58 := base58.Encode(hash[:l])

			if strings.HasPrefix(strings.ToLower(b58), search) {
				fmt.Println("WINNER")
				fmt.Printf("Found in %s\n", time.Since(tStart))
				fmt.Printf("Address starts wtih V%s...\n", b58)
				serPubPriv := append(keyPair.Serialize(), serializedPubkey...)
				fmt.Println("Private Key:")
				fmt.Println(hex.EncodeToString(serPubPriv))
				close(done)
			}

			if i%100000 == 0 {
				fmt.Printf("loop %d: %d addr/sec\n", thread, 100000*time.Second.Nanoseconds()/time.Since(t).Nanoseconds())
				t = time.Now()
			}
		}
	}
}
