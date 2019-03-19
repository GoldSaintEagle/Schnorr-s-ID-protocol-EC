package main

import (
	"Schnorr"
	"bufio"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var host = flag.String("host", "localhost", "The hostname or IP to connect to; defaults to \"localhost\".")
var port = flag.Int("port", 8000, "The port to connect to; defaults to 8000.")

var state = Schnorr.UNINIT

var certPath = "./eccert.pem"
var privKeyPath = "./ecpriv.pem"

var e *big.Int
var k *big.Int

func main() {
	RunClient()
}


func RunClient() {
	flag.Parse()

	dest := *host + ":" + strconv.Itoa(*port)
	fmt.Printf("Connecting to %s...\n", dest)

	conn, err := net.Dial("tcp", dest)

	if err != nil {
		if _, t := err.(*net.OpError); t {
			fmt.Println("Some problem connecting.")
		} else {
			fmt.Println("Unknown error: " + err.Error())
		}
		os.Exit(1)
	}

	// public key
	pubData, err := ioutil.ReadFile(certPath)
	if err != nil {
		fmt.Printf("Cannnot find client cert file in %s.\n", certPath)
		os.Exit(1)
	}
	pubBlock, _ := pem.Decode(pubData)
	if pubBlock == nil {
		fmt.Println("Fail to decode pem.")
		os.Exit(1)
	}
	cert, err := x509.ParseCertificate(pubBlock.Bytes)
	if err != nil {
		fmt.Printf("Fail to ParseCertificate: %v.\n", err)
		os.Exit(1)
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		fmt.Println("Cannot get public key!")
		os.Exit(1)
	}

	// private key
	privData, err := ioutil.ReadFile(privKeyPath)
	if err != nil {
		fmt.Printf("Cannnot find client cert file in %s.\n", privKeyPath)
		os.Exit(1)
	}
	privBlock, _ := pem.Decode(privData)
	if privBlock == nil {
		fmt.Println("Fail to decode pem.")
		os.Exit(1)
	}
	privKey, err := x509.ParsePKCS8PrivateKey(privBlock.Bytes)
	if err != nil {
		fmt.Printf("Fail to ParsePKCS8PrivateKey: %v.\n", err)
		os.Exit(1)
	}
	priv, ok := privKey.(*ecdsa.PrivateKey)
	if !ok {
		fmt.Println("Cannot get private key!")
		os.Exit(1)
	}
	if priv.PublicKey.X.Cmp(pub.X) != 0 || priv.PublicKey.Y.Cmp(pub.Y) != 0 {
		fmt.Println("Private and public keys doesn't match!")
		os.Exit(1)
	}


	go readConnection(conn)

	for {
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("> ")
		text, _ := reader.ReadString('\n')

		msg, rst := makeMessage(text, priv)
		if rst == false {
			continue
		}
		fmt.Print("> ")
		fmt.Printf("[send] %s\n", msg)
		conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
		_, err := conn.Write([]byte(msg))
		if err != nil {
			fmt.Println("Error writing to stream.")
			break
		}
	}
}

func readConnection(conn net.Conn) {
	for {
		scanner := bufio.NewScanner(conn)

		for {
			ok := scanner.Scan()
			text := scanner.Text()

			command := handleCommands(text)
			if !command {
				fmt.Printf("\b\b** %s\n> ", text)
			}

			if !ok {
				fmt.Println("Reached EOF on server connection.")
				break
			}
		}
	}
}

func handleCommands(text string) bool {
	fmt.Printf("[receive] %s\n", text)

	switch {
	case strings.HasPrefix(text, Schnorr.HandshakePrefix):
		fmt.Println("\b\bHandshake pass.")
		state = Schnorr.INIT

	case strings.HasPrefix(text, Schnorr.CommitPrefix):
		msg := text[len(Schnorr.CommitPrefix):]
		eHex, err := hex.DecodeString(msg)
		if err != nil {
			fmt.Println("DecodeString fail!")
			break
		}
		e = new(big.Int).SetBytes(eHex)
		fmt.Println("\b\bCommit pass.")
		state = Schnorr.COMMIT

	case strings.HasPrefix(text, Schnorr.ResponsePrefix):
		fmt.Println("\b\bResponse pass.")
		state = Schnorr.ACCEPT

	case strings.HasPrefix(text, "/read: accept"):
		fmt.Println("\b\bRead accept.")

	case strings.HasPrefix(text, "error"):
		fmt.Println("\b\bError.")
		state = Schnorr.UNINIT
	}

	r, err := regexp.Compile("^%.*%$")
	if err == nil {
		if r.MatchString(text) {
			fmt.Printf("[encode] %s\n", text)
			switch {
			case text == "%quit%":
				fmt.Println("\b\bServer is leaving. Hanging up.")
				os.Exit(0)
			}

			return true
		}
	}

	return false
}

func makeMessage(text string, priv *ecdsa.PrivateKey) (string, bool) {
	switch text {
	case "/h\n", "/handshake\n":
		fmt.Println("\b\bInit connection.")
		data, err := ioutil.ReadFile(certPath)
		if err != nil {
			fmt.Printf("Cannnot find cert file in %s.\n", certPath)
			os.Exit(1)
		}
		var jsonMsg Schnorr.HandshakeTemplate
		jsonMsg.Cert = string(data)
		strMsg, err := json.Marshal(jsonMsg)
		if err != nil {
			fmt.Println("Marshal fail!")
			os.Exit(1)
		}
		return Schnorr.HandshakePrefix + string(strMsg) + "\n", true

	case "/c\n", "/commitment\n":
		fmt.Println("\b\bCommitment.")
		if state != Schnorr.INIT {
			return text, false
		}
		params := priv.Params()
		b := make([]byte, params.BitSize/8+8)
		_, err := io.ReadFull(rand.Reader, b)
		if err != nil {
			fmt.Println("Create random error!")
			os.Exit(1)
		}
		one := new(big.Int).SetInt64(1)
		k = new(big.Int).SetBytes(b)
		n := new(big.Int).Sub(params.N, one)
		k.Mod(k, n)
		k.Add(k, one)
		x, y := priv.Curve.ScalarBaseMult(k.Bytes())

		var jsonMsg Schnorr.CommitTemplate
		jsonMsg.Kx = hex.EncodeToString(x.Bytes())
		jsonMsg.Ky = hex.EncodeToString(y.Bytes())

		strMsg, err := json.Marshal(jsonMsg)
		if err != nil {
			fmt.Println("Marshal fail!")
			os.Exit(1)
		}
		return Schnorr.CommitPrefix + string(strMsg) + "\n", true

	case "/r\n", "/response\n":
		fmt.Println("\b\bResponse.")
		if state != Schnorr.COMMIT {
			return text, false
		}
		fmt.Printf("e: %v\nk: %v\n", e, k)
		r := new(big.Int).Add(k, new(big.Int).Mul(e, priv.D))
		r.Mod(r, priv.Params().N)

		var jsonMsg Schnorr.ResponseTemplate
		jsonMsg.R = hex.EncodeToString(r.Bytes())
		strMsg, err := json.Marshal(jsonMsg)
		if err != nil {
			fmt.Println("Marshal fail!")
			os.Exit(1)
		}
		return Schnorr.ResponsePrefix + string(strMsg) + "\n", true

	case "/read\n":
		fmt.Printf("Read from state :%d.\n", state)
		return text, true
	}
	return text, true
}