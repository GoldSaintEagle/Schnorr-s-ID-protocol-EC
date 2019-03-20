package server

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
	"math/big"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

var addr = flag.String("addr", "", "The address to listen to; default is \"\" (all interfaces).")
var port = flag.Int("port", 8000, "The port to listen on; default is 8000.")

var state = Schnorr.UNINIT


func RunServer() {

	flag.Parse()
	fmt.Println("Starting server...")

	src := *addr + ":" + strconv.Itoa(*port)
	listener, _ := net.Listen("tcp", src)
	fmt.Printf("Listening on %s.\n", src)

	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Printf("Some connection error: %s\n", err)
		}

		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	remoteAddr := conn.RemoteAddr().String()
	fmt.Println("Client connected from " + remoteAddr)

	scanner := bufio.NewScanner(conn)
	pub := new(ecdsa.PublicKey)
	x := new(big.Int) // K = (x, y)
	y := new(big.Int) // K = (x, y)
	e := new(big.Int) // challenge
	r := new(big.Int) // response

	for {
		ok := scanner.Scan()
		if !ok {
			break
		}
		handleMessage(scanner.Text(), conn, pub, x, y, e, r)
	}

	fmt.Println("Client at " + remoteAddr + " disconnected.")
}

func handleMessage(message string, conn net.Conn, pub *ecdsa.PublicKey, x, y, e, r *big.Int) {
	fmt.Println("[receive] " + message)

	if len(message) > 0 && message[0] == '/' {
		switch {
		case message == "/time":
			resp := "It is " + time.Now().String() + "\n"
			fmt.Print("< " + resp)
			conn.Write([]byte(resp))

		case message == "/quit", message == "/q":
			fmt.Println("Quitting.")
			conn.Write([]byte("I'm shutting down now.\n"))
			fmt.Println("< " + "%quit%")
			conn.Write([]byte("%quit%\n"))
			os.Exit(0)

		case strings.HasPrefix(message, Schnorr.HandshakePrefix):
			if state != Schnorr.UNINIT {
				state = Schnorr.UNINIT
			}
			fmt.Println("Init connection.")
			msg := message[len(Schnorr.HandshakePrefix):]

			var jsonMsg Schnorr.HandshakeTemplate
			err := json.Unmarshal([]byte(msg), &jsonMsg)
			if err != nil {
				fmt.Println("Unmarshal fail!")
				conn.Write([]byte("/error: Unmarshal fail!\n"))
				break
			}
			pemBlock, _ := pem.Decode([]byte(jsonMsg.Cert))
			cert, err := x509.ParseCertificate(pemBlock.Bytes)
			if err != nil {
				fmt.Println("ParseCertificate fail!")
				conn.Write([]byte("/error: ParseCertificate fail!\n"))
				break
			}
			pubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
			if !ok {
				fmt.Println("Cannot get public key!")
				os.Exit(1)
			}
			pub.Curve = pubKey.Curve
			pub.X = pubKey.X
			pub.Y = pubKey.Y

			conn.Write([]byte(Schnorr.HandshakePrefix + "Success\n"))
			state = Schnorr.INIT
			fmt.Println("Init success!")

		case strings.HasPrefix(message, Schnorr.CommitPrefix):
			if state != Schnorr.INIT {
				fmt.Println("Invalid commit!")
				conn.Write([]byte("/error: init before commit!\n"))
				break
			}
			msg := message[len(Schnorr.CommitPrefix):]

			var jsonMsg Schnorr.CommitTemplate
			err := json.Unmarshal([]byte(msg), &jsonMsg)
			if err != nil {
				fmt.Println("Unmarshal fail!")
				conn.Write([]byte("/error: Unmarshal fail!\n"))
				break
			}
			xHex, err := hex.DecodeString(jsonMsg.Kx)
			if err != nil {
				fmt.Println("DecodeString fail!")
				conn.Write([]byte("/error: DecodeString fail!\n"))
				break
			}
			x.SetBytes(xHex)
			yHex, err := hex.DecodeString(jsonMsg.Ky)
			if err != nil {
				fmt.Println("DecodeString fail!")
				conn.Write([]byte("/error: DecodeString fail!\n"))
				break
			}
			y.SetBytes(yHex)

			params := pub.Params()
			b := make([]byte, params.BitSize/8+8)
			_, err = io.ReadFull(rand.Reader, b)
			if err != nil {
				fmt.Println("ReadFull fail!")
				conn.Write([]byte("/error: ReadFull fail!\n"))
				break
			}
			one := new(big.Int).SetInt64(1)
			e.SetBytes(b)
			n := new(big.Int).Sub(params.N, one)
			e.Mod(e, n)
			e.Add(e, one)

			conn.Write([]byte(Schnorr.CommitPrefix + hex.EncodeToString(e.Bytes()) + "\n"))
			state = Schnorr.COMMIT
			fmt.Println("Commit success!")

		case strings.HasPrefix(message, Schnorr.ResponsePrefix):
			if state != Schnorr.COMMIT {
				fmt.Println("Invalid response!")
				conn.Write([]byte("/error: commit before response!\n"))
				break
			}
			msg := message[len(Schnorr.ResponsePrefix):]

			var jsonMsg Schnorr.ResponseTemplate
			err := json.Unmarshal([]byte(msg), &jsonMsg)
			if err != nil {
				fmt.Println("Unmarshal fail!")
				conn.Write([]byte("/error: Unmarshal fail!\n"))
				break
			}
			rHex, err := hex.DecodeString(jsonMsg.R)
			if err != nil {
				fmt.Println("DecodeString fail!")
				conn.Write([]byte("/error: DecodeString fail!\n"))
				break
			}
			r = new(big.Int).SetBytes(rHex)

			//fmt.Printf("%v\nx: %v\ny: %v\ne: %v\nr: %v\n", pub, x, y, e, r)
			Rx, Ry := pub.ScalarBaseMult(r.Bytes())
			ePx, ePy := pub.ScalarMult(pub.X, pub.Y, e.Bytes())
			RRx, RRy := pub.Add(x, y, ePx, ePy)
			if RRx.Cmp(Rx) == 0 && RRy.Cmp(Ry) == 0 {
				fmt.Println("PASS!")
				conn.Write([]byte(Schnorr.CommitPrefix + "Success\n"))
				state = Schnorr.ACCEPT
				break
			}
			fmt.Println("FAIL!")
			conn.Write([]byte("/error: verify fail\n"))
			state = Schnorr.UNINIT
		case strings.HasPrefix(message, "/read"):
			if state == Schnorr.ACCEPT {
				fmt.Println("Accept read request!")
				conn.Write([]byte("/read: accept.\n"))
				break
			}
			fmt.Println("Deny read!")
			conn.Write([]byte("/error: deny.\n"))

		default:
			conn.Write([]byte("Unrecognized command: " + message + "\n"))
		}
	}
}
