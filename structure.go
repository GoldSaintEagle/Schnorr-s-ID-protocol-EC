package Schnorr

/**
Prover (P): client (has pr)
Verifier (V): server

P->V: handshake (P's cert)
V->P: handshake OK
P->V: commitment (K = k*G)
V->P: challenge (e)
P->V: response (r = k + e * pr)
V->P: OK (r*G =? K + e*P)
 */
type HandshakeTemplate struct {
	Cert string
}

type CommitTemplate struct {
	Kx string
	Ky string
}

type ResponseTemplate struct {
	R string
}

const (
	UNINIT = iota
	INIT
	COMMIT
	ACCEPT

)

var HandshakePrefix = "/handshake: "
var CommitPrefix = "/commit: "
var ResponsePrefix = "/response: "
