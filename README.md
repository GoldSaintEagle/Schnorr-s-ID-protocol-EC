# Schnorr-s-ID-protocol-EC-
An EC implementation of Schnorr's ID protocol (example)

####Schnorr's Protocol

Prover (P, client) proves to Verifier (V, server) that he has pr


* P->V: handshake (P's cert)
* V->P: handshake OK
* P->V: commitment (K = k*G)
* V->P: challenge (e)
* P->V: response (r = k + e * pr)
* V->P: OK (r*G =? K + e*P)

####Usage

Run server: call `RunServer()` function (in `server/server_test.go`, `TestRunServer`)

Run client: call `RunClient()` function (in `client/client.go`, `main`)

Client:

* directly call `/read` command will fail
* call `/h` or `/handshake` to send cert (public key) to V
* after receiving `handshake success`, call `/c` or `/commit` for commitment
* after receiving `challenge`, call `/r` or `/response`for response
* call `/read` command will success after passing Schnorr's ID protocol
* call `/q` or `/quit` will quit client

Server:

Automatically handle client's request.


