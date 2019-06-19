// Package handlers implements an api for the bitbox-wallet-app to talk to.
package handlers

import (
	"crypto/rand"
	"encoding/json"
	"log"
	"net/http"

	"github.com/digitalbitbox/bitbox-base/middleware/src/system"
	"github.com/digitalbitbox/bitbox-wallet-app/util/errp"
	"github.com/flynn/noise"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
)

const (
	opICanHasHandShaek = "h"
)

// Middleware provides an interface to the middleware package.
type Middleware interface {
	// Start triggers the main middleware event loop that emits events to be caught by the handlers.
	Start() <-chan interface{}
	// GetSystemEnv returns a system Environment instance containing host system services information.
	GetSystemEnv() system.Environment
}

// Handlers provides a web api
type Handlers struct {
	Router *mux.Router
	//upgrader takes an http request and upgrades the connection with its origin to websocket
	upgrader   websocket.Upgrader
	middleware Middleware
	//TODO(TheCharlatan): Starting from the generic interface, flesh out restrictive types over time as the code implements more services.
	middlewareEvents <-chan interface{}

	clientNoiseStaticPubkey       []byte
	channelHash                   string
	channelHashMiddlewareVerified bool
	channelHashClientVerified     bool
	sendCipher, receiveCipher     *noise.CipherState
}

// NewHandlers returns a handler instance.
func NewHandlers(middlewareInstance Middleware) *Handlers {
	router := mux.NewRouter()

	handlers := &Handlers{
		middleware: middlewareInstance,
		Router:     router,
		// TODO(TheCharlatan): The upgrader should do an origin check before upgrading. This is important later once we introduce authentication.
		upgrader: websocket.Upgrader{},
	}
	handlers.Router.HandleFunc("/", handlers.rootHandler).Methods("GET")
	handlers.Router.HandleFunc("/ws", handlers.wsHandler)
	handlers.Router.HandleFunc("/getenv", handlers.getEnvHandler).Methods("GET")

	handlers.middlewareEvents = handlers.middleware.Start()
	return handlers
}

func (handlers *Handlers) initializeNoise(client *websocket.Conn) error {
	cipherSuite := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)
	keypair := handlers.configGetMiddlewareNoiseStaticKeypair()
	if keypair == nil {
		log.Println("noise static keypair created")
		kp, err := cipherSuite.GenerateKeypair(rand.Reader)
		if err != nil {
			panic(err)
		}
		keypair = &kp
		if err := handlers.configSetMiddlewareNoiseStaticKeypair(keypair); err != nil {
			log.Println("could not store app noise static keypair")

			// Not a critical error, ignore.
		}
	}
	handshake, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   cipherSuite,
		Random:        rand.Reader,
		Pattern:       noise.HandshakeXX,
		StaticKeypair: *keypair,
		Prologue:      []byte("Noise_XX_25519_ChaChaPoly_SHA256"),
		Initiator:     true,
	})
	if err != nil {
		return err
		log.Printf("%v", handshake)
	}

	//Not sure if we should keep this, my current idea is to first make a generic get request that makes the middleware open an extra tcp socket
	//responseBytes, err := device.queryRaw([]byte(opICanHasHandShaek))
	client.WriteMessage(1, []byte(opICanHasHandShaek))
	_, responseBytes, err := client.ReadMessage()
	if string(responseBytes) != string(opICanHasHandShaek) {
		log.Println("Initial response bytes did not match what we were expecting")
	}
	client.WriteMessage(1, []byte("ACK"))

	// Do handshake. My current idea to protect against session highjacking and making the connection fail on purposed is to use websocket. I am not sure exactly how this should work though, since I need to be able to both read and write. Further, the question also is how to handle those requests that are currently just some generic http.
	_, responseBytes, err = client.ReadMessage()
	if err != nil {
		panic(err)
	}
	_, _, _, err = handshake.ReadMessage(nil, responseBytes)
	if err != nil {
		panic(err)
	}
	msg, _, _, err := handshake.WriteMessage(nil, nil)
	if err != nil {
		panic(err)
	}
	client.WriteMessage(1, msg)
	_, responseBytes, err = client.ReadMessage()
	if err != nil {
		panic(err)
	}
	msg, handlers.sendCipher, handlers.receiveCipher, err = handshake.WriteMessage(nil, nil)
	if err != nil {
		panic(err)
	}
	client.WriteMessage(1, msg)
	handlers.clientNoiseStaticPubkey = handshake.PeerStatic()
	if len(handlers.clientNoiseStaticPubkey) != 32 {
		panic(errp.New("expected 32 byte remote static pubkey"))
	}

	return nil
}

// TODO(TheCharlatan): Define a better error-response system. In future, this should be the first step in an authentication procedure.
// rootHandler provides an endpoint to indicate that the middleware is online and able to handle requests.
func (handlers *Handlers) rootHandler(w http.ResponseWriter, r *http.Request) {
	_, err := w.Write([]byte("OK!!\n"))
	if err != nil {
		log.Println(err.Error() + " Failed to write response bytes in root handler")
	}
}

func (handlers *Handlers) getEnvHandler(w http.ResponseWriter, r *http.Request) {
	data, err := json.Marshal(handlers.middleware.GetSystemEnv())
	if err != nil {
		log.Println(err.Error() + " Failed to serialize GetSystemEnv data to json in getEnvHandler")
		http.Error(w, "Something went wrong, I cannot read these hieroglyphs.", http.StatusInternalServerError)
		return
	}
	_, err = w.Write(data)
	if err != nil {
		log.Println(err.Error() + " Failed to write response bytes in getNetwork handler")
		http.Error(w, "Something went wrong, I cannot read these hieroglyphs", http.StatusInternalServerError)
		return
	}
}

// wsHandler spawns a new ws client, by upgrading the sent request to websocket and then starts a serveSampleInfoToClient stream.
func (handlers *Handlers) wsHandler(w http.ResponseWriter, r *http.Request) {
	ws, err := handlers.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println(err.Error() + " Failed to upgrade connection")
	}

	err = handlers.initializeNoise(ws)
	if err != nil {
		log.Println(err.Error() + "Noise connection failed to initialize")
		return
	}

	err = handlers.serveSampleInfoToClient(ws)
	log.Println(err.Error(), " Websocket client disconnected.")
}

// serveSampleInfoToClient takes a single connected ws client and streams data to it indefinitely until the client disconnected, or a websocket error forces it to return.
func (handlers *Handlers) serveSampleInfoToClient(ws *websocket.Conn) error {
	var i = 0
	for {
		i++
		event := <-handlers.middlewareEvents
		err := ws.WriteJSON(event)
		if err != nil {
			log.Println(err.Error() + " Unexpected websocket error")
			ws.Close()
			return err
		}
	}
}
