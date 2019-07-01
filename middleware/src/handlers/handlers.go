// Package handlers implements an api for the bitbox-wallet-app to talk to. It also takes care of running the noise encryption.
package handlers

import (
	"encoding/json"
	"log"
	"net/http"

	noisemanager "github.com/digitalbitbox/bitbox-base/middleware/src/noise"
	"github.com/digitalbitbox/bitbox-base/middleware/src/system"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
)

//const (
//	opICanHasHandShaek = "h"
//)

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

	noiseConfig *noisemanager.NoiseConfig
	//clientNoiseStaticPubkey       []byte
	//channelHash                   string
	//channelHashMiddlewareVerified bool
	//channelHashClientVerified     bool
	//sendCipher, receiveCipher     *noise.CipherState
}

// NewHandlers returns a handler instance.
func NewHandlers(middlewareInstance Middleware) *Handlers {
	router := mux.NewRouter()

	handlers := &Handlers{
		middleware: middlewareInstance,
		Router:     router,
		// TODO(TheCharlatan): The upgrader should do an origin check before upgrading. This is important later once we introduce authentication.
		upgrader:    websocket.Upgrader{},
		noiseConfig: noisemanager.NewNoiseConfig(),
	}
	handlers.Router.HandleFunc("/", handlers.rootHandler).Methods("GET")
	handlers.Router.HandleFunc("/ws", handlers.wsHandler)
	handlers.Router.HandleFunc("/getenv", handlers.getEnvHandler).Methods("GET")

	handlers.middlewareEvents = handlers.middleware.Start()
	return handlers
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

	err = handlers.noiseConfig.InitializeNoise(ws)
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
		message, err := json.Marshal(event)
		if err != nil {
			log.Println("Failed to marshal even json bytes before sending over websocket")
		}
		//messageEncrypted := handlers.sendCipher.Encrypt(nil, nil, message)
		messageEncrypted := handlers.noiseConfig.Encrypt(message)
		log.Println("Plaintext:\n ", string(message), "Ciphertext:\n ", string(messageEncrypted))
		err = ws.WriteMessage(1, messageEncrypted)

		if err != nil {
			log.Println(err.Error() + " Unexpected websocket error")
			ws.Close()
			return err
		}
	}
}
