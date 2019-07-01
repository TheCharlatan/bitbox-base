package noisemanager

import (
	"crypto/rand"
	"log"

	"github.com/digitalbitbox/bitbox-wallet-app/util/errp"
	"github.com/flynn/noise"
	"github.com/gorilla/websocket"
)

const (
	opICanHasHandShaek = "h"
)

type NoiseConfig struct {
	clientNoiseConfigStaticPubkey []byte
	channelHash                   string
	channelHashMiddlewareVerified bool
	channelHashClientVerified     bool
	sendCipher, receiveCipher     *noise.CipherState
}

func NewNoiseConfig() *NoiseConfig {
	noise := &NoiseConfig{}
	return noise
}

func (noiseConfig *NoiseConfig) InitializeNoise(ws *websocket.Conn) error {
	cipherSuite := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)
	keypair := noiseConfig.getMiddlewareNoiseStaticKeypair()
	if keypair == nil {
		log.Println("noise static keypair created")
		kp, err := cipherSuite.GenerateKeypair(rand.Reader)
		if err != nil {
			panic(err)
		}
		keypair := &kp
		if err := noiseConfig.setMiddlewareNoiseStaticKeypair(keypair); err != nil {
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
		Initiator:     false,
	})
	if err != nil {
		log.Printf("%v", handshake)
		return err
	}

	//Not sure if we should keep this, my current idea is to first make a generic get request that makes the middleware open an extra tcp socket
	//responseBytes, err := device.queryRaw([]byte(opICanHasHandShaek))
	_, responseBytes, err := ws.ReadMessage()
	if err != nil {
		panic(err)
	}
	if string(responseBytes) != string(opICanHasHandShaek) {
		log.Println("Initial response bytes did not match what we were expecting")
	}
	err = ws.WriteMessage(1, []byte("ACK"))
	if err != nil {
		panic(err)
	}

	// Do handshake. My current idea to protect against session highjacking and making the connection fail on purposed is to use websocket. I am not sure exactly how this should work though, since I need to be able to both read and write. Further, the question also is how to handle those requests that are currently just some generic http.
	log.Println("Reading first noise message from client")
	_, responseBytes, err = ws.ReadMessage()
	if err != nil {
		panic(err)
	}
	log.Println("Reading this message into the handshake state")
	_, _, _, err = handshake.ReadMessage(nil, responseBytes)
	if err != nil {
		panic(err)
	}
	log.Println("Writing a new noise message")
	msg, _, _, err := handshake.WriteMessage(nil, nil)
	if err != nil {
		panic(err)
	}
	err = ws.WriteMessage(1, msg)
	if err != nil {
		panic(err)
	}
	log.Println("Reading a new noise message")
	_, responseBytes, err = ws.ReadMessage()
	if err != nil {
		panic(err)
	}
	log.Println("Reading this message into the noise handshake state")
	msg, noiseConfig.sendCipher, noiseConfig.receiveCipher, err = handshake.ReadMessage(nil, responseBytes)
	if err != nil {
		panic(err)
	}
	//msg, handlers.sendCipher, handlers.receiveCipher, err = handshake.WriteMessage(nil, nil)
	//if err != nil {
	//	panic(err)
	//}

	err = ws.WriteMessage(1, msg)
	if err != nil {
		panic(err)
	}
	noiseConfig.clientNoiseConfigStaticPubkey = handshake.PeerStatic()
	if len(noiseConfig.clientNoiseConfigStaticPubkey) != 32 {
		panic(errp.New("expected 32 byte remote static pubkey"))
	}

	return nil
}

func (noiseConfig *NoiseConfig) Encrypt(message []byte) []byte {
	return noiseConfig.sendCipher.Encrypt(nil, nil, message)
}
