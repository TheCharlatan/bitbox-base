package noisemanager

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"log"
	"time"

	"github.com/digitalbitbox/bitbox-wallet-app/util/errp"
	"github.com/flynn/noise"
	"github.com/gorilla/websocket"
)

const (
	opICanHasHandShaek = "h"
)

type NoiseConfig struct {
	clientNoiseStaticPubkey       []byte
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

	log.Println("Just something to indicate that the handshake is initialized")
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
	_, noiseConfig.sendCipher, noiseConfig.receiveCipher, err = handshake.ReadMessage(nil, responseBytes)
	if err != nil {
		panic(err)
	}
	//msg, handlers.sendCipher, handlers.receiveCipher, err = handshake.WriteMessage(nil, nil)
	//if err != nil {
	//	panic(err)
	//}

	//err = ws.WriteMessage(1, msg)
	//if err != nil {
	//	panic(err)
	//}
	noiseConfig.clientNoiseStaticPubkey = handshake.PeerStatic()
	if len(noiseConfig.clientNoiseStaticPubkey) != 32 {
		panic(errp.New("expected 32 byte remote static pubkey"))
	}

	_, responseBytes, err = ws.ReadMessage()
	if err != nil {
		panic(err)
	}
	pairingVerificationRequiredByClient := false
	if string(responseBytes) == "v" {
		pairingVerificationRequiredByClient = true
	}
	pairingVerificationRequiredByMiddleware := !noiseConfig.containsClientStaticPubkey(noiseConfig.clientNoiseStaticPubkey)
	if pairingVerificationRequiredByMiddleware {
		msg = []byte("v")
	}
	err = ws.WriteMessage(websocket.TextMessage, msg)
	if err != nil {
		panic(err)
	}

	if pairingVerificationRequiredByMiddleware || pairingVerificationRequiredByClient {
		channelHashBase32 := base32.StdEncoding.EncodeToString(handshake.ChannelBinding())
		noiseConfig.channelHash = fmt.Sprintf(
			"%s %s\n%s %s",
			channelHashBase32[:5],
			channelHashBase32[5:10],
			channelHashBase32[10:15],
			channelHashBase32[15:20])
		log.Println("This is the noise channel hash: ", noiseConfig.channelHash)
		// TODO(TheCharlatan) At this point, the channel Hash should be displayed on the screen, with a blocking call.
		// For now, just add a dummy timer, since we do not have a screen yet, and make every verification a success.
		time.Sleep(2 * time.Second)
		err = ws.WriteMessage(websocket.TextMessage, []byte("ACK"))
		if err != nil {
			panic(err)
		}
	}
	return nil
}

func (noiseConfig *NoiseConfig) Encrypt(message []byte) []byte {
	return noiseConfig.sendCipher.Encrypt(nil, nil, message)
}
