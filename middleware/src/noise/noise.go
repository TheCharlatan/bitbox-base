package noisemanager

import (
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/flynn/noise"
	"github.com/gorilla/websocket"
)

const (
	opICanHasHandShaek          = "h"
	opICanHasPairinVerificashun = "v"
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
		log.Println("Creaing noise static keypair...")
		kp, err := cipherSuite.GenerateKeypair(rand.Reader)
		if err != nil {
			return errors.New("Failed to generate a new noise keypair")
		}
		keypair := &kp
		if err := noiseConfig.setMiddlewareNoiseStaticKeypair(keypair); err != nil {
			log.Println("could not store app noise static keypair")
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
		return errors.New("Websocket failed to read noise handshake request")
	}
	if string(responseBytes) != string(opICanHasHandShaek) {
		return errors.New("Initial response bytes did not match what we were expecting")
	}
	err = ws.WriteMessage(1, []byte("ACK"))
	if err != nil {
		return errors.New("Websocket failed to write the noise handshake request response")
	}

	log.Println("Reading first noise handshake message from client")
	_, responseBytes, err = ws.ReadMessage()
	if err != nil {
		return errors.New("Websocket failed to read first noise handshake message")
	}
	log.Println("Reading this message into the handshake state")
	_, _, _, err = handshake.ReadMessage(nil, responseBytes)
	if err != nil {
		return errors.New("Noise failed to read first noise handshake message")
	}
	log.Println("Writing a new noise message")
	msg, _, _, err := handshake.WriteMessage(nil, nil)
	if err != nil {
		return errors.New("Noise failed to write second noise handshake message")
	}
	err = ws.WriteMessage(1, msg)
	if err != nil {
		return errors.New("Websocket failed to write second noise handshake message")
	}
	log.Println("Reading a new noise message")
	_, responseBytes, err = ws.ReadMessage()
	if err != nil {
		return errors.New("Websocket failed to read third noise handshake message")
	}
	log.Println("Reading this message into the noise handshake state")
	_, noiseConfig.sendCipher, noiseConfig.receiveCipher, err = handshake.ReadMessage(nil, responseBytes)
	if err != nil {
		return errors.New("Noise failed to read the third noise handshake message")
	}

	// Now start the verification of the channel hash
	noiseConfig.clientNoiseStaticPubkey = handshake.PeerStatic()
	_, responseBytes, err = ws.ReadMessage()
	if err != nil {
		return errors.New("Websocket failed to read the pairingVerificationRequiredByClient message")
	}
	responseBytes, err = noiseConfig.Decrypt(responseBytes)
	if err != nil {
		return errors.New("Noise failed to decrypt the pairingVerificationRequiredByClient message")
	}
	pairingVerificationRequiredByClient := false
	if string(responseBytes) == opICanHasPairinVerificashun {
		pairingVerificationRequiredByClient = true
	}
	pairingVerificationRequiredByMiddleware := !noiseConfig.containsClientStaticPubkey(noiseConfig.clientNoiseStaticPubkey)
	if pairingVerificationRequiredByMiddleware {
		msg = []byte(opICanHasPairinVerificashun)
	}
	err = ws.WriteMessage(websocket.TextMessage, noiseConfig.Encrypt(msg))
	if err != nil {
		return errors.New("Websocket failed to write pairingVerificationRequiredByMiddleware message")
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
		// Also skip writing the static key to the file, since we do not want to skip the timer yet, such that we can test its behaviour.
		time.Sleep(2 * time.Second)
		err = ws.WriteMessage(websocket.TextMessage, noiseConfig.Encrypt([]byte("ACK")))
		if err != nil {
			return errors.New("Websocket failed to write the pairing accepted ACK message")
		}
	}
	return nil
}

func (noiseConfig *NoiseConfig) Encrypt(message []byte) []byte {
	return noiseConfig.sendCipher.Encrypt(nil, nil, message)
}

func (noiseConfig *NoiseConfig) Decrypt(message []byte) ([]byte, error) {
	return noiseConfig.receiveCipher.Decrypt(nil, nil, message)
}
