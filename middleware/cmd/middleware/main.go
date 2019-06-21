// Package main provides the entry point into the middleware and accepts command line arguments.
// Once compiled, the application pipes information from bitbox-base backend services to the bitbox-wallet-app and serves as an authenticator to the bitbox-base.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"io/ioutil"
	"log"
	"net/http"

	middleware "github.com/digitalbitbox/bitbox-base/middleware/src"
	"github.com/digitalbitbox/bitbox-base/middleware/src/handlers"
)

func main() {
	bitcoinRPCUser := flag.String("rpcuser", "rpcuser", "Bitcoin rpc user name")
	bitcoinRPCPassword := flag.String("rpcpassword", "rpcpassword", "Bitcoin rpc password")
	bitcoinRPCPort := flag.String("rpcport", "18332", "Bitcoin rpc port, localhost is assumed as an address")
	lightningRPCPath := flag.String("lightning-rpc-path", "/home/bitcoin/.lightning/lightning-rpc", "Path to the lightning rpc unix socket")
	electrsRPCPort := flag.String("electrsport", "51002", "Electrs rpc port")
	network := flag.String("network", "testnet", "Indicate wether running bitcoin on testnet or mainnet")
	flag.Parse()

	logBeforeExit := func() {
		// Recover from all panics and log error before panicking again.
		if r := recover(); r != nil {
			// r is of type interface{}, just print its value
			log.Printf("%v, error detected, shutting down.", r)
			panic(r)
		}
	}
	defer logBeforeExit()
	middleware := middleware.NewMiddleware(*bitcoinRPCUser, *bitcoinRPCPassword, *bitcoinRPCPort, *lightningRPCPath, *electrsRPCPort, *network)
	log.Println("--------------- Started middleware --------------")

	handlers := handlers.NewHandlers(middleware)
	log.Println("Binding middleware api to port 8845")

	certBytes, err := ioutil.ReadFile("server.crt")
	if err != nil {
		log.Fatalln("Unable to read server.crt - is it created?", err)
	}

	clientCertPool := x509.NewCertPool()
	if ok := clientCertPool.AppendCertsFromPEM(certBytes); !ok {
		log.Fatalln("Unable to add certificate to certificate pool")
	}

	tlsConfig := &tls.Config{
		// Reject any TLS certificate that cannot be validated
		ClientAuth: tls.RequireAndVerifyClientCert,
		// Ensure that we only use our "CA" to validate certificates
		ClientCAs: clientCertPool,
		// Reject clients with RSA certificate, required settings for http-2
		CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		// Force it on our side
		PreferServerCipherSuites: true,
		// Force TLS 1.3
		MinVersion: tls.VersionTLS13,
	}

	// Build a "map" to our client certs.
	tlsConfig.BuildNameToCertificate()

	httpServer := &http.Server{
		Addr:      ":8045",
		TLSConfig: tlsConfig,
		Handler:   handlers.Router,
	}

	if err := httpServer.ListenAndServeTLS("server.crt", "server.key"); err != nil {
		log.Println(err.Error() + " Failed to listen for HTTP")
	}
}
