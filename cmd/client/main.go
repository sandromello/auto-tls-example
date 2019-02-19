package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"flag"
	"io/ioutil"
	"log"
	"strings"
	"time"
)

func createClientConfig(ca, crt, key string) (*tls.Config, error) {
	caCertPEM, err := ioutil.ReadFile(ca)
	if err != nil {
		return nil, err
	}

	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM(caCertPEM)
	if !ok {
		panic("failed to parse root certificate")
	}

	cert, err := tls.LoadX509KeyPair(crt, key)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      roots,
	}, nil
}

func printConnState(conn *tls.Conn) {
	log.Print(">>>>>>>>>>>>>>>> State <<<<<<<<<<<<<<<<")
	state := conn.ConnectionState()
	for i, cert := range state.PeerCertificates {

		subject := cert.Subject
		issuer := cert.Issuer
		rand := sha256.Sum256(cert.Signature)
		fingerprint := hex.EncodeToString(rand[:])
		log.Printf("SIGNATURE -> [%d] %s", i, fingerprint)
		log.Printf("  %d SUBJECT CN=%s", i, subject.CommonName)
		log.Printf("  %d ISSUER CN=%s", i, issuer.CommonName)
	}
	log.Print(">>>>>>>>>>>>>>>> State End <<<<<<<<<<<<<<<<")
}

func main() {
	connect := flag.String("connect", "localhost:8443", "who to connect to")
	ca := flag.String("ca", "./ca.crt", "root certificate")
	crt := flag.String("crt", "./app.crt", "certificate")
	key := flag.String("key", "./app.key", "key")
	flag.Parse()

	addr := *connect
	if !strings.Contains(addr, ":") {
		addr += ":443"
	}

	config, err := createClientConfig(*ca, *crt, *key)
	if err != nil {
		log.Fatalf("config failed: %s", err.Error())
	}

	for {
		conn, err := tls.Dial("tcp", addr, config)
		if err != nil {
			log.Printf("failed to connect: %s", err.Error())
		} else {

			defer conn.Close()

			log.Printf("connect to %s succeed", addr)
			printConnState(conn)
		}
		time.Sleep(time.Second * 2)
	}
}
