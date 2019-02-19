package main

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/pflag"
	certificate "k8s.io/api/certificates/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	certutil "k8s.io/client-go/util/cert"
	log "k8s.io/klog"
)

var (
	kubeconfig string
	masterURL  string
)
var appSelector = labels.Set{"app": "auto-tls"}

type WebServer struct {
	listener net.Listener
	pemCert  []byte
}

// Verifies if the certificate is valid (not expired)
func (s *WebServer) Valid() (bool, error) {
	block, _ := pem.Decode(s.pemCert)
	if block == nil {
		return false, nil
	}
	crt, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false, err
	}
	check := time.Now().UTC()
	return check.After(crt.NotBefore) && check.Before(crt.NotAfter), nil
}

// WordSepNormalizeFunc changes all flags that contain "_" separators
func wordSepNormalizeFunc(f *pflag.FlagSet, name string) pflag.NormalizedName {
	if strings.Contains(name, "_") {
		return pflag.NormalizedName(strings.Replace(name, "_", "-", -1))
	}
	return pflag.NormalizedName(name)
}

func init() {
	log.InitFlags(nil)
	pflag.CommandLine.SetNormalizeFunc(wordSepNormalizeFunc)
	pflag.CommandLine.AddGoFlagSet(flag.CommandLine)
	pflag.Set("logtostderr", "true")
	// We do not want these flags to show up in --help
	// These MarkHidden calls must be after the lines above
	pflag.CommandLine.MarkHidden("version")
	pflag.CommandLine.MarkHidden("log-flush-frequency")
	pflag.CommandLine.MarkHidden("alsologtostderr")
	pflag.CommandLine.MarkHidden("log-backtrace-at")
	pflag.CommandLine.MarkHidden("log-dir")
	pflag.CommandLine.MarkHidden("logtostderr")
	pflag.CommandLine.MarkHidden("stderrthreshold")
	pflag.CommandLine.MarkHidden("vmodule")

	pflag.StringVar(&kubeconfig, "kubeconfig", "", "Path to a kubeconfig. Only required if out-of-cluster.")
	pflag.StringVar(&masterURL, "master", "", "The address of the Kubernetes API server. Overrides any value in kubeconfig. Only required if out-of-cluster.")
	pflag.Parse()
}

type ServerTLSConfig struct {
	pemKey  []byte
	pemCert []byte
}

func (s *ServerTLSConfig) PrivateKey() *rsa.PrivateKey {
	block, _ := pem.Decode(s.pemKey)
	if block == nil {
		log.Warningf("failed decoding pem private key")
		return nil
	}
	pk, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Warningf("failed converting key to private key: %v", err)
	}
	return pk
}

func (s *ServerTLSConfig) X509Cert() *x509.Certificate {
	block, _ := pem.Decode(s.pemCert)
	if block == nil {
		log.Warningf("failed decoding pem certificate")
		return nil
	}
	crt, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Warningf("failed parsing certificate: %v", err)
	}
	return crt
}

func (s *ServerTLSConfig) X509KeyPair(pemCA []byte) tls.Certificate {
	var chain []byte
	chain = append(chain, s.pemCert...)
	chain = append(chain, '\n')
	chain = append(chain, pemCA...)
	tlscert, err := tls.X509KeyPair(chain, s.pemKey)
	if err != nil {
		log.Warningf("failed parsing certificate/private key: %v", err)
	}
	return tlscert
}

func NewServerTLSConfig(csr *certificate.CertificateSigningRequest) (*ServerTLSConfig, error) {
	var key string
	if len(csr.Annotations) != 0 {
		key = csr.Annotations["key"]
	}
	pemPrivateKeyData, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return nil, err
	}
	if len(pemPrivateKeyData) == 0 {
		return nil, fmt.Errorf("private key is empty, missing annotation proper annotation!")
	}
	return &ServerTLSConfig{
		pemKey:  pemPrivateKeyData,
		pemCert: csr.Status.Certificate,
	}, nil
}

func GetKubernetesClientOrDie() (kubernetes.Interface, []byte) {
	cfg, err := clientcmd.BuildConfigFromFlags(masterURL, kubeconfig)
	if err != nil {
		log.Fatal(err)
	}
	rootCAData := cfg.CAData
	if len(cfg.TLSClientConfig.CAData) == 0 {
		rootCAData, err = ioutil.ReadFile(cfg.TLSClientConfig.CAFile)
		if err != nil {
			log.Fatalf("failed reading ca-file: %v", err)
		}
	}
	return kubernetes.NewForConfigOrDie(cfg), rootCAData
}

func CreateCertSignRequest(kubecli kubernetes.Interface) (*certificate.CertificateSigningRequest, error) {
	pk, err := certutil.NewPrivateKey()
	if err != nil {
		return nil, err
	}
	pemPK, err := certutil.MarshalPrivateKeyToPEM(pk)
	if err != nil {
		return nil, err
	}
	dnsName := os.ExpandEnv("auto-tls-app.$POD_NAMESPACE.$CLUSTER_DNS")
	subject := &pkix.Name{
		CommonName: dnsName,
	}

	csrData, err := certutil.MakeCSR(pk, subject, []string{dnsName, "localhost"}, nil)
	if err != nil {
		return nil, err
	}
	rand := sha256.Sum256(csrData)
	csrName := fmt.Sprintf("auto-tls-%s", hex.EncodeToString(rand[:])[:8])

	csrObj := &certificate.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:   csrName,
			Labels: appSelector,
			// It's not recommended to store the private key
			// inside a CSR object, it was done for the sake of simplicity
			Annotations: map[string]string{
				"key": base64.StdEncoding.EncodeToString(pemPK),
			},
		},
		Spec: certificate.CertificateSigningRequestSpec{
			Request: csrData,
			Usages: []certificate.KeyUsage{
				certificate.UsageDigitalSignature,
				certificate.UsageKeyEncipherment,
				certificate.UsageServerAuth,
			},
		},
	}

	log.Infof("creating new csr=%v", csrObj.Name)
	csr, err := kubecli.CertificatesV1beta1().CertificateSigningRequests().Create(csrObj)
	if err != nil {
		return nil, err
	}
	return csr, err
}

func FetchFreshCertificate(kubecli kubernetes.Interface) (*certificate.CertificateSigningRequest, error) {
	// If there's a pending certificate, it will block until its status changes
	var csr *certificate.CertificateSigningRequest
	var hasPendingCertificates bool
	for {
		csrList, err := kubecli.CertificatesV1beta1().CertificateSigningRequests().List(metav1.ListOptions{
			LabelSelector: appSelector.AsSelector().String(),
		})
		if err != nil {
			return nil, err
		}
		for _, item := range csrList.Items {
			if len(item.Status.Certificate) == 0 {
				log.Infof("csr=%s - found a pending certificate, it will block until it's processed ...", item.Name)
				hasPendingCertificates = true
				break
			}
			log.Infof("csr=%s - found a certificate", item.Name)
			block, _ := pem.Decode(item.Status.Certificate)
			if block == nil {
				log.Warningf("failed decoding, certificate is invalid or empty: %v", string(item.Status.Certificate))
				continue
			}
			crt, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				log.Warningf("failed parsing certificate: %v", err)
				continue
			}
			check := time.Now().UTC()
			log.Infof("csr=%s, notbefore=%s, notafter=%s", item.Name, crt.NotBefore, crt.NotAfter)
			if check.After(crt.NotBefore) && check.Before(crt.NotAfter) {
				log.Infof("csr=%s - certificate valid", item.Name)
				csr = &item
				// turn off because it found a valid one
				hasPendingCertificates = false
				break
			}
			log.Infof("csr=%s - certificate expired, moving to the next one ...", item.Name)
		}
		// It processed all certificates and didn't find any valid ones
		// Move on to create a CSR
		if !hasPendingCertificates {
			break
		}
		time.Sleep(time.Second * 5)
	}
	if csr == nil {
		// If there isn't any valid or Pending CSR, generate one
		if _, err := CreateCertSignRequest(kubecli); err != nil {
			return nil, err
		}
		// To make sure the process only return when there's
		// a valid certificate
		return FetchFreshCertificate(kubecli)
	}
	return csr, nil
}

func main() {
	if kubeconfig == "" {
		kubeconfig = os.ExpandEnv("$KUBECONFIG")
	}
	var webserver *WebServer

	for {
		log.Info("===> executing cert manager")
		kubecli, pemCA := GetKubernetesClientOrDie()
		csr, err := FetchFreshCertificate(kubecli)
		if err != nil {
			log.Fatalf("failed fetching certificate: %v", err)
		}
		tlsConf, err := NewServerTLSConfig(csr)
		if err != nil {
			log.Fatalf("failed creating tls config: %v", err)
		}

		if webserver == nil {
			webserver = &WebServer{pemCert: tlsConf.pemCert}
			log.Infof("Starting Web Server at *:8443")
			mux := http.NewServeMux()
			mux.HandleFunc("/", appHandler)
			ioutil.WriteFile("/tmp/app.crt", tlsConf.pemCert, 0644)
			ioutil.WriteFile("/tmp/app.key", tlsConf.pemKey, 0644)
			go ListenAndServeTLSKeyPair(":8443", tlsConf.X509KeyPair(pemCA), webserver, mux)
		} else {
			// The webserver is running, check if the certificate needs to be renewed
			valid, err := webserver.Valid()
			if err != nil {
				log.Fatalf("failed veryfing if certificate is expired: %v", err)
			}
			if !valid {
				log.Infof("closing webserver, certificate expired!")
				if err := webserver.listener.Close(); err != nil {
					log.Fatalf("failed closing server: %v", err)
				}
				webserver = nil
				log.Info("===> done")
				continue
			}
		}
		log.Info("===> done")
		time.Sleep(5 * time.Second)
	}
}

func appHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/json")
	isHTTPS := r.TLS != nil
	response := []byte(
		fmt.Sprintf(
			`{"proto": "%s", "method": "%s", "status": "OK", "https": "%v"}`,
			r.Proto, r.Method, isHTTPS,
		),
	)
	w.Write(response)
}

// tcpKeepAliveListener sets TCP keep-alive timeouts on accepted
// connections. It's used by ListenAndServe and ListenAndServeTLS so
// dead TCP connections (e.g. closing laptop mid-download) eventually
// go away.
type tcpKeepAliveListener struct {
	*net.TCPListener
}

func (ln tcpKeepAliveListener) Accept() (net.Conn, error) {
	tc, err := ln.AcceptTCP()
	if err != nil {
		return nil, err
	}
	tc.SetKeepAlive(true)
	tc.SetKeepAlivePeriod(3 * time.Minute)
	return tc, nil
}

func ListenAndServeTLSKeyPair(addr string, cert tls.Certificate, ws *WebServer, handler http.Handler) error {
	server := http.Server{Addr: addr, Handler: handler}
	tlsConfig := &tls.Config{
		NextProtos:   []string{"http/1.0", "http/1.1"},
		Certificates: make([]tls.Certificate, 1),
	}
	tlsConfig.Certificates[0] = cert
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	tlsListener := tls.NewListener(tcpKeepAliveListener{ln.(*net.TCPListener)}, tlsConfig)
	ws.listener = tlsListener
	return server.Serve(tlsListener)
}
