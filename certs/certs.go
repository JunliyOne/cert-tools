package certs

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
)

// openssl  pkcs12  -export  -in  ca.crt  -inkey  ca.key  -out  ca.p12 -password 123456

// func NewCAPairWithP12(name string, alog string, n int, passwd string) {
// 	NewCAPair(name, alog, n)
// 	cmdTmp := "openssl pkcs12 -export -in %s.crt -inkey %s.key -out %s.p12 -password pass:%s"
// 	cmdS := strings.Split(fmt.Sprintf(cmdTmp, name, name, name, passwd), " ")
// 	err := exec.Command(cmdS[0], cmdS[1:]...).Run()
// 	if err != nil {
// 		panic(err)
// 	}

// }

// func NewCAPair(name string, alog string, n int) {
// 	var (
// 		priv      crypto.PrivateKey
// 		privBytes []byte
// 		err       error
// 		keyFile   *os.File
// 	)
// 	priv, err = NewPrivKey(alog, n)
// 	if err != nil {
// 		fmt.Printf("%s err: %v\n", alog, err)
// 		return
// 	}
// 	keyFile, err = os.Create(name + ".key")
// 	if err != nil {
// 		fmt.Printf("err: %v\n", err)
// 		return
// 	}
// 	defer keyFile.Close()
// 	switch alog {
// 	case "rsa":
// 		privBytes = x509.MarshalPKCS1PrivateKey(priv.(*rsa.PrivateKey))
// 		err = pem.Encode(keyFile, &pem.Block{
// 			Type:  "RSA PRIVATE KEY",
// 			Bytes: privBytes,
// 		})
// 	case "ecdsa":
// 		privBytes, err = x509.MarshalECPrivateKey(priv.(*ecdsa.PrivateKey))
// 		if err != nil {
// 			fmt.Printf("err: %v\n", err)
// 			return
// 		}
// 		err = pem.Encode(keyFile, &pem.Block{
// 			Type:  "EC PRIVATE KEY",
// 			Bytes: privBytes,
// 		})
// 	}

// 	if err != nil {
// 		fmt.Printf("err: %v\n", err)
// 		return
// 	}
// 	// err = NewCertificate(priv,  name)
// 	if err != nil {
// 		fmt.Printf("err: %v\n", err)
// 	}
// }

func NewPrivKey(alog string, n int) (crypto.PrivateKey, error) {
	var (
		priv crypto.PrivateKey
		err  error
	)
	switch alog {
	case "rsa":
		priv, err = rsa.GenerateKey(rand.Reader, n)
	case "ecdsa":
		priv, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	default:
		return nil, errors.New("unknown alog")
	}
	return priv, err
}

func checkCertPairExist(cert, key string) bool {
	_, errc := os.Stat(cert)
	_, errk := os.Stat(key)
	if errors.Is(os.ErrNotExist, errc) && errors.Is(os.ErrNotExist, errk) {
		return false
	}
	return true
}

func GenCertificate(cert *Cert) error {
	var (
		certBytes []byte
		err       error
		certFile  *os.File
		caCert    *x509.Certificate
		caPriv    crypto.PrivateKey
	)
	if cert.Cert.IsCA {
		certBytes, err = x509.CreateCertificate(rand.Reader, cert.Cert, cert.Cert, &cert.Priv.(*rsa.PrivateKey).PublicKey, cert.Priv)
		if err != nil {
			return errors.Wrap(err, CreateCertificateError.print())
		}
	} else {
		if cert.CACert == "" || cert.CAKey == "" {
			return errors.Wrap(fmt.Errorf("CA information not configured: %s", cert.Name), CAInfoNotConfigured.print())
		}
		if !checkCertPairExist(cert.CACert, cert.CAKey) {
			return errors.Wrap(fmt.Errorf("CA key pair not exits: %s", cert.Name), CAInfoNotConfigured.print())
		}
		caCert, caPriv, err = GetCertKeyPair(cert.CACert, cert.CAKey)
		if err != nil {
			return errors.Wrap(fmt.Errorf("%s prase file to CA key pair error: %s,%s", cert.Name, cert.CACert, cert.CAKey), FileNotExist.print())
		}
		// x509.CreateCertificate args: rand.Reader, certTmp, caCert, &PrivateKey.PublicKey,caPrivKey
		certBytes, err = x509.CreateCertificate(rand.Reader, cert.Cert, caCert, &cert.Priv.(*rsa.PrivateKey).PublicKey, caPriv)
		if err != nil {
			return errors.Wrap(err, CreateCertificateError.print())
		}
	}

	certFile, err = os.Create(filepath.Join(cert.Path, cert.Name+".crt"))
	if err != nil {
		return errors.Wrap(err, IoCreateFileError.print())
	}
	defer certFile.Close()
	err = pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	if err != nil {
		return errors.Wrap(err, IoWriteError.print())
	}
	return err
}

func GenKey(cert *Cert) error {
	var (
		privBytes []byte
		err       error
		keyFile   *os.File
	)
	keyFile, err = os.Create(filepath.Join(cert.Path, cert.Name+".key"))
	if err != nil {
		return errors.Wrap(err, IoCreateFileError.print())
	}
	defer keyFile.Close()
	privBytes = x509.MarshalPKCS1PrivateKey(cert.Priv.(*rsa.PrivateKey))
	err = pem.Encode(keyFile, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privBytes,
	})
	return errors.Wrap(err, IoWriteError.print())
}

func GenCertKeyPair(cert *Cert, withP12 bool) error {
	err := GenKey(cert)
	if err != nil {
		return err
	}
	GenCertificate(cert)
	if err != nil {
		return err
	}
	if withP12 {
		cmdTmp := "openssl pkcs12 -export -in %s.crt -inkey %s.key -out %s.p12 -password pass:%s"
		cmdS := strings.Split(fmt.Sprintf(cmdTmp, cert.Name, cert.Name, cert.Name, cert.Passwd), " ")
		err := exec.Command(cmdS[0], cmdS[1:]...).Run()
		return errors.Wrap(err, OSCommandExecError.print())
	}
	return nil
}

func GetCertKeyPair(certFile, keyFile string) (*x509.Certificate, *rsa.PrivateKey, error) {
	if len(certFile) == 0 && len(keyFile) == 0 {
		return nil, nil, errors.New("cert or key has not provided")
	}
	tlsCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return nil, nil, err
	}
	rsaKey, ok := tlsCert.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, nil, errors.New("get rsa private key err")
	}
	return cert, rsaKey, nil
}
