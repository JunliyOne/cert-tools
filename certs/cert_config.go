package certs

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	mRand "math/rand"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/pkg/errors"

	"github.com/pelletier/go-toml/v2"
	"gopkg.in/yaml.v3"
)

type certs struct {
	Certs []*CertConf `toml:"certs" yaml:"certs"`
}
type Cert struct {
	Path    string
	Name    string
	Cert    *x509.Certificate
	Priv    crypto.PrivateKey
	CACert  string
	CAKey   string
	Passwd  string
	PassIn  string
	PassOut string
}

type CertConf struct {
	Path                  string      `toml:"path" yaml:"path"`
	Name                  string      `toml:"name" yaml:"name"`
	Subject               SubjectConf `toml:"subject" yaml:"subject"`
	IsCa                  bool        `toml:"isCa" yaml:"isCa"`
	CACert                string      `toml:"caCert" yaml:"caCert"`
	CAKey                 string      `toml:"caKey" yaml:"caKey"`
	BasicConstraintsValid bool        `toml:"basicConstraintsValid" yaml:"basicConstraintsValid"`
	KeyUsage              []string    `toml:"keyUsage" yaml:"keyUsage"`
	ExtKeyUsage           []string    `toml:"extKeyUsage" yaml:"extKeyUsage"`
	DNSNames              []string    `toml:"dns" yaml:"dns"`
	IPAddresses           []string    `toml:"IPs" yaml:"IPs"`
	NotBefore             *time.Time  `toml:"notBefore" yaml:"notBefore"`
	NotAfter              *time.Time  `toml:"notAfter" yaml:"notAfter"`
	Expiration            int         `toml:"expiration" yaml:"expiration"`
	Passwd                string      `toml:"password" yaml:"password"`
	PassIn                string      `toml:"passin" yaml:"passin"`
	PassOut               string      `toml:"passout" yaml:"passout"`
}

type SubjectConf struct {
	Country            []string `json:"country" yaml:"country" toml:"country"`
	Organization       []string `json:"organization" yaml:"organization" toml:"organization"`
	OrganizationalUnit []string `json:"organizational_unit" yaml:"organizational_unit" toml:"organizational_unit"`
	Locality           []string `json:"locality" yaml:"locality" toml:"locality"`
	Province           []string `json:"province" yaml:"province" toml:"province"`
	StreetAddress      []string `json:"street_address" yaml:"street_address" toml:"street_address"`
	PostalCode         []string `json:"postal_code" yaml:"postal_code" toml:"postal_code"`
	SerialNumber       string   `json:"serial_number" yaml:"serial_number" toml:"serial_number"`
	CommonName         string   `json:"common_name" yaml:"common_name" toml:"common_name"`

	// // Names contains all parsed attributes. When parsing distinguished names,
	// // this can be used to extract non-standard attributes that are not parsed
	// // by this package. When marshaling to RDNSequences, the Names field is
	// // ignored, see ExtraNames.
	// Names []AttributeTypeAndValue

	// // ExtraNames contains attributes to be copied, raw, into any marshaled
	// // distinguished names. Values override any attributes with the same OID.
	// // The ExtraNames field is not populated when parsing, see Names.
	// ExtraNames []AttributeTypeAndValue
}

var (
	KeyUsageMap = map[string]x509.KeyUsage{
		"KeyUsageDigitalSignature":  x509.KeyUsageDigitalSignature,
		"KeyUsageContentCommitment": x509.KeyUsageContentCommitment,
		"KeyUsageKeyEncipherment":   x509.KeyUsageKeyEncipherment,
		"KeyUsageDataEncipherment":  x509.KeyUsageDataEncipherment,
		"KeyUsageKeyAgreement":      x509.KeyUsageKeyAgreement,
		"KeyUsageCertSign":          x509.KeyUsageCertSign,
		"KeyUsageCRLSign":           x509.KeyUsageCRLSign,
		"KeyUsageEncipherOnly":      x509.KeyUsageEncipherOnly,
		"KeyUsageDecipherOnly":      x509.KeyUsageDecipherOnly,
	}
	ExtKeyUsageMap = map[string]x509.ExtKeyUsage{
		"ExtKeyUsageAny":                            x509.ExtKeyUsageAny,
		"ExtKeyUsageServerAuth":                     x509.ExtKeyUsageServerAuth,
		"ExtKeyUsageClientAuth":                     x509.ExtKeyUsageClientAuth,
		"ExtKeyUsageCodeSigning":                    x509.ExtKeyUsageCodeSigning,
		"ExtKeyUsageEmailProtection":                x509.ExtKeyUsageEmailProtection,
		"ExtKeyUsageIPSECEndSystem":                 x509.ExtKeyUsageIPSECEndSystem,
		"ExtKeyUsageIPSECTunnel":                    x509.ExtKeyUsageIPSECTunnel,
		"ExtKeyUsageIPSECUser":                      x509.ExtKeyUsageIPSECUser,
		"ExtKeyUsageTimeStamping":                   x509.ExtKeyUsageTimeStamping,
		"ExtKeyUsageOCSPSigning":                    x509.ExtKeyUsageOCSPSigning,
		"ExtKeyUsageMicrosoftServerGatedCrypto":     x509.ExtKeyUsageMicrosoftServerGatedCrypto,
		"ExtKeyUsageNetscapeServerGatedCrypto":      x509.ExtKeyUsageNetscapeServerGatedCrypto,
		"ExtKeyUsageMicrosoftCommercialCodeSigning": x509.ExtKeyUsageMicrosoftCommercialCodeSigning,
		"ExtKeyUsageMicrosoftKernelCodeSigning":     x509.ExtKeyUsageMicrosoftKernelCodeSigning,
	}
)

func NewCerts() []*Cert {
	return []*Cert{}
}

func ParseFile(certss []*Cert, fileName string) error {
	ext := filepath.Ext(fileName)
	file, err := os.ReadFile(fileName)
	if err != nil {
		return errors.Wrap(err, UnKnownExt.print())
	}
	certs := new(certs)

	var marshalErr error
	switch ext {
	case ".yml":
		fallthrough
	case ".yaml":
		// TODO
		err := yaml.Unmarshal(file, certs)
		marshalErr = errors.Wrap(err, YamlUnmarshalError.print())
	case ".toml":
		err := toml.Unmarshal(file, certs)
		marshalErr = errors.Wrap(err, TomlUnmarshalError.print())

	default:
		marshalErr = errors.Wrap(errors.New("unknown ext"), TomlUnmarshalError.print())
	}
	if marshalErr != nil {
		return marshalErr
	}
	return parseCertificate(certss, certs.Certs)
}

func parseCertificate(certs []*Cert, confs []*CertConf) error {
	var (
		err error
	)

	for _, conf := range confs {
		certs = append(certs, convertCert(conf))
	}
	for index, cert := range certs {
		if !cert.Cert.IsCA && (cert.CAKey == "" || cert.CACert == "") {
			err = errors.Wrap(fmt.Errorf("certificate %d: CA information not configured", index), CAInfoNotConfigured.print())
			if err != nil {
				return err
			}
		}
	}
	return err
}

func convertCert(conf *CertConf) *Cert {
	cert := &Cert{
		Path:    conf.Path,
		Name:    conf.Name,
		Cert:    new(x509.Certificate),
		CAKey:   conf.CAKey,
		CACert:  conf.CACert,
		Passwd:  conf.Passwd,
		PassIn:  conf.PassIn,
		PassOut: conf.PassOut,
	}
	cert.Priv, _ = rsa.GenerateKey(rand.Reader, 2048)
	cert.Cert = &x509.Certificate{
		Version: 3,
		Subject: pkix.Name{
			Country:            conf.Subject.Country,
			Organization:       conf.Subject.Organization,
			OrganizationalUnit: conf.Subject.OrganizationalUnit,
			Locality:           conf.Subject.Locality,
			Province:           conf.Subject.Province,
			StreetAddress:      conf.Subject.StreetAddress,
			PostalCode:         conf.Subject.PostalCode,
			CommonName:         conf.Subject.CommonName,
			SerialNumber:       conf.Subject.SerialNumber,
		},
		KeyUsage:              convertKeyUsage(conf.KeyUsage),
		ExtKeyUsage:           convertExtKeyUsage(conf.ExtKeyUsage),
		DNSNames:              conf.DNSNames,
		IPAddresses:           convertIPs(conf.IPAddresses),
		BasicConstraintsValid: conf.BasicConstraintsValid,
		IsCA:                  conf.IsCa,
	}

	if conf.NotBefore != nil && conf.NotAfter != nil {
		cert.Cert.NotBefore = *conf.NotBefore
		cert.Cert.NotAfter = *conf.NotAfter
	} else if conf.NotAfter != nil {
		cert.Cert.NotBefore = time.Now()
		cert.Cert.NotAfter = *conf.NotAfter
	} else if conf.Expiration != 0 {
		cert.Cert.NotBefore = time.Now()
		cert.Cert.NotAfter = cert.Cert.NotBefore.Add(time.Hour * 24 * 365 * time.Duration(conf.Expiration))
	}
	if conf.IsCa {
		cert.Cert.DNSNames = nil
		cert.Cert.IPAddresses = nil
		cert.Cert.SerialNumber = big.NewInt(0)
	} else {
		cert.Cert.BasicConstraintsValid = false
		cert.Cert.SerialNumber = big.NewInt(mRand.Int63())
	}

	return cert
}

func convertKeyUsage(kuss []string) x509.KeyUsage {
	var (
		ku x509.KeyUsage
	)
	for _, kus := range kuss {
		ku = ku | KeyUsageMap[kus]
	}
	return ku
}

func convertExtKeyUsage(ekuss []string) []x509.ExtKeyUsage {
	var (
		eku []x509.ExtKeyUsage
	)
	for _, kus := range ekuss {
		eku = append(eku, ExtKeyUsageMap[kus])
	}
	return eku
}

func convertIPs(ipss []string) []net.IP {
	var (
		ip []net.IP
	)
	for _, ips := range ipss {
		ip = append(ip, net.ParseIP(ips))
	}
	return ip
}

func PrintConfTemp(ext string) {
	var (
		defaults = certs{
			Certs: []*CertConf{
				{
					Path:        "your path",
					Name:        "your certificate name",
					Subject:     SubjectConf{},
					KeyUsage:    []string{"KeyUsage1", "KeyUsage2"},
					ExtKeyUsage: []string{"ExtKeyUsage1", "ExtKeyUsage2"},
					DNSNames:    []string{"your domain 1", "your domain 2", "localhost"},
					IPAddresses: []string{"127.0.0.1", "::1"},
					NotBefore:   &time.Time{},
					NotAfter:    &time.Time{},
				},
			},
		}
		confBytes []byte
		err       error
	)
	switch ext {
	case "yaml":
		confBytes, err = yaml.Marshal(defaults)
		CheckError(errors.Wrap(err, YamlMarshalError.print()))
	case "toml":
		confBytes, err = toml.Marshal(defaults)
		CheckError(errors.Wrap(err, TomlMarshalError.print()))

	default:
		fmt.Println("unknown format")
		os.Exit(127)
	}
	fmt.Printf("%s", confBytes)
}
