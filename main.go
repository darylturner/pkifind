package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
)

type match struct {
	CommonName string    `json:"common_name"`
	ValidFrom  time.Time `json:"valid_from"`
	ValidUntil time.Time `json:"valid_until"`
	Serial     string    `json:"serial"`
	Revoked    bool      `json:"revoked"`
	Expired    bool      `json:"expired"`
}

func getCRL(ca *string, client *vaultapi.Client) (c *pkix.CertificateList, err error) {
	r, err := client.Logical().Read(fmt.Sprintf("%v/cert/crl", *ca))
	if r == nil {
		return c, fmt.Errorf("no value found at %v/cert/crl", *ca)
	}
	if err != nil {
		return
	}

	crl, _ := pem.Decode([]byte(r.Data["certificate"].(string)))
	if crl == nil {
		return c, errors.New("failed to decode crl")
	}

	return x509.ParseCRL(crl.Bytes)
}

func decodeCertificate(c string) (d *x509.Certificate, err error) {
	block, _ := pem.Decode([]byte(c))
	if block == nil {
		return d, errors.New("failed to parse certificate")
	}

	return x509.ParseCertificate(block.Bytes)
}

func main() {
	ca := flag.String("ca", "pki", "vault pki mount to search through")
	term := flag.String("search", "", "common name search term")
	addr := flag.String("address", "", "override VAULT_ADDR environment variable")
	token := flag.String("token", "", "override VAULT_TOKEN environment variable")
	flag.Parse()

	config := vaultapi.DefaultConfig()
	config.ReadEnvironment()
	if *addr != "" {
		config.Address = *addr
	}

	vc, err := vaultapi.NewClient(config)
	if err != nil {
		log.Fatal(err)
	}

	if *token != "" {
		vc.SetToken(*token)
	}
	if _, err := vc.Auth().Token().LookupSelf(); err != nil {
		log.Fatal(err)
	}

	crl, err := getCRL(ca, vc)
	if err != nil {
		log.Fatal(err)
	}

	r, err := vc.Logical().List(fmt.Sprintf("%v/certs", *ca))
	if r == nil {
		log.Fatal(fmt.Errorf("no value found at %v/certs", *ca))
	}
	if err != nil {
		log.Fatal(err)
	}
	allCerts := r.Data["keys"].([]interface{})

	res := make([]match, 0)
	for _, serial := range allCerts {
		r, err := vc.Logical().Read(fmt.Sprintf("%v/cert/%v", *ca, serial))
		if r == nil {
			log.Fatal(fmt.Errorf("no value found at %v/cert/%v", *ca, serial))
		}
		if err != nil {
			log.Fatal(err)
		}

		decoded, err := decodeCertificate(r.Data["certificate"].(string))
		if err != nil {
			log.Fatal(err)
		}

		if strings.Contains(decoded.Subject.CommonName, *term) {
			rev := false
			for _, rc := range crl.TBSCertList.RevokedCertificates {
				if decoded.SerialNumber.String() == rc.SerialNumber.String() {
					rev = true
					break
				}
			}

			res = append(res, match{
				CommonName: decoded.Subject.CommonName,
				ValidFrom:  decoded.NotBefore,
				ValidUntil: decoded.NotAfter,
				Serial:     serial.(string),
				Revoked:    rev,
				Expired:    time.Now().After(decoded.NotAfter),
			})
		}
	}

	jsonOut := json.NewEncoder(os.Stdout)
	jsonOut.SetIndent("", "  ")
	if err := jsonOut.Encode(res); err != nil {
		log.Fatal(err)
	}
}
