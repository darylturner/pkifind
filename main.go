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

func getCRL(ca *string, client *vaultapi.Logical) (cl *pkix.CertificateList, err error) {
	// get the pem encoded crl
	crlResults, err := client.Read(fmt.Sprintf("%v/cert/crl", *ca))
	if err != nil {
		return
	}

	// get the crl pem block from the api results
	crlBlock, _ := pem.Decode([]byte(crlResults.Data["certificate"].(string)))
	if crlBlock == nil {
		return cl, errors.New("failed to decode crl")
	}

	// decode the x509 into native certificate list
	return x509.ParseCRL(crlBlock.Bytes)
}

func decodeCertificate(c string) (dc *x509.Certificate, err error) {
	// get the cert pem block from the api results
	block, _ := pem.Decode([]byte(c))
	if block == nil {
		return dc, errors.New("failed to parse certificate")
	}

	// decode the x509 into native cert
	return x509.ParseCertificate(block.Bytes)
}

func main() {
	vault := flag.String("vault", "http://localhost:8200", "address of vault api")
	ca := flag.String("ca", "", "vault pki mount to search through")
	term := flag.String("s", "", "common name search term")
	token := flag.String("token", "", "vault api token")

	// process command line arguments
	flag.Parse()
	if *ca == "" {
		log.Fatal("please specify vault pki mount to search")
	}
	if *token == "" {
		var ok bool
		*token, ok = os.LookupEnv("VAULT_TOKEN")
		if !ok {
			log.Fatal("please supply vault token")
		}
	}

	// connect and set up authentication to vault
	vc, err := vaultapi.NewClient(&vaultapi.Config{Address: *vault})
	if err != nil {
		log.Fatalf("error connecting to vault: %v\n", err)
	}
	vc.SetToken(*token)
	logical := vc.Logical()

	// retrieve decoded crl from vault api
	crl, err := getCRL(ca, logical)
	if err != nil {
		log.Fatal(err)
	}

	// get slice of all issued certificate serial numbers
	certResults, err := logical.List(fmt.Sprintf("%v/certs", *ca))
	if err != nil {
		log.Fatal(err)
	}
	allCerts := certResults.Data["keys"].([]interface{})

	// initialize slice of matched certificates to store results
	res := make([]match, 0)

	// range over serial numbers
	for _, serial := range allCerts {
		r, err := logical.Read(fmt.Sprintf("%v/cert/%v", *ca, serial)) // get raw certificate from vault
		if err != nil {
			log.Fatal(err)
		}

		decoded, err := decodeCertificate(r.Data["certificate"].(string)) // decode the certificate
		if err != nil {
			log.Fatal(err)
		}

		// check to see if the search term is in the common name
		if strings.Contains(decoded.Subject.CommonName, *term) {
			// check to see if the serial number matches any in the revoked list
			rev := false
			for _, rc := range crl.TBSCertList.RevokedCertificates {
				if decoded.SerialNumber.String() == rc.SerialNumber.String() {
					rev = true
					break
				}
			}

			// push the matched onto the results slice
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

	// encode the results as json to stdout
	jsonOut := json.NewEncoder(os.Stdout)
	jsonOut.SetIndent("", "  ")
	if err := jsonOut.Encode(res); err != nil {
		log.Fatal(err)
	}
}
