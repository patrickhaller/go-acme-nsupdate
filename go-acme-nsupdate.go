package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os/exec"
	"strings"

	"github.com/patrickhaller/acme"
)

var (
	webroot      string
	domain       string
	directoryURL string
	contactsList string
	accountFile  string
	certFile     string
	keyFile      string
	nsKeyFile    string
)

type acmeAccountFile struct {
	PrivateKey *ecdsa.PrivateKey `json:"privateKey"`
	URL        string            `json:"url"`
}

func nsUpdate(rr string, challenge string, addDelete string) error {
	cmd := exec.Command("nsupdate", "-v", "-k", nsKeyFile)
	buf := bytes.NewBufferString("update ")
	buf.WriteString(addDelete)
	buf.WriteString(" ")
	buf.WriteString(rr)
	if addDelete == "add" {
		buf.WriteString(" 300 TXT ")
		buf.WriteString(challenge)
	} else {
		buf.WriteString(" TXT")
	}
	buf.WriteString("\nsend\n")

	log.Printf("Sending nsupdate: `%v'", buf)
	cmd.Stdin = strings.NewReader(buf.String())
	return cmd.Run()
}

func main() {
	flag.StringVar(&directoryURL, "dirurl", acme.LetsEncryptStaging,
		"acme directory url - defaults to lets encrypt v2 staging url if not provided")
	flag.StringVar(&contactsList, "contact", "",
		"comma separated contact emails to use when creating a new account (optional, dont include 'mailto:' prefix)")
	flag.StringVar(&domain, "domain", "",
		"domain for which to issue a certificate")
	flag.StringVar(&accountFile, "accountfile", "account.json",
		"file for the account json data (will create new file if none exists)")
	flag.StringVar(&certFile, "certfile", "cert.pem",
		"file for the pem encoded certificate chain")
	flag.StringVar(&keyFile, "keyfile", "privkey.pem",
		"file for the pem encoded certificate private key")
	flag.StringVar(&nsKeyFile, "nskeyfile", "nsupdate.key",
		"file for the nsupdate key")
	flag.Parse()

	// check domains are provided
	if domain == "" {
		log.Fatal("No domain provided")
	}

	log.Printf("Connecting to acme directory url: %s", directoryURL)
	client, err := acme.NewClient(directoryURL)
	if err != nil {
		log.Fatalf("Error connecting to acme directory: %v", err)
	}

	log.Printf("Loading account file %s", accountFile)
	account, err := loadAccount(client)
	if err != nil {
		log.Printf("Error loading existing account: %v", err)
		log.Printf("Creating new account")
		account, err = createAccount(client)
		if err != nil {
			log.Fatalf("Error creaing new account: %v", err)
		}
	}
	log.Printf("Account url: %s", account.URL)

	var acmeIDs []acme.Identifier
	acmeIDs = append(acmeIDs, acme.Identifier{Type: "dns", Value: domain})

	domainList := strings.Split(domain, ",")

	// create a new order with the acme service given the provided identifiers
	log.Printf("Creating new order for domain: %s", domain)
	order, err := client.NewOrder(account, acmeIDs)
	if err != nil {
		log.Fatalf("Error creating new order: %v", err)
	}
	log.Printf("Order created: %s", order.URL)

	// setup the rr we need to create
	idx := strings.Index(domainList[0], ".")
	nsDomain := domainList[0][idx+1:]

	rr := bytes.NewBufferString("_acme-challenge.")
	rr.WriteString(nsDomain)
	rr.WriteString(".")

	// loop through each of the provided authorization urls
	for _, authURL := range order.Authorizations {
		// fetch the authorization data from the acme service given the provided authorization url
		log.Printf("Fetching authorization: %s", authURL)
		auth, err := client.FetchAuthorization(account, authURL)
		if err != nil {
			log.Fatalf("Error fetching authorization url %q: %v", authURL, err)
		}
		log.Printf("Fetched authorization: %s", auth.Identifier.Value)

		chal, ok := auth.ChallengeMap[acme.ChallengeTypeDNS01]
		if !ok {
			log.Fatalf("Unable to find dns challenge for auth %s", auth.Identifier.Value)
		}

		err = nsUpdate(rr.String(), acme.EncodeDNS01KeyAuthorization(chal.KeyAuthorization), "add")
		if err != nil {
			log.Fatalf("Error nsupdating authorization %s challenge: %v", auth.Identifier.Value, err)
		}

		// update the acme server that the challenge file is ready to be queried
		log.Printf("Updating challenge for authorization %s: %s", auth.Identifier.Value, chal.URL)
		chal, err = client.UpdateChallenge(account, chal)
		if err != nil {
			log.Fatalf("Error updating authorization %s challenge: %v", auth.Identifier.Value, err)
		}
		log.Printf("Challenge updated")
	}

	// all the challenges should now be completed

	// create a csr for the new certificate
	log.Printf("Generating certificate private key")
	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("Error generating certificate key: %v", err)
	}
	// encode the new ec private key
	certKeyEnc, err := x509.MarshalECPrivateKey(certKey)
	if err != nil {
		log.Fatalf("Error encoding certificate key file: %v", err)
	}

	// write the key to the key file as a pem encoded key
	log.Printf("Writing key file: %s", keyFile)
	if err := ioutil.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: certKeyEnc,
	}), 0600); err != nil {
		log.Fatalf("Error writing key file %q: %v", keyFile, err)
	}

	// create the new csr template
	log.Printf("Creating csr")
	tpl := &x509.CertificateRequest{
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		PublicKeyAlgorithm: x509.ECDSA,
		PublicKey:          certKey.Public(),
		Subject:            pkix.Name{CommonName: domain},
		DNSNames:           domainList,
	}
	csrDer, err := x509.CreateCertificateRequest(rand.Reader, tpl, certKey)
	if err != nil {
		log.Fatalf("Error creating certificate request: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(csrDer)
	if err != nil {
		log.Fatalf("Error parsing certificate request: %v", err)
	}

	// finalize the order with the acme server given a csr
	log.Printf("Finalising order: %s", order.URL)
	order, err = client.FinalizeOrder(account, order, csr)
	if err != nil {
		log.Fatalf("Error finalizing order: %v", err)
	}

	// fetch the certificate chain from the finalized order provided by the acme server
	log.Printf("Fetching certificate: %s", order.Certificate)
	certs, err := client.FetchCertificates(account, order.Certificate)
	if err != nil {
		log.Fatalf("Error fetching order certificates: %v", err)
	}

	// write the pem encoded certificate chain to file
	log.Printf("Saving certificate to: %s", certFile)
	var pemData []string
	for _, c := range certs {
		pemData = append(pemData, strings.TrimSpace(string(pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: c.Raw,
		}))))
	}
	if err := ioutil.WriteFile(certFile, []byte(strings.Join(pemData, "\n")), 0600); err != nil {
		log.Fatalf("Error writing certificate file %q: %v", certFile, err)
	}

	if err := nsUpdate(rr.String(), "", "delete"); err != nil {
		log.Fatalf("error deleting nsupdate record: `%v'", err)
	}
	log.Printf("Done.")
}

func loadAccount(client acme.Client) (acme.Account, error) {
	raw, err := ioutil.ReadFile(accountFile)
	if err != nil {
		return acme.Account{}, err
	}
	var accountFile acmeAccountFile
	if err := json.Unmarshal(raw, &accountFile); err != nil {
		return acme.Account{}, fmt.Errorf("error reading account file %q: %v", accountFile, err)
	}
	account, err := client.UpdateAccount(acme.Account{PrivateKey: accountFile.PrivateKey, URL: accountFile.URL}, true, getContacts()...)
	if err != nil {
		return acme.Account{}, fmt.Errorf("error updating existing account: %v", err)
	}
	return account, nil
}

func createAccount(client acme.Client) (acme.Account, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return acme.Account{}, fmt.Errorf("error creating private key: %v", err)
	}
	account, err := client.NewAccount(privKey, false, true, getContacts()...)
	if err != nil {
		return acme.Account{}, fmt.Errorf("error creating new account: %v", err)
	}
	raw, err := json.Marshal(acmeAccountFile{PrivateKey: privKey, URL: account.URL})
	if err != nil {
		return acme.Account{}, fmt.Errorf("error parsing new account: %v", err)
	}
	if err := ioutil.WriteFile(accountFile, raw, 0600); err != nil {
		return acme.Account{}, fmt.Errorf("error creating account file: %v", err)
	}
	return account, nil
}

func getContacts() []string {
	var contacts []string
	if contactsList != "" {
		contacts = strings.Split(contactsList, ",")
		for i := 0; i < len(contacts); i++ {
			contacts[i] = "mailto:" + contacts[i]
		}
	}
	return contacts
}
