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
	"math/big"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/patrickhaller/acme"
)

var (
	domainList   []string
	contactsList string
	accountFile  string
	nsKeyFile    string
	nameServer   string
	isDebug      bool
	isTesting    bool
	isWildcard   bool
)

var directoryURL = acme.LetsEncryptProduction
var certFileFmt = "%s.pem"
var keyFileFmt = "%s-privkey.pem"
var certFile = ""
var keyFile = ""

type acmeAccountFile struct {
	PrivateKey *ecdsa.PrivateKey `json:"privateKey"`
	URL        string            `json:"url"`
}

var usageFmt = `USAGE: 
 %s [OPTIONS] HOSTNAME [HOSTNAME ...] 
  for wildcard certs set HOSTNAME to the domainname

`

func parseCmdLineFlags() {
	flag.BoolVar(&isWildcard, "wild", false,
		"make a wildcard cert")
	flag.BoolVar(&isDebug, "v", false,
		"\nenable verbose output / debugging")
	flag.BoolVar(&isTesting, "test", false,
		"run against LetsEncrypt staging, not production servers")
	flag.StringVar(&contactsList, "contact", "",
		"comma separated contact emails to use for new accounts")
	flag.StringVar(&accountFile, "accountfile", "account.json",
		"file of account data -- will be auto-created if unset)")
	flag.StringVar(&nameServer, "ns", "",
		"Secondary DNS server to query for the status of the nsupdate")
	flag.StringVar(&nsKeyFile, "nskey", "nsupdate.key",
		"file for the nsupdate key")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), usageFmt, os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
	domainList = flag.Args()
	if len(domainList) == 0 {
		log.Fatal("No domains provided")
	}
	certFile = fmt.Sprintf(certFileFmt, domainList[0])
	keyFile = fmt.Sprintf(keyFileFmt, domainList[0])
	if isWildcard {
		for i, domain := range domainList {
			domainList[i] = fmt.Sprintf("*.%s", domain)
		}
	}
}

func main() {
	parseCmdLineFlags()
	log.SetFlags(0)

	if isTesting {
		directoryURL = acme.LetsEncryptStaging
	}

	client, err := acme.NewClient(directoryURL)
	if err != nil {
		log.Fatalf("Error connecting to acme directory(%s): %v", directoryURL, err)
	}

	var account acme.Account
	if _, err := os.Stat(accountFile); err == nil {
		if account, err = loadAccount(client); err != nil {
			log.Fatalf("Error loading existing account: %v", err)
		}
	} else {
		logD("Creating new account")
		if account, err = createAccount(client); err != nil {
			log.Fatalf("Error creating new account: %v", err)
		}
	}
	logD("Account url: %s", account.URL)

	var acmeIDs []acme.Identifier
	for _, domain := range domainList {
		acmeIDs = append(acmeIDs, acme.Identifier{Type: "dns", Value: domain})
	}

	order, err := client.NewOrder(account, acmeIDs)
	if err != nil {
		log.Fatalf("Error creating new order for domain `%v': %v", domainList, err)
	}
	logD("Order created: %s", order.URL)

	for _, authURL := range order.Authorizations {
		logD("Fetching authorization: %s", authURL)
		auth, err := client.FetchAuthorization(account, authURL)
		if err != nil {
			log.Fatalf("Error fetching authorization url %q: %v", authURL, err)
		}
		logD("Fetched authorization: %s", auth.Identifier.Value)

		chal, ok := auth.ChallengeMap[acme.ChallengeTypeDNS01]
		if !ok {
			log.Fatalf("Unable to find dns challenge for auth %s", auth.Identifier.Value)
		}

		nsDomain := auth.Identifier.Value
		if strings.HasPrefix(auth.Identifier.Value, "*.") {
			idx := strings.Index(auth.Identifier.Value, ".")
			nsDomain = auth.Identifier.Value[idx+1:]
		}
		rr := fmt.Sprintf("_acme-challenge.%s.", nsDomain)
		logD("Using nsupdate domain `%s'", nsDomain)

		logD("Sending nsupdate request")
		err = nsUpdate(rr, acme.EncodeDNS01KeyAuthorization(chal.KeyAuthorization), "add")
		if err != nil {
			log.Fatalf("Error nsupdating authorization %s challenge: %v", auth.Identifier.Value, err)
		}

		logD("Updating challenge")
		chal, err = client.UpdateChallenge(account, chal)
		if err != nil {
			log.Fatalf("Error updating authorization %s challenge url `%s': %v", auth.Identifier.Value, chal.URL, err)
		}

	}

	logD("Generating certificate private key")
	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("Error generating certificate key: %v", err)
	}
	certKeyEnc, err := x509.MarshalECPrivateKey(certKey)
	if err != nil {
		log.Fatalf("Error encoding certificate key file: %v", err)
	}

	logD("Writing key file: %s", keyFile)
	if err := ioutil.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: certKeyEnc,
	}), 0600); err != nil {
		log.Fatalf("Error writing key file %q: %v", keyFile, err)
	}

	logD("Creating csr")
	tpl := &x509.CertificateRequest{
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		PublicKeyAlgorithm: x509.ECDSA,
		PublicKey:          certKey.Public(),
		Subject:            pkix.Name{CommonName: domainList[0]},
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

	logD("Finalising order: %s", order.URL)
	order, err = client.FinalizeOrder(account, order, csr)
	if err != nil {
		log.Fatalf("Error finalizing order: %v", err)
	}

	logD("Fetching certificate: %s", order.Certificate)
	certs, err := client.FetchCertificates(account, order.Certificate)
	if err != nil {
		log.Fatalf("Error fetching order certificates: %v", err)
	}

	logD("Saving certificate to: %s", certFile)
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

	for _, domain := range domainList {
		if err := nsUpdate(domain, "", "delete"); err != nil {
			log.Fatalf("error deleting nsupdate record: `%v'", err)
		}
	}

	logD("Done.")
}

func nsUpdate(rr string, challenge string, addDelete string) error {
	var input string
	if addDelete == "add" {
		input = fmt.Sprintf("update add %s 1 TXT %s", rr, challenge)
	} else {
		input = fmt.Sprintf("update delete %s TXT", rr)
	}
	logD("Sending nsupdate: `%v'", input)
	cmd := exec.Command("nsupdate", "-v", "-k", nsKeyFile)
	cmd.Stdin = strings.NewReader(fmt.Sprintf("%s\nsend\n", input))
	err := cmd.Run()
	if err != nil || nameServer == "" {
		return err
	}

	for i := 0; i < 5; i++ {
		cmd = exec.Command("dig", "-k", nsKeyFile, "TXT", rr, fmt.Sprintf("@%s", nameServer))
		out, _ := cmd.Output()
		logD("dig output: %s", out)
		if strings.Contains(string(out), challenge) {
			return nil
		}
		logD("waiting on nameserver `%s` to see the nsupdate", nameServer)
		time.Sleep(1 * time.Second)
	}
	return fmt.Errorf("too many retries looking for nsupdates")
}

func logD(fmt string, args ...interface{}) {
	if isDebug == true {
		log.Printf(fmt, args...)
	}
}

/* elliptic Curve cannot be unmarshal'ed, so we fake it */

type fakeCurve struct {
	P, N, B, Gx, Gy *big.Int
	BitSize         int
	Name            string
}

type fakePrivateKey struct {
	D, X, Y *big.Int
	Curve   *fakeCurve
}

type fakeAccountFile struct {
	URL        string         `json:"url"`
	PrivateKey fakePrivateKey `json:"privateKey"`
}

func loadAccount(client acme.Client) (acme.Account, error) {
	if _, err := os.Stat(accountFile); err != nil {
		return acme.Account{}, err
	}
	raw, err := ioutil.ReadFile(accountFile)
	if err != nil {
		return acme.Account{}, err
	}
	var pp bytes.Buffer
	json.Indent(&pp, raw, " ", "  ")
	logD("accountFile contents =\n%s", pp.String())

	var faf fakeAccountFile
	if err := json.Unmarshal(raw, &faf); err != nil {
		return acme.Account{}, fmt.Errorf("error reading account file: %v", err)
	}

	var apkey ecdsa.PrivateKey
	apkey.D = faf.PrivateKey.D
	apkey.X = faf.PrivateKey.X
	apkey.Y = faf.PrivateKey.Y
	apkey.Curve = elliptic.P256()

	acct := acme.Account{PrivateKey: &apkey, URL: faf.URL}
	account, err := client.UpdateAccount(acct, true, getContacts()...)
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
