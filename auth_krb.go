package mysql

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/openshift/gssapi"
)

type KerberosLookup struct {
	User                    string `json:"user"`
	DBName                  string `json:"database"`
	Address                 string `json:"address"`
	CredentialCacheFilename string `json:"credentialCache"`
}

func (mc *mysqlConn) authKerberos(authData []byte) ([]byte, error) {
	l := log.New(os.Stderr, "GOKRB5 Client: ", log.LstdFlags)
	log.Printf("Addr: %s DBName: %s User: %s", mc.cfg.Addr, mc.cfg.DBName, mc.cfg.User)

	krb5ConfigFilename := os.Getenv("KRB5_CONFIG")
	// try common location for config
	if krb5ConfigFilename == "" {
		krb5ConfigFilename = "/etc/krb5.conf"
	}
	log.Printf("using KRB5_CONFIG: %s", krb5ConfigFilename)

	krb5Config, err := ioutil.ReadFile(krb5ConfigFilename)
	if err != nil {
		log.Fatalf("could not read krb5.conf (%s): %v", krb5ConfigFilename, err)
	}
	// decode the SPN from authData
	spn, spnRealm, upnRealm := krb5ParseAuthData(authData)
	log.Printf("SPN: %s", spn)
	log.Printf("SPN Realm: %s", spnRealm)
	log.Printf("UPN Realm: %s", upnRealm)
	conf, err := config.NewFromString(string(krb5Config))
	if err != nil {
		log.Fatalf("could not load krb5.conf: %v", err)
	}
	// set the default realm to the parsed realm
	conf.LibDefaults.DefaultRealm = spnRealm

	// load keytab from file
	keytabFilename := os.Getenv("KRB5_CLIENT_KTNAME")
	if keytabFilename == "" {
		// try default
		keytabFilename = conf.LibDefaults.DefaultClientKeytabName
	}

	var cl *client.Client

	krb5keytabContent, err := ioutil.ReadFile(keytabFilename)
	if err != nil && !os.IsNotExist(err) {
		log.Printf("error reading keytab: %s", keytabFilename)
		return nil, err
	}

	if os.IsNotExist(err) {
		// if there is a lookup file, try to use it first
		haveMatchedCC := false
		credentialCacheFile := ""
		if os.Getenv("KRB5_CC_LOOKUP_FILE") != "" {
			// lookup enabled, check for a match using cfg
			lookupFile := os.Getenv("KRB5_CC_LOOKUP_FILE")
			credentialCacheFile = getCredentialCacheFromLookup(lookupFile, mc.cfg)
			if credentialCacheFile != "" {
				haveMatchedCC = true
				log.Printf("using credential cache from lookup: %s", credentialCacheFile)
				// important - this must be set to match our actual file
				os.Setenv("KRB5CCNAME", credentialCacheFile)
				log.Printf("setting KRB5CCNAME for this session to: %s", credentialCacheFile)
			} else {
				log.Printf("match not found in lookup file: %s", lookupFile)
			}
		}
		if !haveMatchedCC {
			var ok bool
			credentialCacheFile, ok = os.LookupEnv("KRB5CCNAME")
			if !ok {
				// KRB5CCNAME is not set, return the error from loading the Keytab.
				return nil, err
			}
			log.Printf("using credential cache from KRB5CCNAME: %s", credentialCacheFile)
		}
		cCache, err := credentials.LoadCCache(credentialCacheFile)
		if err != nil {
			return nil, err
		}
		cl, err = client.NewFromCCache(cCache, conf, client.Logger(l), client.DisablePAFXFAST(true), client.AssumePreAuthentication(false))
		if err != nil {
			return nil, err
		}
	} else {
		log.Printf("using keytab: %s", keytabFilename)
		log.Printf("krb5 default realm: %s", conf.LibDefaults.DefaultRealm)
		log.Printf("krb5 kdc: %v", conf.Realms[0].KDC)

		kt := keytab.New()
		err = kt.Unmarshal(krb5keytabContent)
		if err != nil {
			return nil, err
		}
		cl = client.NewWithKeytab(mc.cfg.User, spnRealm, kt, conf, client.Logger(l), client.DisablePAFXFAST(true), client.AssumePreAuthentication(false))
	}

	// Log in the client
	err = cl.Login()
	if err != nil {
		log.Fatalf("could not login client: %v", err)
	}

	_, _, err = cl.GetServiceTicket(spn)
	if err != nil {
		log.Printf("failed to get service ticket: %v\n", err)
	}
	//log.Println("ok got service ticket...")

	dl, err := gssapi.Load(nil)
	if err != nil {
		return nil, err
	}

	buf_name, err := dl.MakeBufferBytes([]byte(spn))
	if err != nil {
		return nil, err
	}
	name, err := buf_name.Name(dl.GSS_KRB5_NT_PRINCIPAL_NAME)
	input_buf, _ := dl.MakeBuffer(0)
	if err != nil {
		return nil, err
	}
	cname, _ := name.Canonicalize(dl.GSS_MECH_KRB5)
	//
	// TODO: need to implement mutual authentication to ensure both sides agree?
	//reqFlags := gssapi.GSS_C_DELEG_FLAG + gssapi.GSS_C_MUTUAL_FLAG
	//
	// allow delegation
	//
	reqFlags := gssapi.GSS_C_DELEG_FLAG

	//reqFlags = 0
	_, _, token, _, _, err := dl.InitSecContext(
		dl.GSS_C_NO_CREDENTIAL,
		nil,
		cname,
		dl.GSS_C_NO_OID,
		reqFlags,
		0,
		dl.GSS_C_NO_CHANNEL_BINDINGS,
		input_buf)

	if token == nil {
		return nil, err
	}
	log.Println("login success: gssapi security context created")

	return token.Bytes(), err

}

// Parse KRB5 authentication data.
//
// Get the SPN and REALM from the authentication data packet.
//
// Format:
//		SPN string length two bytes <B1> <B2> +
//		SPN string +
//		UPN realm string length two bytes <B1> <B2> +
//		UPN realm string
//
//Returns:
//		'spn' and 'realm'
func krb5ParseAuthData(authData []byte) (string, string, string) {
	buf := bytes.NewBuffer(authData[:2])
	spnLen := int16(0)
	binary.Read(buf, binary.LittleEndian, &spnLen)
	packet := authData[2:]
	spn := string(packet[:spnLen])
	// next realm
	packet = packet[spnLen:]
	buf = bytes.NewBuffer(packet[:2])
	UPNRealmLen := int16(0)
	binary.Read(buf, binary.LittleEndian, &UPNRealmLen)
	packet = packet[2:]
	UPNRealm := string(packet[:UPNRealmLen])
	// remove realm from SPN
	spn = strings.TrimSuffix(spn, "@"+UPNRealm)
	// check if there is a different realm in the spn
	if strings.Contains(spn, "@") {
		// get the realm supplied by the spn
		// if the SPM realm does not match the auth realm, return the SPN supplied realm
		SPNRealm := strings.Split(spn, "@")[1]
		spn = strings.TrimSuffix(spn, "@"+SPNRealm)
		if SPNRealm != UPNRealm {
			return spn, SPNRealm, UPNRealm
		}
	}
	return spn, UPNRealm, UPNRealm
}

func getCredentialCacheFromLookup(lookupFile string, cfg *Config) string {
	log.Printf("reading credential cache lookup: %s", lookupFile)
	content, err := ioutil.ReadFile(lookupFile)
	if err != nil {
		log.Printf("error reading: %s, %v", lookupFile, err)
		return ""
	}
	var lookups []KerberosLookup
	err = json.Unmarshal(content, &lookups)
	if err != nil {
		log.Printf("error parsing: %s, %v", lookupFile, err)
		return ""
	}
	// find cache file
	for _, item := range lookups {
		if item.Address == cfg.Addr && item.DBName == cfg.DBName && item.User == cfg.User {
			log.Printf("matched: %+v", item)
			return item.CredentialCacheFilename
		}
	}
	log.Printf("no match found for %s", cfg.Addr)
	return ""
}
