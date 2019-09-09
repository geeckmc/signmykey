package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/signmykeyio/signmykey/builtin/store"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/signmykeyio/signmykey/builtin/signer"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

// Signer struct represents Hashicorp Vault options for signing SSH Key.
type Signer struct {
	Address  string
	Port     int
	UseTLS   bool
	RoleID   string
	SecretID string
	Path     string
	Role     string
	SignTTL  string
	fullAddr string
}

type vaultSignReq struct {
	PubKey string `json:"public_key" binding:"required"`
}

// Init method is used to ingest config of Signer
func (v *Signer) Init(config *viper.Viper) error {
	neededEntries := []string{
		"vaultAddr",
		"vaultPort",
		"vaultTLS",
		"vaultRoleID",
		"vaultSecretID",
		"vaultPath",
		"vaultRole",
		"vaultSignTTL",
	}

	for _, entry := range neededEntries {
		if !config.IsSet(entry) {
			return fmt.Errorf("Config entry %s missing for Signer", entry)
		}
	}

	v.Address = config.GetString("vaultAddr")
	v.Port = config.GetInt("vaultPort")
	v.UseTLS = config.GetBool("vaultTLS")
	v.RoleID = config.GetString("vaultRoleID")
	v.SecretID = config.GetString("vaultSecretID")
	v.Path = config.GetString("vaultPath")
	v.Role = config.GetString("vaultRole")
	v.SignTTL = config.GetString("vaultSignTTL")

	var scheme string
	if v.UseTLS {
		scheme = "https"
	} else {
		scheme = "http"
	}
	v.fullAddr = fmt.Sprintf("%s://%s:%d/v1", scheme, v.Address, v.Port)

	return nil
}

// ReadCA method read CA public cert from Hashicorp Vault backend
func (v Signer) ReadCA() (string, error) {
	token, err := v.getToken()
	if err != nil {
		return "", errors.Wrap(err, "error getting auth token")
	}

	client := http.Client{Timeout: time.Second * 10}
	req, err := http.NewRequest(
		"GET",
		fmt.Sprintf("%s/%s/config/ca", v.fullAddr, v.Path),
		nil,
	)
	if err != nil {
		return "", errors.Wrap(err, "error creating new httprequest")
	}
	req.Header.Add("X-Vault-Token", token)

	resp, err := client.Do(req)
	if err != nil {
		return "", errors.Wrap(err, "failed during Get request")
	}
	defer resp.Body.Close() // nolint: errcheck

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("unknown error from Vault with status code %d", resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", errors.Wrap(err, "error reading response body")
	}

	var caResp map[string]interface{}
	err = json.Unmarshal(body, &caResp)
	if err != nil {
		return "", errors.Wrap(err, "error unmarshaling vault response")
	}
	val, ok := caResp["data"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("CA public key not found in Vault response")
	}
	publicKey, ok := val["public_key"].(string)
	if !ok {
		return "", fmt.Errorf("CA public key not found in Vault response")
	}

	// Remove newline
	publicKey = strings.Replace(publicKey, "\n", "", 1)

	return publicKey, nil
}

// Sign method is used to sign passed SSH Key.
func (v Signer) Sign(ctx context.Context, payload []byte, id string, principals []string) (cert string, err error) {

	var signReq vaultSignReq
	err = json.Unmarshal(payload, &signReq)
	if err != nil {
		log.Errorf("json unmarshaling failed: %s", err)
		return "", fmt.Errorf("JSON unmarshaling failed: %s", err)
	}

	token, err := v.getToken()
	if err != nil {
		return "", errors.Wrap(err, "error getting auth token")
	}

	certreq := signer.CertReq{
		Key:        signReq.PubKey,
		ID:         id,
		Principals: principals,
	}
	data, err := json.Marshal(map[string]string{
		"key_id":           certreq.ID,
		"public_key":       certreq.Key,
		"valid_principals": strings.Join(certreq.Principals, ","),
		"ttl":              v.SignTTL,
	})
	if err != nil {
		return "", errors.Wrap(err, "marshaling of sign request payload failed")
	}

	client := http.Client{Timeout: time.Second * 10}
	req, err := http.NewRequest(
		"POST",
		fmt.Sprintf("%s/%s/sign/%s", v.fullAddr, v.Path, v.Role),
		bytes.NewBuffer(data),
	)
	if err != nil {
		return "", errors.Wrap(err, "error creating new httprequest")
	}
	req.Header.Add("X-Vault-Token", token)

	resp, err := client.Do(req)
	if err != nil {
		return "", errors.Wrap(err, "failed during Post request")
	}
	defer resp.Body.Close() // nolint: errcheck

	body, err := ioutil.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return "", fmt.Errorf(">> unknown error from Vault with status code %s", string(body))
	}

	signedKey, serialNumber, err := extractSignedKeyAndSerialNumber(resp)

	err = storeCert(certreq.ID, v.SignTTL, signedKey, serialNumber)

	return signedKey, err
}

func storeCert(keyID string, ttl string, signedKey string, serialNumber string) error {

	cert := store.Certificate{
		KeyID:        keyID,
		TTL:          ttl,
		SerialNumber: serialNumber,
		SignedKey:    signedKey,
		CreatedAt:    time.Now(),
	}

	log.Debugf("certificate to persist : %s" , cert)

	err := cert.Save()

	if err != nil {
		return fmt.Errorf("storm error: %s", err)
	}

	return nil

}

func extractSignedKeyAndSerialNumber(resp *http.Response) (string, string, error) {
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", "", errors.Wrap(err, "error reading response body")
	}

	var signResp map[string]interface{}
	err = json.Unmarshal(body, &signResp)
	if err != nil {
		return "", "", errors.Wrap(err, "error unmarshaling Vault response")
	}
	val, ok := signResp["data"].(map[string]interface{})
	if !ok {
		return "", "", fmt.Errorf("Signed key not found in Vault response")
	}
	signedKey, ok := val["signed_key"].(string)
	if !ok {
		return "", "", fmt.Errorf("Signed key not found in Vault response")
	}

	serialNumber, ok := val["serial_number"].(string)
	if !ok {
		return signedKey, "", fmt.Errorf("Serial number  not found in Vault response")
	}

	return signedKey, serialNumber, nil
}

func (v Signer) getToken() (string, error) {

	data, err := json.Marshal(map[string]string{
		"role_id":   v.RoleID,
		"secret_id": v.SecretID,
	})
	if err != nil {
		return "", err
	}

	client := http.Client{Timeout: time.Second * 10}
	resp, err := client.Post(
		fmt.Sprintf("%s/auth/approle/login", v.fullAddr),
		"application/json",
		bytes.NewBuffer(data))

	if err != nil {
		return "", err
	}
	defer resp.Body.Close() // nolint: errcheck

	if resp.StatusCode == 400 {
		return "", fmt.Errorf("invalid role_id or secret_id")
	}
	if resp.StatusCode == 500 {
		return "", fmt.Errorf("Vault internal server error")
	}
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("unknown error during authentication with status code %d", resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var loginResp map[string]interface{}
	err = json.Unmarshal(body, &loginResp)
	if err != nil {
		return "", err
	}
	val, ok := loginResp["auth"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("client token not found in AppRole login response")
	}
	token, ok := val["client_token"].(string)
	if !ok {
		return "", fmt.Errorf("client token not found in AppRole login response")
	}

	return token, nil
}

// According to ssh documentation certificate can be revoked by adding it to KRL (Keys Revocation List)
// KRL is particular binary file format contains keys data ( keyID, serial number, ... )
// ssh-keygen tools offer an option to create (-k) and update (-u) this file
// the only inputs needed by this tool are : root certificate and a issued certificate to revoke

func (v Signer) RevokeCertificate(ctx context.Context, keyID string) error {
	certs, err := store.Get(keyID)
	if err != nil {
		return err
	}

	const certFilename = "/tmp/cert_to_revoke.pem"
	rootCA := viper.GetString("rootCA")
	krl := viper.GetString("krl")
	
	for _, cert := range certs {
		err := writeFile(certFilename, cert.SignedKey)
		if err != nil {
			return err
		}

		cmd := exec.Command("ssh-keygen", "-ukf", krl, "-s", rootCA, certFilename)

		if err := cmd.Run(); err != nil {
			log.Fatalf("failed to revoke certificate %s", err)
			return err
		}
		_ = deleteFile(certFilename)
	}

	return nil
}

func writeFile(filename string, content string) error {

	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := file.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()

	err = os.Chmod(filename, 0600)
	if err != nil {
		return err
	}

	_, err = file.WriteString(content)
	return err
}

func deleteFile(path string) error {
	 err := os.Remove(path)
	return err
}
