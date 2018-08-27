package client

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/flynn/u2f/u2fhid"
	"github.com/flynn/u2f/u2ftoken"
	"github.com/tstranex/u2f"
)

func getAuth(client *http.Client, url string) ([]byte, []byte, string, error) {
	authResponse, err := client.Get(url)

	if err != nil {
		return []byte{}, []byte{}, "", fmt.Errorf("error getting auth challenge: %s", err)
	}
	defer authResponse.Body.Close() //nolint: errcheck

	buf, err := ioutil.ReadAll(authResponse.Body)
	if err != nil {
		return []byte{}, []byte{}, "", fmt.Errorf("error reading auth challenge: %s", err)
	}

	var auth u2f.WebSignRequest
	err = json.Unmarshal(buf, &auth)
	if err != nil {
		return []byte{}, []byte{}, "", fmt.Errorf("error unmarshalling auth challenge: %s", err)
	}

	if len(auth.RegisteredKeys) == 0 {
		return []byte{}, []byte{}, "", errors.New("no auth keys found in server request")
	}

	clientData := u2f.ClientData{
		Typ:       "navigator.id.getAssertion",
		Challenge: auth.Challenge,
		Origin:    auth.AppID,
	}

	clientDataJSON, err := json.Marshal(clientData)
	if err != nil {
		return []byte{}, []byte{}, "", fmt.Errorf("error marshaling clientData to json: %s", err)
	}

	keyHandle, err := base64.RawURLEncoding.DecodeString(auth.RegisteredKeys[0].KeyHandle)
	if err != nil {
		return []byte{}, []byte{}, "", fmt.Errorf("error decoding auth request key handle: %s", err)
	}

	return clientDataJSON, keyHandle, auth.AppID, nil
}

func postAuth(client *http.Client, url string, keyHandle []byte, clientData []byte, authData []byte) error {
	authResponse := u2f.SignResponse{
		KeyHandle:     base64.RawURLEncoding.EncodeToString(keyHandle),
		ClientData:    base64.RawURLEncoding.EncodeToString(clientData),
		SignatureData: base64.RawURLEncoding.EncodeToString(authData),
	}

	authResponseJSON, err := json.Marshal(authResponse)
	if err != nil {
		return fmt.Errorf("error marshaling auth response: %s", err)
	}

	res, err := client.Post(url, "application/json", bytes.NewBuffer(authResponseJSON))
	if err != nil {
		return fmt.Errorf("error posting auth challenge: %s", err)
	}
	defer res.Body.Close() //nolint: errcheck

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return fmt.Errorf("error getting auth challenge response")
	}

	fmt.Println(string(body))

	return nil
}

func authWithToken(clientData []byte, appID string, keyHandle []byte) (signature []byte, counter uint32, err error) {

	devices, err := u2fhid.Devices()
	if err != nil {
		return []byte{}, counter, fmt.Errorf("error getting U2F devices: %s", err)
	}
	if len(devices) == 0 {
		return []byte{}, counter, errors.New("no U2F token found")
	}

	device, err := u2fhid.Open(devices[0])
	if err != nil {
		return []byte{}, counter, fmt.Errorf("error opening U2F device: %s", err)
	}
	defer device.Close()

	t := u2ftoken.NewToken(device)
	clientHash := sha256.Sum256(clientData)
	appHash := sha256.Sum256([]byte(appID))

	fmt.Println("registering, provide user presence")
	var authData *u2ftoken.AuthenticateResponse
	for {
		authData, err = t.Authenticate(u2ftoken.AuthenticateRequest{
			Challenge:   clientHash[:],
			Application: appHash[:],
			KeyHandle:   keyHandle,
		})

		if err == u2ftoken.ErrPresenceRequired {
			time.Sleep(200 * time.Millisecond)
			continue
		} else if err != nil {
			return []byte{}, counter, err
		}
		break
	}

	return authData.RawResponse, authData.Counter, nil
}
