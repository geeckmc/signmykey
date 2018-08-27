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

func getRegistration(client *http.Client, url string) ([]byte, string, error) {

	registrationResponse, err := client.Get(url)
	if err != nil {
		return []byte{}, "", fmt.Errorf("error getting register challenge: %s", err)
	}
	defer registrationResponse.Body.Close() //nolint: errcheck

	buf, err := ioutil.ReadAll(registrationResponse.Body)
	if err != nil {
		return []byte{}, "", fmt.Errorf("error reading register challenge: %s", err)
	}

	var registration u2f.WebRegisterRequest
	err = json.Unmarshal(buf, &registration)
	if err != nil {
		return []byte{}, "", fmt.Errorf("error unmarshalling register challenge: %s", err)
	}

	if len(registration.RegisterRequests) == 0 {
		return []byte{}, "", errors.New("no register challenge found")
	}

	clientData := u2f.ClientData{
		Typ:       "navigator.id.finishEnrollment",
		Challenge: registration.RegisterRequests[0].Challenge,
		Origin:    registration.AppID,
	}

	clientDataJSON, err := json.Marshal(clientData)
	if err != nil {
		return []byte{}, "", fmt.Errorf("error marshaling clientData to json: %s", err)
	}

	return clientDataJSON, registration.AppID, nil
}

func postRegistration(client *http.Client, url string, version string, clientData []byte, registrationData []byte) error {
	RegisterResponse := u2f.RegisterResponse{
		Version:          version,
		ClientData:       base64.RawURLEncoding.EncodeToString(clientData),
		RegistrationData: base64.RawURLEncoding.EncodeToString(registrationData),
	}

	registerResponseJSON, err := json.Marshal(RegisterResponse)
	if err != nil {
		return fmt.Errorf("error marshaling register response: %s", err)
	}

	res, err := client.Post("http://127.0.0.1:3000/register", "application/json", bytes.NewBuffer(registerResponseJSON))
	if err != nil {
		return fmt.Errorf("error posting register challenge: %s", err)
	}
	defer res.Body.Close() //nolint: errcheck

	return nil

}

func registerWithToken(clientData []byte, appID string) (version string, registrationData []byte, keyHandle []byte, err error) {

	devices, err := u2fhid.Devices()
	if err != nil {
		return version, registrationData, keyHandle, fmt.Errorf("error getting U2F devices: %s", err)
	}
	if len(devices) == 0 {
		return version, registrationData, keyHandle, errors.New("no U2F token found")
	}

	device, err := u2fhid.Open(devices[0])
	if err != nil {
		return version, registrationData, keyHandle, fmt.Errorf("error opening U2F device: %s", err)
	}
	defer device.Close()

	t := u2ftoken.NewToken(device)
	clientHash := sha256.Sum256(clientData)
	appHash := sha256.Sum256([]byte(appID))

	fmt.Println("registering, provide user presence")
	for {
		registrationData, err = t.Register(u2ftoken.RegisterRequest{
			Challenge:   clientHash[:],
			Application: appHash[:],
		})
		if err == u2ftoken.ErrPresenceRequired {
			time.Sleep(200 * time.Millisecond)
			continue
		} else if err != nil {
			return version, registrationData, keyHandle, err
		}
		break
	}
	version, err = t.Version()
	if err != nil {
		return version, registrationData, keyHandle, fmt.Errorf("error getting token U2F version: %s", err)
	}

	keyHandle, err = getKeyHandle(registrationData)
	if err != nil {
		return version, registrationData, keyHandle, fmt.Errorf("error getting key handler: %s", err)
	}

	return version, registrationData, keyHandle, nil
}

func getKeyHandle(rawData []byte) ([]byte, error) {

	if len(rawData) < 67 {
		return []byte{}, errors.New("rawData slice to small to find keyhandle length")
	}
	khLen := int(rawData[66])

	if len(rawData) < (67 + khLen) {
		return []byte{}, errors.New("rawData slice to small to find key handle")
	}

	return rawData[67:(khLen + 67)], nil
}
