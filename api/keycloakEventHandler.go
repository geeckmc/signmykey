package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"strings"

	"github.com/go-chi/render"
	log "github.com/sirupsen/logrus"
)

type KeycloakResp struct {
	RealmId      string `json:"realmId"`
	ResourceType string `json:"resourceType"`
	OperationType string `json:"operationType"`
	Representation map[string]*json.RawMessage `json:"representation"`
}


func KeycloakEnventHandler(w http.ResponseWriter, r *http.Request) {

	authKey := r.Header.Get("X-Auth-Key")

	requestDump, err := httputil.DumpRequest(r, true)
	if err != nil {
		log.Error(err)
	}
	log.Debug(string(requestDump))

	if len(strings.TrimSpace(authKey)) == 0 || authKey != config.Addons.KeycloakHookAuthKey {
		log.Errorf("invalid auth key from keycloack: %s", authKey)
		render.Status(r, 401)
		render.JSON(w, r, map[string]string{"error": "invalid auth key"})
		return
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Errorf("failed to read body: %s", err)
		render.Status(r, 400)
		render.JSON(w, r, map[string]string{"error": "failed to read body"})
		return
	}

	keycloakResponse := KeycloakResp{}

	cleanBody := strings.Replace(string(body), "\\", "", -1)

	err = json.Unmarshal( []byte(cleanBody), &keycloakResponse)

	if err != nil {
		log.Errorf("failed to parse keycloak payload: %s", err)
		render.Status(r, 400)
		return
	}

	log.Debugf("event from server: %s", string(body))

	dispatchAction(r.Context(),keycloakResponse)

	render.JSON(w, r, map[string]string{"ack": "recieved"})
}

func dispatchAction(context context.Context, p KeycloakResp) {
	switch p.ResourceType {
	case "USER":
		var userIsEnabled bool
		var username string

		_ = json.Unmarshal(*p.Representation["enabled"] ,&userIsEnabled)
		_ = json.Unmarshal(*p.Representation["username"] ,&username)

		if p.OperationType == "DELETE" || (p.OperationType == "UPDATE" &&  userIsEnabled == false) {

			keyID := fmt.Sprintf("oidc-%s", username)
			log.Debugf("request to revoke certificates with key id = %s", keyID)

			err := config.Signer.RevokeCertificate(context,keyID)

			if err != nil {
				log.Fatalf("failed to revoke certs %s", err)
			}
		}

	}
}
