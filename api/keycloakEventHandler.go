package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/go-chi/render"
	log "github.com/sirupsen/logrus"
)

type KeycloakResp struct {
	RealmId      string `json:"realmId"`
	ResourceType string `json:"realmId"`
	OperationType string `json:"realmId"`
	Representation map[string]interface{}
}


func KeycloakEnventHandler(w http.ResponseWriter, r *http.Request) {

	authKey := r.Header.Get("X-Auth-Key")

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
	err = json.Unmarshal(body, &keycloakResponse)

	if err != nil {
		log.Errorf("failed to parse keycloak payload: %s", err)
		render.Status(r, 400)
		return
	}

	log.Debugf("event from server: %s", string(body))

	dispatchAction(r.Context(),&keycloakResponse)

	render.JSON(w, r, map[string]string{"ack": "recieved"})
}

func dispatchAction(context context.Context, p *KeycloakResp) {
	switch p.ResourceType {
	case "USER":
		if p.OperationType == "DELETE" || (p.OperationType == "UPDATE" && p.Representation["enabled"].(bool) == false) {

			keyID := fmt.Sprintf("oidc-%s", p.Representation["username"].(string))
			log.Debugf("request to revoke certificates with key id = %s", keyID)

			err := config.Signer.RevokeCertificate(context,keyID)

			if err != nil {
				log.Fatalf("failed to revoke certs %s", err)
			}
		}

	}
}
