package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/tstranex/u2f"
)

const appID = "signmykey"

var trustedFacets = []string{appID}

// Normally these state variables would be stored in a database.
// For the purposes of the demo, we just store them in memory.
var regChallenge *u2f.Challenge
var authChallenge *u2f.Challenge

var registrations []u2f.Registration
var counter uint32

func getRegister(w http.ResponseWriter, r *http.Request) {

	c, err := u2f.NewChallenge(appID, trustedFacets)
	if err != nil {
		log.Printf("u2f.NewChallenge error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	regChallenge = c
	req := u2f.NewWebRegisterRequest(c, registrations)

	log.Printf("registerRequest: %+v", req)
	err = json.NewEncoder(w).Encode(req)
	if err != nil {
		log.Printf("failed to write response: %s\n", err)
	}
}

func postRegister(w http.ResponseWriter, r *http.Request) {

	var regResp u2f.RegisterResponse
	if err := json.NewDecoder(r.Body).Decode(&regResp); err != nil {

		http.Error(w, "invalid response: "+err.Error(), http.StatusBadRequest)
		return
	}

	if regChallenge == nil {
		http.Error(w, "Registration challenge not found", http.StatusBadRequest)
		return
	}

	config := &u2f.Config{SkipAttestationVerify: false}

	reg, err := u2f.Register(regResp, *regChallenge, config)
	if err != nil {
		log.Printf("u2f.Register error: %v", err)
		http.Error(w, "error verifying response", http.StatusInternalServerError)
		return
	}

	registrations = append(registrations, *reg)
	counter = 0

	_, err = w.Write([]byte("success"))
	if err != nil {
		log.Printf("failed to write http message: %s", err)
		return
	}

	fmt.Printf("%+v\n", registrations[0])
}

func getAuth(w http.ResponseWriter, r *http.Request) {

	c, err := u2f.NewChallenge(appID, trustedFacets)
	if err != nil {
		log.Printf("u2f.NewChallenge error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	authChallenge = c
	req := c.SignRequest(registrations)

	log.Printf("authRequest: %+v", req)
	err = json.NewEncoder(w).Encode(req)
	if err != nil {
		log.Printf("failed to write response: %s\n", err)
	}
}

func postAuth(w http.ResponseWriter, r *http.Request) {
	var authResp u2f.SignResponse
	if err := json.NewDecoder(r.Body).Decode(&authResp); err != nil {

		http.Error(w, "invalid response: "+err.Error(), http.StatusBadRequest)
		return
	}

	if regChallenge == nil {
		http.Error(w, "Auth challenge not found", http.StatusBadRequest)
		return
	}

	decData, _ := base64.RawURLEncoding.DecodeString(authResp.ClientData)
	log.Printf("authResponse: %s", string(decData))

	counter, err := registrations[0].Authenticate(authResp, *authChallenge, 1)
	if err != nil {
		http.Error(w, "Auth failed: "+err.Error(), http.StatusUnauthorized)
		return
	}

	fmt.Printf("Auth successful, new counter %d", counter)
}
