package store

import (
	"log"
	"time"
)


type Certificate struct {
	 SerialNumber string `storm:"id"`
	 SignedKey string `storm:"unique"`
	 KeyID string
	 TTL string
	 CreatedAt time.Time `storm:"index"`
}

func (c *Certificate) save() {
	err := db.Save(&c)

	if err != nil {
		log.Fatalf("Failed to save certificate \n trace : %s", err)
	}
}

func (c *Certificate) get(keyId string) ( []Certificate, error) {

	var certs []Certificate
	err := db.Find("KeyID",keyId, &certs )

	if err != nil {
		return nil, err
	}
	return certs, nil
}