package store

import (
	"time"
)

type Certificate struct {
	KeyID        string
	TTL          string
	SerialNumber string    `storm:"id"`
	SignedKey    string    `storm:"unique"`
	CreatedAt    time.Time `storm:"index"`
}

func (c Certificate) Save() error {
	err := db.Save(c)
	return err
}

func  Get(keyId string) ([]Certificate, error) {

	var certs []Certificate
	err := db.Find("KeyID", keyId, &certs)

	if err != nil {
		return nil, err
	}
	return certs, nil
}
