package store

import (
	"github.com/asdine/storm"
	"log"
)

var (
	db *storm.DB
)

func init() {

	var err error
	db, err = storm.Open("signmykey.db")

	if err != nil {
		log.Fatalf("Failed to init database\n trace : %s", err)
	}
}


