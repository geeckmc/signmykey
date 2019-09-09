package store

import (
	"github.com/asdine/storm"
	"github.com/spf13/viper"
	"log"
)

var (
	db *storm.DB
)

func init() {

	var err error
	viper.SetDefault("db", "/etc/signmykey/signmykey.db")
	db, err = storm.Open(viper.GetString("db"))

	if err != nil {
		log.Fatalf("Failed to init database\n trace : %s", err)
	}
}


