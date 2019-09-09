package addons

import (
	"fmt"
	"github.com/spf13/viper"
)

// Addons is  the interface that wrap the get of Addons configs.
type Addons struct {
	KeycloakHookAuthKey string
}

// Init method is used to ingest config of Addons
func (a *Addons) Init(config *viper.Viper) error {
	neededEntries := []string{
		"keycloakAuthKey",
	}

	for _, entry := range neededEntries {
		if !config.IsSet(entry) {
			return fmt.Errorf("Config entry %s missing for Addons", entry)
		}
	}

	a.KeycloakHookAuthKey = config.GetString("keycloakAuthKey")
	return nil
}


