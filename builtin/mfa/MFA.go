package authenticator

import "github.com/spf13/viper"

// MFA is the interface that wrap the Multifactor authentication logic
type MFA interface {
	Init(config *viper.Viper) error
	Register(user, password string) (bool, error)
}
