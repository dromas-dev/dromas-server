package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// envPrefix names serve's environment: each of its flags is also
// DROMAS_SERVER_ and the flag's name, upper case, a dash written _
// (--valkey is DROMAS_SERVER_VALKEY), as etcd reads ETCD_NAME for --name.
const envPrefix = "DROMAS_SERVER"

// envName is the variable of flag name.
func envName(name string) string {
	return envPrefix + "_" + strings.ToUpper(strings.ReplaceAll(name, "-", "_")) //nolint:forbidigo // a flag's name, ASCII, which no protocol token is
}

// fromEnv sets each flag of fs that the command line left unset from its
// variable in the environment, where that is set: a flag given wins over its
// variable, and a variable over the flag's default, Viper's precedence
// (spf13/viper README, "Putting Values in Viper"). The value is set through
// the flag itself, so it is read as the flag reads one, and one it refuses
// names its variable.
func fromEnv(fs *flag.FlagSet) error {
	v := viper.New()
	v.SetEnvPrefix(envPrefix)
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	v.AutomaticEnv()
	if err := v.BindPFlags(fs); err != nil {
		return err
	}
	var errs []error
	fs.VisitAll(func(f *flag.Flag) {
		if f.Changed || !v.IsSet(f.Name) {
			return
		}
		if err := fs.Set(f.Name, v.GetString(f.Name)); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", envName(f.Name), err))
		}
	})
	return errors.Join(errs...)
}

// secret is a secret serve reads from its environment alone, never a flag,
// which a process list and a command line show: the variable name, or the
// file the variable name_FILE names, with one trailing newline dropped, as
// the official PostgreSQL image reads POSTGRES_PASSWORD_FILE. Both set is
// refused. Empty: none.
func secret(name string) (string, error) {
	value, hasValue := os.LookupEnv(name)
	path, hasPath := os.LookupEnv(name + "_FILE")
	switch {
	case hasValue && hasPath:
		return "", fmt.Errorf("%s and %s_FILE are both set: set one", name, name)
	case hasPath:
		b, err := os.ReadFile(path) //nolint:gosec // the file the operator names for the secret
		if err != nil {
			return "", fmt.Errorf("%s_FILE: %w", name, err)
		}
		return strings.TrimSuffix(strings.TrimSuffix(string(b), "\n"), "\r"), nil
	}
	return value, nil
}
