package settings

import (
	"errors"
	"io/ioutil"
	"net"
	"os"

	"github.com/hashicorp/hcl"
)

type Settings struct {
	Recursors  []string             `hcl:"recursors"`
	Forwarders map[string]Forwarder `hcl:"forwarder"`
	Listen     string               `hcl:"listen"`
	LogLevel   string               `hcl:"log-level"`
}
type Forwarder struct {
	Pattern string `hcl:"pattern"`
	Address string `hcl:"address"`
	Limit   int    `hcl:limit`
}

func (s Settings) verify() error {
	// check rcursors
	if len(s.Recursors) == 0 {
		return errors.New("Must have atleast one recursor")
	}

	for _, v := range s.Recursors {
		_, _, err := net.SplitHostPort(v)
		if err != nil {
			return err
		}
	}
	for _, v := range s.Forwarders {
		_, _, err := net.SplitHostPort(v.Address)
		if err != nil {
			return err
		}
	}
	return nil
}

func Load() (Settings, error) {
	path := os.Getenv("FR9_CONFIG")
	if path == "" {
		path = "./config.hcl"
	}
	s, err := ioutil.ReadFile(path)
	if err != nil {
		return Settings{}, errors.New("an error occurred while reading the config: " + err.Error())
	}

	c := Settings{}
	err = hcl.Decode(&c, string(s))
	if err != nil {
		return c, errors.New("an error occurred while decoding the config: " + err.Error())
	}
	err = c.verify()
	return c, err
}
