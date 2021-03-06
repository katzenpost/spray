// config.go - Katzenpost client configuration.
// Copyright (C) 2018  Yawning Angel, David Stainton.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

// Package config implements the configuration for the Katzenpost client.
package config

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net/mail"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
	nvClient "github.com/katzenpost/authority/nonvoting/client"
	vClient "github.com/katzenpost/authority/voting/client"
	vServerConfig "github.com/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/crypto/eddsa"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/core/log"
	"github.com/katzenpost/core/pki"
	"github.com/katzenpost/core/utils"
	"golang.org/x/net/idna"
	"golang.org/x/text/secure/precis"
)

const (
	defaultLogLevel                    = "NOTICE"
	defaultPollingInterval             = 10
	defaultInitialMaxPKIRetrievalDelay = 10
)

var defaultLogging = Logging{
	Disable: false,
	File:    "",
	Level:   defaultLogLevel,
}

// Proxy is the proxy configuration.
type Proxy struct {
	// DataDir is the absolute path to the data directory.
	DataDir string
}

func (pCfg *Proxy) validate() error {
	if !filepath.IsAbs(pCfg.DataDir) {
		return fmt.Errorf("config: Proxy: DataDir '%v' is not an absolute path", pCfg.DataDir)
	}
	return nil
}

// Logging is the logging configuration.
type Logging struct {
	// Disable disables logging entirely.
	Disable bool

	// File specifies the log file, if omitted stdout will be used.
	File string

	// Level specifies the log level.
	Level string
}

func (lCfg *Logging) validate() error {
	lvl := strings.ToUpper(lCfg.Level)
	switch lvl {
	case "ERROR", "WARNING", "NOTICE", "INFO", "DEBUG":
	case "":
		lCfg.Level = defaultLogLevel
	default:
		return fmt.Errorf("config: Logging: Level '%v' is invalid", lCfg.Level)
	}
	lCfg.Level = lvl // Force uppercase.
	return nil
}

// Debug is the debug configuration.
type Debug struct {
	// TargetProvider is the target service provider for our probes.
	TargetProvider string

	// TargetRecipient is the target recipient for our probes.
	TargetRecipient string

	// SendBurst controls the burst rate of the egress rate limiter.
	SendBurst int

	// SendRate controls the egress rate limiter and is packets per second.
	SendRate float64

	// SessionDialTimeout is the number of seconds that a session dial
	// is allowed to take until it is cancelled.
	SessionDialTimeout int

	// InitialMaxPKIRetrievalDelay is the initial maximum number of seconds
	// we are willing to wait for the retreival of the PKI document.
	InitialMaxPKIRetrievalDelay int

	// CaseSensitiveUserIdentifiers disables the forced lower casing of
	// the Account `User` field.
	CaseSensitiveUserIdentifiers bool

	// GenerateOnly halts and cleans up right after long term
	// key generation.
	GenerateOnly bool

	// PollingInterval is the interval in seconds that will be used to
	// poll the receive queue.  By default this is 30 seconds.  Reducing
	// the value too far WILL result in uneccesary Provider load, and
	// increasing the value too far WILL adversely affect large message
	// transmit performance.
	PollingInterval int
}

func (d *Debug) fixup() {
	if d.PollingInterval == 0 {
		d.PollingInterval = defaultPollingInterval
	}
	if d.InitialMaxPKIRetrievalDelay == 0 {
		d.InitialMaxPKIRetrievalDelay = defaultInitialMaxPKIRetrievalDelay
	}
}

// NonvotingAuthority is a non-voting authority configuration.
type NonvotingAuthority struct {
	// Address is the IP address/port combination of the authority.
	Address string

	// PublicKey is the authority's public key.
	PublicKey *eddsa.PublicKey
}

// New constructs a pki.Client with the specified non-voting authority config.
func (nvACfg *NonvotingAuthority) New(l *log.Backend) (pki.Client, error) {
	cfg := &nvClient.Config{
		LogBackend:    l,
		Address:       nvACfg.Address,
		PublicKey:     nvACfg.PublicKey,
		DialContextFn: nil,
	}
	return nvClient.New(cfg)
}

func (nvACfg *NonvotingAuthority) validate() error {
	if nvACfg.PublicKey == nil {
		return fmt.Errorf("PublicKey is missing")
	}
	return nil
}

// VotingAuthority is a voting authority configuration.
type VotingAuthority struct {
	Peers []*vServerConfig.AuthorityPeer
}

// New constructs a pki.Client with the specified non-voting authority config.
func (vACfg *VotingAuthority) New(l *log.Backend) (pki.Client, error) {
	cfg := &vClient.Config{
		LogBackend:    l,
		Authorities:   vACfg.Peers,
		DialContextFn: nil,
	}
	return vClient.New(cfg)
}

func (vACfg *VotingAuthority) validate() error {
	if vACfg.Peers == nil || len(vACfg.Peers) == 0 {
		return errors.New("VotingAuthority failure, must specify at least one peer.")
	}
	for _, peer := range vACfg.Peers {
		err := peer.Validate()
		if err != nil {
			return err
		}
	}
	return nil
}

// NewPKIClient returns a voting or nonvoting implementation of pki.Client or error
func (c *Config) NewPKIClient(l *log.Backend) (pki.Client, error) {
	switch {
	case c.NonvotingAuthority != nil:
		return c.NonvotingAuthority.New(l)
	case c.VotingAuthority != nil:
		return c.VotingAuthority.New(l)
	}
	return nil, fmt.Errorf("No Authority found")
}

// Account is a provider account configuration.
type Account struct {
	// User is the account user name.
	User string

	// Provider is the provider identifier used by this account.
	Provider string

	// ProviderKeyPin is the optional pinned provider signing key.
	ProviderKeyPin *eddsa.PublicKey
}

func (accCfg *Account) fixup(cfg *Config) error {
	var err error
	if !cfg.Debug.CaseSensitiveUserIdentifiers {
		accCfg.User, err = precis.UsernameCaseMapped.String(accCfg.User)
	} else {
		accCfg.User, err = precis.UsernameCasePreserved.String(accCfg.User)
	}
	if err != nil {
		return err
	}

	accCfg.Provider, err = idna.Lookup.ToASCII(accCfg.Provider)
	return err
}

func (accCfg *Account) toEmailAddr() (string, error) {
	addr := fmt.Sprintf("%s@%s", accCfg.User, accCfg.Provider)
	if _, err := mail.ParseAddress(addr); err != nil {
		return "", fmt.Errorf("User/Provider does not form a valid e-mail address: %v", err)
	}
	return addr, nil
}

func (accCfg *Account) validate(cfg *Config) error {
	if accCfg.User == "" {
		return fmt.Errorf("User is missing")
	}
	if accCfg.Provider == "" {
		return fmt.Errorf("Provider is missing")
	}
	return nil
}

// Config is the top level client configuration.
type Config struct {
	Proxy              *Proxy
	Logging            *Logging
	Debug              *Debug
	NonvotingAuthority *NonvotingAuthority
	VotingAuthority    *VotingAuthority
	Account            *Account
}

// FixupAndValidate applies defaults to config entries and validates the
// supplied configuration.  Most people should call one of the Load variants
// instead.
func (c *Config) FixupAndValidate() error {
	// Handle missing sections if possible.
	if c.Proxy == nil {
		return errors.New("config: No Proxy block was present")
	}
	if c.Logging == nil {
		c.Logging = &defaultLogging
	}
	if c.Debug == nil {
		return errors.New("config: No Debug block was present")
	} else {
		c.Debug.fixup()
	}

	// Validate/fixup the various sections.
	if err := c.Proxy.validate(); err != nil {
		return err
	}
	if err := c.Logging.validate(); err != nil {
		return err
	}
	switch {
	case c.NonvotingAuthority == nil && c.VotingAuthority != nil:
		if err := c.VotingAuthority.validate(); err != nil {
			return fmt.Errorf("config: NonvotingAuthority is invalid: %s", err)
		}
	case c.NonvotingAuthority != nil && c.VotingAuthority == nil:
		if err := c.NonvotingAuthority.validate(); err != nil {
			return fmt.Errorf("config: NonvotingAuthority is invalid: %s", err)
		}
	default:
		return fmt.Errorf("config: Authority configuration is invalid")
	}

	// account
	if err := c.Account.fixup(c); err != nil {
		return fmt.Errorf("config: Account is invalid (User): %v", err)
	}
	addr, err := c.Account.toEmailAddr()
	if err != nil {
		return fmt.Errorf("config: Account is invalid (Identifier): %v", err)
	}
	if err := c.Account.validate(c); err != nil {
		return fmt.Errorf("config: Account '%v' is invalid: %v", addr, err)
	}

	return nil
}

// Load parses and validates the provided buffer b as a config file body and
// returns the Config.
func Load(b []byte, forceGenOnly bool) (*Config, error) {
	cfg := new(Config)
	md, err := toml.Decode(string(b), cfg)
	if err != nil {
		return nil, err
	}
	if undecoded := md.Undecoded(); len(undecoded) != 0 {
		return nil, fmt.Errorf("config: Undecoded keys in config file: %v", undecoded)
	}
	if err := cfg.FixupAndValidate(); err != nil {
		return nil, err
	}
	if forceGenOnly {
		cfg.Debug.GenerateOnly = true
	}
	return cfg, nil
}

// GenerateKeys makes the key dir and then
// generates the keys and saves them into pem files
func GenerateKeys(cfg *Config) error {
	id := cfg.Account.User + "@" + cfg.Account.Provider
	basePath := filepath.Join(cfg.Proxy.DataDir, id)
	if err := utils.MkDataDir(basePath); err != nil {
		return err
	}
	_, err := LoadLinkKey(basePath)
	return err
}

// LoadLinkKey can load or generate the keys
func LoadLinkKey(basePath string) (*ecdh.PrivateKey, error) {
	linkPriv := filepath.Join(basePath, "link.private.pem")
	linkPub := filepath.Join(basePath, "link.public.pem")
	var err error
	linkKey := new(ecdh.PrivateKey)
	if linkKey, err = ecdh.Load(linkPriv, linkPub, rand.Reader); err != nil {
		return nil, err
	}
	return linkKey, nil
}

// LoadFile loads, parses, and validates the provided file and returns the
// Config.
func LoadFile(f string, forceGenOnly bool) (*Config, error) {
	b, err := ioutil.ReadFile(f)
	if err != nil {
		return nil, err
	}
	return Load(b, forceGenOnly)
}
