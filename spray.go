// spray.go - Katzenpost client for load testing.
// Copyright (C) 2018  David Stainton.
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

package spray

import (
	"context"
	"path/filepath"
	"sync"
	"time"

	"github.com/katzenpost/core/log"
	cutils "github.com/katzenpost/core/utils"
	"github.com/katzenpost/spray/config"
	"github.com/katzenpost/spray/session"
	"gopkg.in/op/go-logging.v1"
)

type Spray struct {
	cfg        *config.Config
	logBackend *log.Backend
	log        *logging.Logger
	fatalErrCh chan error
	haltedCh   chan interface{}
	haltOnce   *sync.Once

	session *session.Session
}

func (c *Spray) initLogging() error {
	f := c.cfg.Logging.File
	if !c.cfg.Logging.Disable && c.cfg.Logging.File != "" {
		if !filepath.IsAbs(f) {
			f = filepath.Join(c.cfg.Proxy.DataDir, f)
		}
	}

	var err error
	c.logBackend, err = log.New(f, c.cfg.Logging.Level, c.cfg.Logging.Disable)
	if err == nil {
		c.log = c.logBackend.GetLogger("katzenpost/client")
	}
	return err
}

// GetLogger returns a new logger with the given name.
func (c *Spray) GetLogger(name string) *logging.Logger {
	return c.logBackend.GetLogger(name)
}

// Shutdown cleanly shuts down a given Spray instance.
func (c *Spray) Shutdown() {
	c.haltOnce.Do(func() { c.halt() })
}

// Wait waits till the Spray is terminated for any reason.
func (c *Spray) Wait() {
	<-c.haltedCh
}

func (c *Spray) halt() {
	c.log.Noticef("Starting graceful shutdown.")
	if c.session != nil {
		c.session.Halt()
	}
	close(c.fatalErrCh)
	close(c.haltedCh)
}

// NewSession creates and returns a new session or an error.
func (c *Spray) Start() (*session.Session, error) {
	var err error
	timeout := time.Duration(c.cfg.Debug.SessionDialTimeout) * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	c.session, err = session.New(ctx, c.fatalErrCh, c.logBackend, c.cfg)
	return c.session, err
}

// New creates a new Spray with the provided configuration.
func New(cfg *config.Config) (*Spray, error) {
	c := new(Spray)
	c.cfg = cfg
	c.fatalErrCh = make(chan error)
	c.haltedCh = make(chan interface{})
	c.haltOnce = new(sync.Once)

	// Do the early initialization and bring up logging.
	if err := cutils.MkDataDir(c.cfg.Proxy.DataDir); err != nil {
		return nil, err
	}
	if err := c.initLogging(); err != nil {
		return nil, err
	}

	// Ensure we generate keys if the user requested it.
	if c.cfg.Debug.GenerateOnly {
		err := config.GenerateKeys(c.cfg)
		return nil, err
	}

	c.log.Noticef("😼 Katzenpost is still pre-alpha.  DO NOT DEPEND ON IT FOR STRONG SECURITY OR ANONYMITY. 😼")

	// Start the fatal error watcher.
	go func() {
		err, ok := <-c.fatalErrCh
		if !ok {
			return
		}
		c.log.Warningf("Shutting down due to error: %v", err)
		c.Shutdown()
	}()
	return c, nil
}
