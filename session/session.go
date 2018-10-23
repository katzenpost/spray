// session.go - mixnet spray session
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

package session

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	mrand "math/rand"
	"path/filepath"
	"sync"
	"time"

	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/log"
	"github.com/katzenpost/core/pki"
	"github.com/katzenpost/core/sphinx/constants"
	cutils "github.com/katzenpost/core/utils"
	"github.com/katzenpost/core/worker"
	"github.com/katzenpost/minclient"
	"github.com/katzenpost/spray/config"
	"github.com/katzenpost/spray/internal/pkiclient"
	"gopkg.in/op/go-logging.v1"
)

// ServiceDescriptor describe a mixnet Provider-side service.
type ServiceDescriptor struct {
	// Name of the service.
	Name string
	// Provider name.
	Provider string
}

// FindServices is a helper function for finding Provider-side services in the PKI document.
func FindServices(capability string, doc *pki.Document) []ServiceDescriptor {
	services := []ServiceDescriptor{}
	for _, provider := range doc.Providers {
		for cap := range provider.Kaetzchen {
			if cap == capability {
				serviceID := ServiceDescriptor{
					Name:     provider.Kaetzchen[cap]["endpoint"].(string),
					Provider: provider.Name,
				}
				services = append(services, serviceID)
			}
		}
	}
	return services
}

type workerOp interface{}

// Session is the struct type that keeps state for a given session.
type Session struct {
	worker.Worker

	cfg       *config.Config
	pkiClient pki.Client
	minclient *minclient.Client
	log       *logging.Logger

	fatalErrCh chan error
	haltedCh   chan interface{}
	haltOnce   sync.Once

	linkKey   *ecdh.PrivateKey
	opCh      chan workerOp
	onlineAt  time.Time
	hasPKIDoc bool

	cryptoChan chan []byte
	egressChan chan []byte
}

// New establishes a session with provider using key.
// This method will block until session is connected to the Provider.
func New(ctx context.Context, fatalErrCh chan error, logBackend *log.Backend, cfg *config.Config) (*Session, error) {
	var err error

	// create a pkiclient for our own client lookups
	// AND create a pkiclient for minclient's use
	pkiClient, err := cfg.NewPKIClient(logBackend)
	if err != nil {
		return nil, err
	}

	// create a pkiclient for minclient's use
	pkiClient2, err := cfg.NewPKIClient(logBackend)
	if err != nil {
		return nil, err
	}
	pkiCacheClient := pkiclient.New(pkiClient2)

	log := logBackend.GetLogger(fmt.Sprintf("%s@%s_c", cfg.Account.User, cfg.Account.Provider))

	s := &Session{
		cfg:        cfg,
		pkiClient:  pkiClient,
		log:        log,
		fatalErrCh: fatalErrCh,
		opCh:       make(chan workerOp),
	}
	id := cfg.Account.User + "@" + cfg.Account.Provider
	basePath := filepath.Join(cfg.Proxy.DataDir, id)
	if err := cutils.MkDataDir(basePath); err != nil {
		return nil, err
	}

	err = s.loadKeys(basePath)
	if err != nil {
		return nil, err
	}

	// Configure and bring up the minclient instance.
	clientCfg := &minclient.ClientConfig{
		User:                cfg.Account.User,
		Provider:            cfg.Account.Provider,
		ProviderKeyPin:      cfg.Account.ProviderKeyPin,
		LinkKey:             s.linkKey,
		LogBackend:          logBackend,
		PKIClient:           pkiCacheClient,
		OnConnFn:            s.onConnection,
		OnMessageFn:         s.onMessage,
		OnACKFn:             s.onACK,
		OnDocumentFn:        s.onDocument,
		DialContextFn:       nil,
		MessagePollInterval: time.Duration(cfg.Debug.PollingInterval) * time.Second,
		EnableTimeSync:      false, // Be explicit about it.
	}

	s.minclient, err = minclient.New(clientCfg)
	if err != nil {
		return nil, err
	}

	// block until we get the first PKI document
	// and then set our timers accordingly
	_, err = s.awaitFirstPKIDoc(ctx)
	if err != nil {
		return nil, err
	}

	s.Go(s.sendWorker)
	return s, nil
}

func (s *Session) awaitFirstPKIDoc(ctx context.Context) (*pki.Document, error) {
	for {
		var qo workerOp
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-s.HaltCh():
			s.log.Debugf("Terminating gracefully.")
			return nil, errors.New("Terminating gracefully.")
		case <-time.After(time.Duration(s.cfg.Debug.InitialMaxPKIRetrievalDelay) * time.Second):
			return nil, errors.New("Timeout failure awaiting first PKI document.")
		case qo = <-s.opCh:
		}
		switch op := qo.(type) {
		case opNewDocument:
			// Determine if PKI doc is valid. If not then abort.
			err := s.isDocValid(op.doc)
			if err != nil {
				s.log.Errorf("Aborting, PKI doc is not valid for the Loopix decoy traffic use case: %v", err)
				err := fmt.Errorf("Aborting, PKI doc is not valid for the Loopix decoy traffic use case: %v", err)
				s.fatalErrCh <- err
				return nil, err
			}
			return op.doc, nil
		default:
			continue
		}
	}
}

func (s *Session) loadKeys(basePath string) error {
	// Load link key.
	var err error
	if s.linkKey, err = config.LoadLinkKey(basePath); err != nil {
		s.log.Errorf("Failure to load link keys: %s", err)
		return err
	}
	return nil
}

// GetService returns a randomly selected service
// matching the specified service name
func (s *Session) GetService(serviceName string) (*ServiceDescriptor, error) {
	doc := s.minclient.CurrentDocument()
	if doc == nil {
		return nil, errors.New("pki doc is nil")
	}
	serviceDescriptors := FindServices(serviceName, doc)
	if len(serviceDescriptors) == 0 {
		return nil, errors.New("GetService failure, service not found in pki doc.")
	}
	return &serviceDescriptors[mrand.Intn(len(serviceDescriptors))], nil
}

// OnConnection will be called by the minclient api
// upon connecting to the Provider
func (s *Session) onConnection(err error) {
	if err == nil {
		s.opCh <- opConnStatusChanged{
			isConnected: true,
		}
	}
}

// OnMessage will be called by the minclient api
// upon receiving a message
func (s *Session) onMessage(ciphertextBlock []byte) error {
	s.log.Debugf("OnMessage")
	return nil
}

// OnACK is called by the minclient api whe
// we receive an ACK message
func (s *Session) onACK(surbID *[constants.SURBIDLength]byte, ciphertext []byte) error {
	idStr := fmt.Sprintf("[%v]", hex.EncodeToString(surbID[:]))
	s.log.Infof("OnACK with SURBID %x", idStr)
	return nil
}

func (s *Session) onDocument(doc *pki.Document) {
	s.log.Debugf("onDocument(): Epoch %v", doc.Epoch)
	s.hasPKIDoc = true
	s.opCh <- opNewDocument{
		doc: doc,
	}
}
