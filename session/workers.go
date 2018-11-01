// workers.go - mixnet client workers
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
	"errors"
	"time"

	"github.com/katzenpost/core/pki"
)

type opIsEmpty struct{}

type opConnStatusChanged struct {
	isConnected bool
}

type opNewDocument struct {
	doc *pki.Document
}

func (s *Session) isDocValid(doc *pki.Document) error {
	const serviceLoop = "loop"
	for _, provider := range doc.Providers {
		_, ok := provider.Kaetzchen[serviceLoop]
		if !ok {
			return errors.New("Error, found a Provider which does not have the loop service.")
		}
	}
	return nil
}

func (s *Session) connStatusChange(op opConnStatusChanged) bool {
	isConnected := false
	if isConnected = op.isConnected; isConnected {
		const skewWarnDelta = 2 * time.Minute
		s.onlineAt = time.Now()

		skew := s.minclient.ClockSkew()
		absSkew := skew
		if absSkew < 0 {
			absSkew = -absSkew
		}
		if absSkew > skewWarnDelta {
			// Should this do more than just warn?  Should this
			// use skewed time?  I don't know.
			s.log.Warningf("The observed time difference between the host and provider clocks is '%v'. Correct your system time.", skew)
		} else {
			s.log.Debugf("Clock skew vs provider: %v", skew)
		}
	}
	return isConnected
}

func (s *Session) sessionWorker() {
	for {
		var qo workerOp
		select {
		case <-s.HaltCh():
			s.log.Debugf("Terminating gracefully.")
			return
		case qo = <-s.opCh:
		}
		if qo != nil {
			switch op := qo.(type) {
			case opIsEmpty:
				// XXX do cleanup here?
				continue
			case opConnStatusChanged:
				// Note: s.isConnected isn't used in favor of passing the
				// value via an op, to save on locking headaches.
				_ = s.connStatusChange(op)
			case opNewDocument:
			default:
				s.log.Warningf("BUG: Worker received nonsensical op: %T", op)
			} // end of switch
		} // if qo != nil
	}
	// NOTREACHED
}

func (s *Session) sendWorker() {
	for {
		select {
		case packet := <-s.cryptoChan:
			s.onSendPacket(packet)
		case <-s.HaltCh():
			s.log.Info("HaltCh received event, halting now.")
			return
		}
	}
}

func (s *Session) cryptoWorker() {
	for {
		pkt, _, _, err := s.minclient.ComposeSphinxPacket(s.cfg.Debug.TargetRecipient, s.cfg.Debug.TargetProvider, nil, s.payload[:])
		if err != nil {
			s.fatalErrCh <- err
			return
		}
		select {
		case s.cryptoChan <- pkt:
		case <-s.HaltCh():
			s.log.Info("HaltCh received event, halting now.")
			return
		}
	}
}

func (s *Session) onSendPacket(packet []byte) {
	ctx := context.Background()
	s.limiter.Wait(ctx)
	err := s.minclient.SendSphinxPacket(packet)
	if err != nil {
		s.log.Warningf("SendSphinxPacket failure: %s", err)
	}
}
