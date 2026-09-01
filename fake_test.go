// Copyright 2026 The Armored Witness OS authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package rpmb

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

// fakeCard models the authenticated requests, monotonic counter, and staged
// result reads needed to exercise the RPMB protocol without hardware.
type fakeCard struct {
	programmed bool
	key        [keyLen]byte
	counter    uint32
	sectors    map[uint16][FrameLength / 2]byte
	pending    []byte
}

func newFakeCard() *fakeCard {
	return &fakeCard{sectors: make(map[uint16][FrameLength / 2]byte)}
}

func (c *fakeCard) WriteRPMB(buf []byte, reliable bool) error {
	if len(buf) != FrameLength {
		return errors.New("invalid frame size")
	}

	var req DataFrame
	if err := binary.Read(bytes.NewReader(buf), binary.LittleEndian, &req); err != nil {
		return err
	}

	wantReliable := req.Req == AuthenticationKeyProgramming || req.Req == AuthenticatedDataWrite
	if reliable != wantReliable {
		return errors.New("invalid reliable write setting")
	}

	switch req.Req {
	case ResultRead:
		// The preceding write already staged its response. A result-read
		// request makes that response available without replacing it.
		return nil
	case AuthenticationKeyProgramming:
		c.programKey(&req)
	case WriteCounterRead:
		c.readCounter(&req)
	case AuthenticatedDataWrite:
		c.write(&req)
	case AuthenticatedDataRead:
		c.read(&req)
	default:
		c.pending = c.errorFrame(&req, GeneralFailure)
	}

	return nil
}

func (c *fakeCard) ReadRPMB(buf []byte) error {
	if len(buf) != FrameLength {
		return errors.New("invalid frame size")
	}

	if c.pending == nil {
		return errors.New("no pending response")
	}

	copy(buf, c.pending)
	c.pending = nil
	return nil
}

func (c *fakeCard) programKey(req *DataFrame) {
	if c.programmed {
		c.pending = c.errorFrame(req, GeneralFailure)
		return
	}

	c.key = req.KeyMAC
	c.programmed = true
	c.pending = (&DataFrame{Resp: req.Req}).Bytes()
}

func (c *fakeCard) readCounter(req *DataFrame) {
	if !c.programmed {
		c.pending = c.errorFrame(req, AuthenticationKeyNotYetProgrammed)
		return
	}

	res := &DataFrame{Resp: req.Req, Nonce: req.Nonce}
	binary.BigEndian.PutUint32(res.WriteCounter[:], c.counter)
	c.pending = c.sign(res)
}

func (c *fakeCard) write(req *DataFrame) {
	if !c.programmed {
		c.pending = c.errorFrame(req, AuthenticationKeyNotYetProgrammed)
		return
	}

	if !c.verify(req) {
		c.pending = c.errorFrame(req, AuthenticationFailure)
		return
	}

	if req.Counter() != c.counter {
		c.pending = c.errorFrame(req, CounterFailure)
		return
	}

	c.sectors[binary.BigEndian.Uint16(req.Address[:])] = req.Data
	c.counter++

	res := &DataFrame{Resp: req.Req}
	binary.BigEndian.PutUint32(res.WriteCounter[:], c.counter)
	c.pending = c.sign(res)
}

func (c *fakeCard) read(req *DataFrame) {
	if !c.programmed {
		c.pending = c.errorFrame(req, AuthenticationKeyNotYetProgrammed)
		return
	}

	res := &DataFrame{Resp: req.Req, Nonce: req.Nonce}
	res.Data = c.sectors[binary.BigEndian.Uint16(req.Address[:])]
	c.pending = c.sign(res)
}

func (c *fakeCard) verify(req *DataFrame) bool {
	frame := req.Bytes()
	mac := hmac.New(sha256.New, c.key[:])
	mac.Write(frame[FrameLength-macOffset:])
	return hmac.Equal(req.KeyMAC[:], mac.Sum(nil))
}

func (c *fakeCard) sign(res *DataFrame) []byte {
	frame := res.Bytes()
	mac := hmac.New(sha256.New, c.key[:])
	mac.Write(frame[FrameLength-macOffset:])
	copy(res.KeyMAC[:], mac.Sum(nil))
	return res.Bytes()
}

func (c *fakeCard) errorFrame(req *DataFrame, result uint16) []byte {
	res := &DataFrame{Resp: req.Req, Nonce: req.Nonce}
	binary.BigEndian.PutUint16(res.Result[:], result)
	if c.programmed {
		return c.sign(res)
	}
	return res.Bytes()
}
