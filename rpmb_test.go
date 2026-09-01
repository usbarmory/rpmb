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
	"testing"
)

var testKey = bytes.Repeat([]byte{0xa5}, keyLen)

// TestInitWithTransport rejects bad transports and MAC keys.
func TestInitWithTransport(t *testing.T) {
	if _, err := InitWithTransport(nil, testKey, 0, false); err == nil {
		t.Fatal("accepted nil transport")
	}

	if _, err := InitWithTransport(newFakeCard(), testKey[:keyLen-1], 0, false); err == nil {
		t.Fatal("accepted invalid MAC key size")
	}
}

// TestTransport exercises an authenticated write and read round trip.
func TestTransport(t *testing.T) {
	card := newFakeCard()

	programmer, err := InitWithTransport(card, testKey, 0, false)
	if err != nil {
		t.Fatal(err)
	}

	if err := programmer.ProgramKey(); err != nil {
		t.Fatalf("program key: %v", err)
	}

	p, err := InitWithTransport(card, testKey, 0, true)
	if err != nil {
		t.Fatal(err)
	}

	want := bytes.Repeat([]byte{0x5a}, FrameLength/2)
	if err := p.Write(1, want); err != nil {
		t.Fatalf("write: %v", err)
	}

	got := make([]byte, FrameLength/2)
	if err := p.Read(1, got); err != nil {
		t.Fatalf("read: %v", err)
	}

	if !bytes.Equal(got, want) {
		t.Fatal("read returned unexpected data")
	}

	if counter, err := p.Counter(true); err != nil {
		t.Fatalf("counter: %v", err)
	} else if counter != 2 {
		t.Fatalf("unexpected counter %d", counter)
	}
}

// TestTransportRejectsLargeTransfer enforces the frame payload limit.
func TestTransportRejectsLargeTransfer(t *testing.T) {
	p, err := InitWithTransport(newFakeCard(), testKey, 0, false)
	if err != nil {
		t.Fatal(err)
	}

	if err := p.Write(0, make([]byte, FrameLength/2+1)); err == nil {
		t.Fatal("accepted transfer larger than a data frame")
	}
}

// TestTransportUnprogrammed reports a card without a key.
func TestTransportUnprogrammed(t *testing.T) {
	p, err := InitWithTransport(newFakeCard(), testKey, 0, false)
	if err != nil {
		t.Fatal(err)
	}

	_, err = p.Counter(false)
	var opErr *OperationError
	if !errors.As(err, &opErr) || opErr.Result != AuthenticationKeyNotYetProgrammed {
		t.Fatalf("unexpected counter error %v", err)
	}
}

// TestTransportInvalidResponseMAC rejects tampered responses.
func TestTransportInvalidResponseMAC(t *testing.T) {
	card := newFakeCard()
	programmer, err := InitWithTransport(card, testKey, 0, false)
	if err != nil {
		t.Fatal(err)
	}

	if err := programmer.ProgramKey(); err != nil {
		t.Fatalf("program key: %v", err)
	}

	p, err := InitWithTransport(&tamperTransport{fakeCard: card}, testKey, 0, false)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := p.Counter(true); !errors.Is(err, ErrInvalidResponseMAC) {
		t.Fatalf("unexpected counter error %v", err)
	}
}

type tamperTransport struct {
	*fakeCard
}

func (t *tamperTransport) ReadRPMB(buf []byte) error {
	if err := t.fakeCard.ReadRPMB(buf); err != nil {
		return err
	}

	buf[FrameLength/2] ^= 0xff
	return nil
}

// TestMACCoversExpectedBytes pins the authenticated frame region.
func TestMACCoversExpectedBytes(t *testing.T) {
	// JESD84-B51 authenticates the trailing 284 bytes, starting at Data.
	// Data follows 196 StuffBytes and 32 KeyMAC bytes: 196 + 32 = 228.
	if FrameLength-macOffset != 228 {
		t.Fatalf("MAC start offset = %d, want 228", FrameLength-macOffset)
	}

	var frame DataFrame
	frame.Data[0] = 0x11

	mac := hmac.New(sha256.New, testKey)
	mac.Write(frame.Bytes()[228:])
	sum := mac.Sum(nil)

	// KeyMAC lies before the authenticated region.
	frame.KeyMAC[0] ^= 0xff
	mac.Reset()
	mac.Write(frame.Bytes()[228:])
	if !hmac.Equal(sum, mac.Sum(nil)) {
		t.Error("MAC changed outside the authenticated region")
	}

	// Data begins the authenticated region.
	frame.Data[0] ^= 0xff
	mac.Reset()
	mac.Write(frame.Bytes()[228:])
	if hmac.Equal(sum, mac.Sum(nil)) {
		t.Error("MAC unchanged inside the authenticated region")
	}
}

// TestFrameLayoutOffsets pins the frame length and counter position.
func TestFrameLayoutOffsets(t *testing.T) {
	var frame DataFrame
	binary.BigEndian.PutUint32(frame.WriteCounter[:], 0xdeadbeef)
	buf := frame.Bytes()

	if len(buf) != 512 {
		t.Fatalf("frame size = %d, want 512", len(buf))
	}

	// JESD84-B51 places WriteCounter after 196 bytes of stuff, 32 bytes
	// of KeyMAC, 256 bytes of data, and a 16-byte nonce. Their total is
	// 500, so the four-byte counter occupies frame[500:504].
	if got := binary.BigEndian.Uint32(buf[500:504]); got != 0xdeadbeef {
		t.Errorf("WriteCounter at [500:504] = %x, want deadbeef", got)
	}
}
