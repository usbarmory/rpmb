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

//go:build tamago

package rpmb

import (
	"fmt"

	"github.com/usbarmory/tamago/soc/nxp/usdhc"
)

// Assert that the hardware transport and legacy constructor retain their
// expected APIs.
var (
	_ Transport = (*usdhc.USDHC)(nil)
	_ func(*usdhc.USDHC, []byte, uint16, bool) (*RPMB, error) = Init
)

// Init returns a new RPMB instance for a specific MMC card and MAC key. The
// dummyBlock argument is an unused sector, required for CVE-2020-13799
// mitigation to invalidate uncommitted writes.
func Init(card *usdhc.USDHC, key []byte, dummyBlock uint16, writeDummy bool) (p *RPMB, err error) {
	if card == nil {
		return nil, fmt.Errorf("no MMC card set")
	}

	if !card.Info().MMC {
		return nil, fmt.Errorf("no MMC card detected")
	}

	return InitWithTransport(card, key, dummyBlock, writeDummy)
}
