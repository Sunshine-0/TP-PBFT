// Copyright 2020 cetc-30. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package test

import (
	"crypto/rand"
	"fmt"
	"github.com/xlcetc/cryptogm/elliptic/sm2curve"
	"github.com/xlcetc/cryptogm/sm/sm2"
	"testing"
)

func TestShamirShare(t *testing.T) {
	c := sm2curve.P256()
	n := 7
	tb := 3
	secret := sm2.GenerateRandK(rand.Reader, c.Params()).String()
	share := sm2.SplitShare(secret, n, tb)
	fmt.Printf("orignal secret:%s\n",secret)
	s := sm2.CombineShare(share)
	fmt.Println(sm2.VerifyShare(s, secret))
}