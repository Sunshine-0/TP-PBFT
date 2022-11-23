// Copyright 2020 cetc-30. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package test

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
	"testing"
	time2 "time"

	"github.com/SSSaaS/sssa-golang"
	"github.com/xlcetc/cryptogm/elliptic/sm2curve"
	. "github.com/xlcetc/cryptogm/sm/sm2"
	"github.com/xlcetc/cryptogm/sm/sm3"
)

//B的随机数的生成，B内有n个代理节点，和1个原始签名者，门限值为2tb+1,设2tb+1=f+1,n>=3f+1,因此f=2，tb=1。
func TestProxy(t *testing.T) {
	c := sm2curve.P256()
	//A的公私钥生成
	priv, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Errorf("error: %s", err)
		return
	}

	if !priv.PublicKey.Curve.IsOnCurve(priv.PublicKey.X, priv.PublicKey.Y) {
		t.Errorf("public key is invalid: %s", err)
		return
	}
	//fmt.Printf("A的私钥为：%v\n", priv.D)

	//代理小组生成随机密钥   其实如果实验下面的for不通过应该是回到随机数重新生成这一步，但是为了简化操作则直接回到代码最初的位置了
	//n := 7//proxy group
	//tb := 3//threashold
	//kb, _, _ := SplitShare(rand.Reader, n, tb)
	kb := GenerateRandK(rand.Reader, c)
	ka := GenerateRandK(rand.Reader, c)
	//generate sa
	//fmt.Printf("int类型的ka：%v\nstring类型的ka:%v\n", ka, ka.String())
	sa, GAx, GAy, rab, x1, y1 := GetSA(ka, kb, priv) //GAB=(x1,y1)
	for sa == nil {                                  //如果生成sA不成功则重新选随机数
		TestProxy(t)
	}
	verifySA := VerifySA(sa, GAx, GAy, rab, &priv.PublicKey)
	fmt.Printf("The verification result of SA is:%v\n", verifySA)
	fmt.Println("---------------------------------------The SA verification process is complete--------------------------------------------")
	for !verifySA {
		TestProxy(t)
	}

	//Generation of proxy keys
	kbInv := big.NewInt(0).ModInverse(kb, c.Params().N) //求kb^(-1)
	dB := ProxyKeyGen(sa, kbInv, priv.Curve)
	//fmt.Printf("the value of dB is：%v\n", dB)

	msg := []byte("sm2 message") //the message
	//Construct the hash digest of the message
	var m = make([]byte, 32+len(msg))
	copy(m, GetZ(&priv.PublicKey))
	copy(m[32:], msg)
	digest := sm3.SumSM3(m)

	s, r := ProxySign(x1, y1, dB, digest[:], priv.PublicKey.Curve)
	for s == nil {
		TestProxy(t)
	}
	fmt.Printf("Threshold proxy signature based on SM2：%v\n", s)

	res1 := VerifyProxySign(&priv.PublicKey, digest[:], r, s, x1, y1, rab)
	fmt.Printf("Threshold proxy signature check result based on SM2：%v\n", res1)
	fmt.Println("-------------------------------Completion of threshold proxy signature verification based on SM2-------------------------------------")
}

func TestProxy2(t *testing.T) {
	//A's public and private key generation
	priv, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Errorf("error: %s", err)
		return
	}

	if !priv.PublicKey.Curve.IsOnCurve(priv.PublicKey.X, priv.PublicKey.Y) {
		t.Errorf("public key is invalid: %s", err)
		return
	}

	msg := []byte("sm2 message") //待签名的消息
	//构造待签名消息的哈希摘要
	var m = make([]byte, 32+len(msg))
	copy(m, GetZ(&priv.PublicKey))
	copy(m[32:], msg)
	digest := sm3.SumSM3(m)

	r1, s1, _ := SignWithDigest(rand.Reader, priv, digest[:])
	fmt.Printf("SM2的签名：%v\n", s1)

	res2 := VerifyWithDigest(&priv.PublicKey, digest[:], r1, s1)
	fmt.Printf("SM2的签名验签结果：%v\n", res2)
	fmt.Println("-------------------------------SM2的签名验证结束-------------------------------------")
}

func TestProxy3(t1 *testing.T) {
	secret := "0y10VAfmyH7GLQY6QccCSLKJi8iFgpcSBTLyYOGbiYPqOpStAf1OYuzEBzZR"
	w := 5
	t := 3

	// 分割秘密
	secretShares, err := sssa.Create(t, w, secret)
	if err != nil {
		fmt.Printf("Create err: %v\n", err)
		os.Exit(-1)
	}
	fmt.Printf("secretShares: %v\n", secretShares)

	// 选择其中的3份
	testShares := []string{
		secretShares[0],
		secretShares[1],
		secretShares[2],
	}
	var time = time2.Now()
	// 恢复秘密
	combined, err := sssa.Combine(testShares)
	fmt.Println(time2.Now().Sub(time))
	if err != nil {
		fmt.Printf("Combine err: %v\n", err)
		os.Exit(-1)
	}
	if combined != secret {
		fmt.Printf("Fatal: combining returned invalid data\n")
		os.Exit(-1)
	}

}
