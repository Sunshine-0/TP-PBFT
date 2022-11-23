package sm2

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/xlcetc/cryptogm/elliptic/sm2curve"
)

func GetSA(ka, kb *big.Int, priv *PrivateKey) (*big.Int, *big.Int, *big.Int, *big.Int, *big.Int, *big.Int) {
	c := priv.Curve
	x, y := c.ScalarBaseMult(kb.Bytes())
	x1, y1 := c.ScalarMult(x, y, ka.Bytes()) //GAB
	q := c.Params().N
	rab := new(big.Int).Mod(x1, q)
	fmt.Printf("rab:%v\n", rab)

	if rab == big.NewInt(0) {
		fmt.Println("输入的第二个随机数不可用，请重新输入！")
		return nil, nil, nil, nil, nil, nil //如果返回nil说明sA生成不成功
	}
	kaInv := new(big.Int).ModInverse(ka, q) //ka的逆
	//fmt.Printf("string类型的kaInv:%v\n", kaInv)
	sA := new(big.Int).Mul(kaInv, rab)
	sA.Mod(sA, q)
	sA.Mul(sA, priv.D)
	sA.Mod(sA, q) //sa = ka^(-1)*rab*priv.D mod q
	fmt.Printf("sA:%v\n", sA)

	GAx, GAy := c.ScalarBaseMult(ka.Bytes())
	return sA, GAx, GAy, rab, x1, y1
}

func VerifySA(sA, GAx, GAy, rab *big.Int, pub *PublicKey) bool {
	c := pub.Curve
	x1, y1 := c.ScalarMult(GAx, GAy, sA.Bytes())
	x2, y2 := c.ScalarMult(pub.X, pub.Y, rab.Bytes())
	fmt.Println("--------------------------------------Starting SA validation---------------------------------------------")
	fmt.Printf("x1:%v\ny1:%v\nx2:%v\ny2:%v\n", x1, y1, x2, y2)
	if x1.Cmp(x2) == 0 && y1.Cmp(y2) == 0 {
		return true
	}
	fmt.Printf("sA验证不通过，请原始签名者重新发送sA\n")
	return false
}

//func ProxyKeyGen(sAi, ki, kbInv *big.Int, c sm2curve.Curve)*big.Int{
//	d_Bi := new(big.Int).Add(sAi, ki)
//	d_Bi.Mul(d_Bi,kbInv)
//	d_Bi.Mod(d_Bi, c.Params().N)
//	return d_Bi
//}
//
func ProxyKeyGen(sa, kbInv *big.Int, c sm2curve.Curve) *big.Int {
	one := big.NewInt(1)
	dB := new(big.Int).Mul(sa, kbInv)
	dB.Mod(dB, c.Params().N)
	dB.Add(dB, one)
	dB.Mod(dB, c.Params().N)
	return dB
}

//代理签名，此处的随机数k应为代理小组传入的，但是为了简化，直接在函数中生成
func ProxySign(x1, y1, dB *big.Int, digest []byte, c sm2curve.Curve) (*big.Int, *big.Int) {
	//one := big.NewInt(1)
	e := new(big.Int).SetBytes(digest)
	k := GenerateRandK(rand.Reader, c)
	x3, _ := c.ScalarMult(x1, y1, k.Bytes())
	q := c.Params().N

	r := new(big.Int).Add(e, x3)
	r.Mod(r, q)

	if big.NewInt(0).Add(r, k).Cmp(q) == 0 || r.Cmp(big.NewInt(0)) == 0 {
		return nil, nil
	}

	s1 := new(big.Int).Add(k, r)
	s2 := big.NewInt(0).ModInverse(dB, q)
	s1.Mul(s1, s2)
	s1.Mod(s1, q)
	s1.Sub(s1, r)
	s1.Mod(s1, q)

	return s1, r
}

//代理签名，此处的随机数k应为代理小组传入的，但是为了简化，直接在函数中生成
func ProxySign2(x1, y1, dB *big.Int, digest []byte) (*big.Int, *big.Int) {
	one := big.NewInt(1)
	c := sm2curve.P256()
	e := new(big.Int).SetBytes(digest)
	k := GenerateRandK(rand.Reader, c)
	x3, _ := c.ScalarMult(x1, y1, k.Bytes())
	q := c.Params().N

	r := new(big.Int).Add(e, x3)
	r.Mod(r, q)

	s1 := new(big.Int).Mul(r, dB)
	s1.Mod(s1, q)
	s1.Sub(k, s1)

	s2 := big.NewInt(0).Add(dB, one)
	s2.ModInverse(s2, q)

	s := big.NewInt(0).Mul(s1, s2)
	s.Mod(s, q)

	return s, r
}

func VerifyProxySign(pub *PublicKey, digest []byte, r, s, x1, y1, rab *big.Int) bool {
	c := pub.Curve
	N := c.Params().N

	if r.Sign() <= 0 || s.Sign() <= 0 {
		return false
	}
	if r.Cmp(N) >= 0 || s.Cmp(N) >= 0 {
		return false
	}

	q := pub.Curve.Params().N

	e := new(big.Int).SetBytes(digest)

	t := new(big.Int).Add(r, s)
	t.Mod(t, q)

	var x3 *big.Int

	t.Mul(t, rab)
	t.Mod(t, q)
	x31, y31 := c.ScalarMult(pub.X, pub.Y, t.Bytes())
	x32, y32 := c.ScalarMult(x1, y1, s.Bytes())
	x3, _ = c.Add(x31, y31, x32, y32)

	R := new(big.Int).Add(e, x3)
	R.Mod(R, q)
	fmt.Println("-------------------------------starting threshold proxy signature verification based on SM2-------------------------------------")
	fmt.Printf("R:%v\nr:%v\n", R, r)
	return R.Cmp(r) == 0
}
