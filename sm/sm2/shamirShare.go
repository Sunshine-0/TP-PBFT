package sm2

import (
	"fmt"
	"github.com/SSSaaS/sssa-golang"
	"os"
)

// sharmir(t,n)：准备n把钥匙，至少要t把钥匙才能开启
func SplitShare(rand string, n, t int) []string {
	// 分割秘密
	//c := sm2curve.P256()

	//kBigInt := GenerateRandK(rand, c)
	//kStr := kBigInt.String()
	secretShares, err := sssa.Create(t, n, rand)
	if err != nil {
		fmt.Printf("Create err: %v\n", err)
		os.Exit(-1)
	}
	//fmt.Printf("secretShares.length: %v\n", len(secretShares))

	//// 选择其中的3份
	//testShares := []string{
	//	secretShares[2],
	//	secretShares[5],
	//	secretShares[6],
	//}
	return secretShares
}

func SplitShareString(secret string, n, t int) []string{
	// 分割秘密
	secretShares, err := sssa.Create(t, n, secret)
	if err != nil {
		fmt.Printf("Create err: %v\n", err)
		os.Exit(-1)
	}
	//fmt.Printf("secretShares.length: %v\n", len(secretShares))

	return secretShares
}

func CombineShare(testShares []string) string{
	// 恢复秘密
	combined, err := sssa.Combine(testShares)
	if err != nil {
		fmt.Printf("Combine err: %v\n", err)
		os.Exit(-1)
	}
	fmt.Printf("combined:%v\n", combined)
	return combined
}

func CombineMoreShare(testShares []string) string{
	// 恢复秘密
	combined, err := sssa.Combine(testShares)
	if err != nil {
		fmt.Printf("Combine err: %v\n", err)
		os.Exit(-1)
	}
	fmt.Printf("combined:%v\n", combined)
	return combined
}

func VerifyShare(comShares string, secret string) bool{
	// 校验聚合后的代码是否与原始的secret相等
	if comShares != secret {
		fmt.Printf("Fatal: combining returned invalid data\n")
		return false
		os.Exit(-1)
	}
	return true
}
