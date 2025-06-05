package utils

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	mrand "math/rand"
	"strconv"
)

func (u *Utils) RandSaltGO() []int {
	seed := 8
	n := make([]int, 0, seed/4)

	// Pseudo-random generator
	generate := func(seed int64) func() float64 {
		r := int64(987654321)
		const max uint32 = 4294967295
		return func() float64 {
			r = 36969*(r&65535) + (r>>16)&int64(max)
			seed = 18000*(seed&65535) + (seed>>16)&int64(max)
			i := (r << 16) + (seed & int64(max))

			iF := float64(i) / 4294967296.0
			if mrand.Float64() > 0.5 {
				return iF + 0.5
			}
			return (iF + 0.5) * -1
		}
	}

	// Gen sequence based on seed
	for o := 0; o < seed; o += 4 {
		s := generate(mrand.Int63())
		n = append(n, int(s()*4294967296))
	}

	return n
}

func (u *Utils) X64Hash128GO(key string, seed uint64) string {
	data := []byte(key)
	length := len(data)
	nblocks := length / 16

	h1 := uint64(seed)
	h2 := uint64(seed)

	c1 := uint64(0x87c37b91114253d5)
	c2 := uint64(0x4cf5ad432745937f)

	// Body
	for i := 0; i < nblocks; i++ {
		block := i * 16
		k1 := uint64(data[block+0]) | uint64(data[block+1])<<8 | uint64(data[block+2])<<16 | uint64(data[block+3])<<24 |
			uint64(data[block+4])<<32 | uint64(data[block+5])<<40 | uint64(data[block+6])<<48 | uint64(data[block+7])<<56

		k2 := uint64(data[block+8]) | uint64(data[block+9])<<8 | uint64(data[block+10])<<16 | uint64(data[block+11])<<24 |
			uint64(data[block+12])<<32 | uint64(data[block+13])<<40 | uint64(data[block+14])<<48 | uint64(data[block+15])<<56

		k1 *= c1
		k1 = (k1 << 31) | (k1 >> (64 - 31))
		k1 *= c2
		h1 ^= k1

		h1 = (h1 << 27) | (h1 >> (64 - 27))
		h1 += h2
		h1 = h1*5 + 0x52dce729

		k2 *= c2
		k2 = (k2 << 33) | (k2 >> (64 - 33))
		k2 *= c1
		h2 ^= k2

		h2 = (h2 << 31) | (h2 >> (64 - 31))
		h2 += h1
		h2 = h2*5 + 0x38495ab5
	}

	// Tail
	tail_index := nblocks * 16
	k1 := uint64(0)
	k2 := uint64(0)
	switch length & 15 {
	case 15:
		k2 ^= uint64(data[tail_index+14]) << 48
		fallthrough
	case 14:
		k2 ^= uint64(data[tail_index+13]) << 40
		fallthrough
	case 13:
		k2 ^= uint64(data[tail_index+12]) << 32
		fallthrough
	case 12:
		k2 ^= uint64(data[tail_index+11]) << 24
		fallthrough
	case 11:
		k2 ^= uint64(data[tail_index+10]) << 16
		fallthrough
	case 10:
		k2 ^= uint64(data[tail_index+9]) << 8
		fallthrough
	case 9:
		k2 ^= uint64(data[tail_index+8])
		k2 *= c2
		k2 = (k2 << 33) | (k2 >> (64 - 33))
		k2 *= c1
		h2 ^= k2
		fallthrough
	case 8:
		k1 ^= uint64(data[tail_index+7]) << 56
		fallthrough
	case 7:
		k1 ^= uint64(data[tail_index+6]) << 48
		fallthrough
	case 6:
		k1 ^= uint64(data[tail_index+5]) << 40
		fallthrough
	case 5:
		k1 ^= uint64(data[tail_index+4]) << 32
		fallthrough
	case 4:
		k1 ^= uint64(data[tail_index+3]) << 24
		fallthrough
	case 3:
		k1 ^= uint64(data[tail_index+2]) << 16
		fallthrough
	case 2:
		k1 ^= uint64(data[tail_index+1]) << 8
		fallthrough
	case 1:
		k1 ^= uint64(data[tail_index+0])
		k1 *= c1
		k1 = (k1 << 31) | (k1 >> (64 - 31))
		k1 *= c2
		h1 ^= k1
	}

	// Finalization
	h1 ^= uint64(length)
	h2 ^= uint64(length)

	h1 += h2
	h2 += h1

	h1 = fmix64(h1)
	h2 = fmix64(h2)

	h1 += h2
	h2 += h1

	return fmt.Sprintf("%016x%016x", h1, h2)
}

func fmix64(k uint64) uint64 {
	k ^= k >> 33
	k *= 0xff51afd7ed558ccd
	k ^= k >> 33
	k *= 0xc4ceb9fe1a85ec53
	k ^= k >> 33
	return k
}

// -------------- GENKEY ---------------
var data [256]int

func init() {
	initData()
}

func initData() {
	// Initialize data array with zeros
	for i := 0; i < 256; i++ {
		data[i] = 0
	}
	// '0' to '9'
	for i := '0'; i <= '9'; i++ {
		data[i] = int(i - '0')
	}
	// 'A' to 'F'
	for i := 'A'; i <= 'F'; i++ {
		data[i] = int(10 + i - 'A')
	}
	// 'a' to 'f'
	for i := 'a'; i <= 'f'; i++ {
		data[i] = int(10 + i - 'a')
	}
}

func transformString(str string) string {
	transformed := make([]byte, 0, len(str)/2)
	for i := 0; i < len(str); i += 2 {
		if i+1 >= len(str) {
			break
		}
		e := str[i]
		n := str[i+1]
		value := byte((data[e] << 4) + data[n])
		transformed = append(transformed, value)
	}
	return string(transformed)
}

func hexStringToBinaryString(hexStr string) (string, error) {
	if len(hexStr)%2 != 0 {
		return "", fmt.Errorf("hex string has odd length")
	}
	bytes := make([]byte, len(hexStr)/2)
	for i := 0; i < len(hexStr); i += 2 {
		b, err := strconv.ParseUint(hexStr[i:i+2], 16, 8)
		if err != nil {
			return "", err
		}
		bytes[i/2] = byte(b)
	}
	return string(bytes), nil
}

func hashBinary(t string, e bool) string {
	h := md5.New()
	h.Write([]byte(t))
	hashBytes := h.Sum(nil) // []byte of length 16

	hexString := hex.EncodeToString(hashBytes) // 32-character hex string

	if e {
		// Convert hex string to binary string
		binStr, err := hexStringToBinaryString(hexString)
		if err != nil {
			// Handle error
			return ""
		}
		return binStr
	} else {
		return hexString
	}
}

func (util *Utils) GenkeyGO(headerData string, sValue string) []byte {
	transformed := transformString(sValue)
	u := headerData + transformed

	s := make([]string, 3)
	s[0] = hashBinary(u, true)
	f := s[0]
	for l := 1; l < 3; l++ {
		s[l] = hashBinary(s[l-1]+u, true)
		f += s[l]
	}

	fSubstring := f[:32]

	return []byte(fSubstring)
}
