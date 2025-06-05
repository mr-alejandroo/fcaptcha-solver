package utils

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	mrand "math/rand"
	"strings"
	"time"
	"unicode"

	"github.com/dop251/goja"
	"github.com/google/uuid"
	"golang.org/x/net/html"
)

type Utils struct {
	VM *goja.Runtime
	// RandsigbyteF goja.Callable // not needed
	// GenkeyF goja.Callable
	// X64hash128F goja.Callable
}

func (u *Utils) Find(data []map[string]string, value string) string {
	for _, item := range data {
		if item["key"] == value {
			return item["value"]
		}
	}
	return ""
}

func (u *Utils) NewRelicTime() string { // CHECKED
	now := time.Now()
	seconds := now.Unix()
	nanoseconds := now.UnixNano()
	decimalPart := nanoseconds - seconds*1e9
	decimalStr := fmt.Sprintf("%09d", decimalPart)
	return fmt.Sprintf("%d%s", seconds, decimalStr[:5])
}

func (u *Utils) Hex(data []byte) string { // CHECKED
	result := ""
	for _, b := range data {
		result += fmt.Sprintf("%02x", b)
	}
	return result
}

func (u *Utils) ConvertSalt(words []int, sigBytes int) []byte { // CHECKED
	salt := make([]byte, 0)
	for _, word := range words {
		w := word & 0xFFFFFFFF
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, uint32(w))
		salt = append(salt, b...)
	}
	return salt[:sigBytes]
}

func (u *Utils) IntToBytes(n int, byteLen int) []byte {
	b := make([]byte, byteLen)
	binary.BigEndian.PutUint32(b, uint32(int32(n))) // Cast to int32 for signed conversion
	return b
}

func (u *Utils) ToSigBytes(words []int, sigBytes int) []byte { // CHECKED
	result := make([]byte, 0)
	for _, word := range words {
		b := u.IntToBytes(word, 4)
		result = append(result, b...)
	}
	return result[:sigBytes]
}

func (u *Utils) DictToList(data map[string]interface{}) []interface{} { // CHECKED
	result := make([]interface{}, 0, len(data))
	for _, value := range data {
		result = append(result, value)
	}
	return result
}

func (u *Utils) Uint8Array(size int) ([]byte, error) { // CHECKED
	v := make([]byte, size)
	_, err := rand.Read(v)
	if err != nil {
		return nil, err
	}
	return v, nil
}

func (u *Utils) ConvertKeyToSigBytesFormat(key []byte) []int { // CHECKED
	keyWords := make([]int, 0, len(key)/4)
	for i := 0; i < len(key); i += 4 {
		if i+4 <= len(key) {
			// Read as unsigned 32-bit integer
			unsignedWord := binary.BigEndian.Uint32(key[i : i+4])
			// Convert to signed integer if necessary
			signedWord := int32(unsignedWord)
			keyWords = append(keyWords, int(signedWord))
		}
	}
	return keyWords
}

func (u *Utils) GetCoords(num int) (float64, int) {
	m := map[int][4]int{
		1: {0, 0, 100, 100},
		2: {100, 0, 200, 100},
		3: {200, 0, 300, 100},
		4: {0, 100, 100, 200},
		5: {100, 100, 200, 200},
		6: {200, 100, 300, 200},
	}

	coords, ok := m[num]
	if !ok {
		return 0, 0
	}
	x1, y1, x2, y2 := coords[0], coords[1], coords[2], coords[3]
	x := float64(x1+x2) / 2.0
	y := float64(y1+y2) / 2.0

	if mrand.Intn(2) == 0 {
		x += mrand.Float64()*(45.99999-10.00001) + 10.00001
	} else {
		x -= mrand.Float64()*(45.99999-10.00001) + 10.00001
	}

	if mrand.Intn(2) == 0 {
		y += float64(mrand.Intn(46))
	} else {
		y -= float64(mrand.Intn(46))
	}

	return x, int(y)
}

func (u *Utils) GridAnswerDict(answer int) map[string]interface{} { // CHECKED
	x, y := u.GetCoords(answer)
	px := fmt.Sprintf("%.2f", x/300.0)
	py := fmt.Sprintf("%.2f", float64(y)/200.0)

	return map[string]interface{}{
		"px": px,
		"py": py,
		"x":  x,
		"y":  y,
	}
}

// Reverse
func (u *Utils) EncryptDouble(main string, extra string) (string, error) { // CHECKED
	saltWords := u.RandSaltGO()

	// Generate Keywords using Salt
	keyWords := u.GenerateOtherKey(main, saltWords)

	// Convert key and IV from key words
	keyBytes := u.ToSigBytes(keyWords, 32)                  // 32 bytes for AES-256
	ivBytes := u.ToSigBytes(keyWords[len(keyWords)-4:], 16) // 16 bytes for IV
	saltBytes := u.ToSigBytes(saltWords, 8)                 // 8 bytes for salt

	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return "", fmt.Errorf("failed to create AES cipher: %v", err)
	}

	// Apply PKCS7 padding
	paddedData := PKCS7Padding([]byte(extra), aes.BlockSize)

	// Init CBC cipher
	ciphertext := make([]byte, len(paddedData))
	mode := cipher.NewCBCEncrypter(block, ivBytes)
	mode.CryptBlocks(ciphertext, paddedData)

	// Base64
	base64CipherText := base64.StdEncoding.EncodeToString(ciphertext)

	// Final JSON string (to avoid shit GO extra characters)
	result := fmt.Sprintf(`{"ct":"%s","iv":"%s","s":"%s"}`,
		base64CipherText,
		u.Hex(ivBytes),
		u.Hex(saltBytes))

	return result, nil
}

func (u *Utils) IsFlagged(data []map[string]string) bool {
	if len(data) == 0 {
		return false
	}

	var values []string
	for _, d := range data {
		for _, value := range d {
			values = append(values, value)
		}
	}

	if len(values) == 0 {
		return false
	}

	for _, value := range values {
		if len(value) == 0 || !unicode.IsUpper(rune(value[len(value)-1])) {
			return false
		}
	}

	return true
}

func (r *Utils) TGuess(sessionToken string, guesses []string, dapibCode string) string {
	tokenParts := strings.Split(sessionToken, ".")
	if len(tokenParts) != 2 {
		log.Fatal("Invalid session token format")
	}
	sess, ion := tokenParts[0], tokenParts[1]

	// Prepare the answers list
	var answersBuilder strings.Builder
	answersBuilder.WriteString("[")

	for i, guess := range guesses {
		if i > 0 {
			answersBuilder.WriteString(", ")
		}

		// Parse each guess
		var guessData map[string]interface{}
		if err := json.Unmarshal([]byte(guess), &guessData); err != nil {
			log.Fatalf("Failed to parse guess: %v", err)
		}

		if index, exists := guessData["index"]; exists {
			answersBuilder.WriteString(fmt.Sprintf("{index: %v, '%s': '%s'}", index, sess, ion))
		} else {
			answersBuilder.WriteString(fmt.Sprintf(
				"{'px': '%v', 'py': '%v', 'x': '%v', 'y': '%v', '%s': '%s'}",
				guessData["px"], guessData["py"], guessData["x"], guessData["y"], sess, ion))
		}
	}

	answersBuilder.WriteString("]")
	answers := answersBuilder.String()

	// Initialize the Goja VM
	vm := goja.New()

	answersJSON, err := json.Marshal(answers)
	if err != nil {
		log.Fatalf("Failed to marshal answers: %v", err)
	}

	answersString := strings.ReplaceAll(string(answersJSON), "\n", "")
	answersString = strings.ReplaceAll(answersString, `"index"`, "index")

	// Create JS Script
	script := `
		var process = {};

		Object.prototype.toString = function () {
			if (this === process) {
				return "[object process]";
			}
			return {}.toString.call(this); // Default behavior for other objects
		};

		var window = { 
			document: {
		        hidden: true,                 // Ensure this is true for the Visibility Flag check
		        visibilityState: "prerender", // Set to 'prerender' for the Visibility Flag
		        activeElement: null           // Set to null to avoid being an instance of Object for Active Element Flag
		    },
			parent: {},
			requestAnimationFrame: undefined,
			cancelAnimationFrame: undefined,
		};
		window.parent.ae = {};

		// Initialize response to null
		var response = null;

		var answers = eval(%s)
		window.parent.ae={"answer":answers}

		window.parent.ae["dapibReceive"] = function(data) {
			response = JSON.stringify(data);
		};

		var result;
	`
	script = fmt.Sprintf(script, answersString)

	_, err = vm.RunString(script)
	if err != nil {
		log.Fatalf("Failed to run JavaScript initialization: %v", err)
	}

	// Run the dapibCode in JS VM
	_, err = vm.RunString(dapibCode)
	if err != nil {
		log.Fatalf("Failed to run dapibCode: %v", err)
	}

	responseValue := vm.Get("response")
	responseStr, ok := responseValue.Export().(string)
	if !ok {
		log.Fatal("Failed to retrieve 'response' from the JavaScript context")
	}

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(responseStr), &result); err != nil {
		log.Fatalf("Failed to parse response JSON: %v", err)
	}

	tanswerData, ok := result["tanswer"].([]interface{})
	if !ok {
		log.Fatal("Invalid 'tanswer' format in result")
	}

	var tanswer []map[string]string
	for _, item := range tanswerData {
		// Convert each item to map[string]interface{} and then to map[string]string
		if itemMap, ok := item.(map[string]interface{}); ok {
			converted := make(map[string]string)
			for key, value := range itemMap {
				// Convert each value to string and add to the new map
				if strVal, ok := value.(string); ok {
					converted[key] = strVal
				} else {
					converted[key] = fmt.Sprintf("%v", value)
				}
			}
			tanswer = append(tanswer, converted)
		} else {
			log.Fatal("Unexpected item format in 'tanswer'")
		}
	}

	// Check if the result is flagged
	if r.IsFlagged(tanswer) {
		for _, itemMap := range tanswer {
			for key, value := range itemMap {
				if ok && len(value) > 0 {
					itemMap[key] = value[:len(value)-1] // Trim last character
				}
			}
		}
	}

	modifiedTanswerJSON, err := json.Marshal(tanswer)
	if err != nil {
		log.Fatalf("Failed to serialize modified tanswer: %v", err)
	}
	modifiedTanswerStr := strings.ReplaceAll(string(modifiedTanswerJSON), " ", "")

	encResult, err := r.EncryptDouble(sessionToken, modifiedTanswerStr)
	if err != nil {
		log.Fatalf("Failed to encrypt result: %v", err)
	}

	return encResult
}

// * NEW FUNC
func (u *Utils) GenerateKey2(password string, salt []byte, keySize int, iterations int) []byte { // CHECKED
	var key []byte
	var block []byte
	hasher := md5.New()

	for len(key) < keySize {
		if block != nil {
			hasher.Write(block)
		}
		hasher.Write([]byte(password))
		hasher.Write(salt)
		block = hasher.Sum(nil)
		hasher.Reset()

		for i := 1; i < iterations; i++ {
			hasher.Write(block)
			block = hasher.Sum(nil)
			hasher.Reset()
		}

		key = append(key, block...)
	}

	return key[:keySize]
}

func (u *Utils) GenerateOtherKey(data string, salt []int) []int { // CHECKED
	sigBytes := 8
	keySize := 48
	iterations := 1

	convertedSalt := u.ConvertSalt(salt, sigBytes)
	key := u.GenerateKey2(data, convertedSalt, keySize, iterations)

	return u.ConvertKeyToSigBytesFormat(key)
}

// * ONE FUNCTION
func PKCS7Padding(data []byte, blockSize int) []byte { // CHECKED
	padding := blockSize - (len(data) % blockSize)
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

func (u *Utils) EncryptCT(plainText, key, iv []byte) ([]byte, error) { // CHECKED
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	paddedText := PKCS7Padding(plainText, aes.BlockSize)
	mode := cipher.NewCBCEncrypter(block, iv)

	cipherText := make([]byte, len(paddedText))
	mode.CryptBlocks(cipherText, paddedText)

	return cipherText, nil
}

func (r *Utils) MakeEncryptedDict(data string, userAgent, xArkValue string) (string, error) { // CHECKED
	utils := &Utils{}

	// Generate s_value as a random 8-byte hex string
	sValueBytes, err := r.Uint8Array(8)
	if err != nil {
		return "", fmt.Errorf("failed to generate s_value: %v", err)
	}
	sValueHex := utils.Hex(sValueBytes)

	// Generate iv_value as a random 16-byte array
	ivValue, err := r.Uint8Array(16)
	if err != nil {
		return "", fmt.Errorf("failed to generate iv_value: %v", err)
	}

	// Session Seed
	encodeSeed := fmt.Sprintf("%s%s", userAgent, xArkValue)

	// Generate key
	key := r.GenkeyGO(encodeSeed, sValueHex)

	// Encrypt the data (converting it to bytes)
	result, err := r.EncryptCT([]byte(data), key, ivValue)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt data: %v", err)
	}

	resultBase64 := base64.StdEncoding.EncodeToString(result)

	// Create the final JSON string
	encryptedDict := fmt.Sprintf(`{"ct":"%s","s":"%s","iv":"%s"}`,
		resultBase64,
		sValueHex,
		utils.Hex(ivValue))

	return encryptedDict, nil
}

func (u *Utils) XArkValue() string { // CHECKED
	now := time.Now().Unix()
	rounded := now - (now % 21600) // Round down to nearest 6hhrs
	return fmt.Sprintf("%d", rounded)
}

func Md5Hash(data string) string {
	hash := md5.New()
	hash.Write([]byte(data))
	return hex.EncodeToString(hash.Sum(nil))
}

func (u *Utils) ProcessFP(fpdata []string) string {
	result := []string{}

	for _, item := range fpdata {
		parts := strings.Split(item, ":")
		if len(parts) > 1 {
			result = append(result, parts[1])
		}
	}

	return strings.Join(result, ";")
}

type EncryptedData struct {
	IV string `json:"iv"`
	CT string `json:"ct"`
	S  string `json:"s"`
}

func aesDecrypt(key, iv, ciphertext []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("invalid key length: AES-256 requires a 32-byte key")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// CBC mode decryption
	cbc := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	cbc.CryptBlocks(plaintext, ciphertext)

	// Remove PKCS7 padding
	paddingLen := int(plaintext[len(plaintext)-1])
	if paddingLen > len(plaintext) || paddingLen > aes.BlockSize {
		return nil, errors.New("invalid padding")
	}
	return plaintext[:len(plaintext)-paddingLen], nil
}

func (u *Utils) DecryptImage(dataJSON, secret string) (string, error) {
	var data EncryptedData
	err := json.Unmarshal([]byte(dataJSON), &data)
	if err != nil {
		return "", err
	}

	// Convert hex strs to byte arrays
	iv, err := hex.DecodeString(data.IV)
	if err != nil {
		return "", err
	}
	salt, err := hex.DecodeString(data.S)
	if err != nil {
		return "", err
	}
	ciphertext, err := base64.StdEncoding.DecodeString(data.CT)
	if err != nil {
		return "", err
	}

	combined := append([]byte(secret), salt...)
	key := md5.Sum(combined)
	for i := 0; i < 2; i++ {
		key = md5.Sum(append(key[:], combined...))
	}
	fullKey := key[:]

	// Decrypt the ciphertext
	plaintext, err := aesDecrypt(fullKey, iv, ciphertext)
	if err != nil {
		return "", err
	}

	finalImage, err := base64.StdEncoding.DecodeString(string(plaintext))
	if err != nil {
		return "", err
	}

	finalBase64Image := base64.StdEncoding.EncodeToString(finalImage)

	return finalBase64Image, nil
}

// Extra Callback Params (User clicked verify)
func (u *Utils) GenerateG() string {
	return uuid.New().String()[:12]
}

func (u *Utils) GenerateH(cs, g string) string {
	dataToHash := cs + g
	hash := sha256.Sum256([]byte(dataToHash))
	return hex.EncodeToString(hash[:])
}

func (u *Utils) GenerateCS() string {
	return uuid.New().String()[:10]
}

func (u *Utils) GeneratePT() float64 {
	start := time.Now()
	time.Sleep(time.Duration(40+mrand.Intn(30)) * time.Millisecond)
	return time.Since(start).Seconds()
}

func (u *Utils) GenerateAHT() string {
	numTrials := mrand.Intn(7) + 1
	totalTime := 0.0

	for i := 0; i < numTrials; i++ {
		pt := u.GeneratePT()
		totalTime += pt
	}

	// Get average handling time
	return fmt.Sprintf("%.17f", totalTime/float64(numTrials))
}

// Header Generation
func (u *Utils) GenerateXRequestedID(Token string) (string, error) {
	// Generate random
	sc := map[string]interface{}{
		"sc": []int{
			mrand.Intn(201) + 100,
			mrand.Intn(201) + 100,
		},
	}

	scJson, err := json.Marshal(sc)
	if err != nil {
		return "", fmt.Errorf("failed to marshal scJson: %w", err)
	}

	// Encrypt
	xRequestedID, err := u.EncryptDouble(fmt.Sprintf("REQUESTED%sID", Token), string(scJson))
	if err != nil {
		return "", fmt.Errorf("failed to encrypt double: %w", err)
	}

	return xRequestedID, nil
}

func StripHTML(input string) string {
	var output bytes.Buffer
	tokenizer := html.NewTokenizer(strings.NewReader(input))

	for {
		tt := tokenizer.Next()
		switch tt {
		case html.ErrorToken:
			return strings.TrimSpace(output.String())
		case html.TextToken:
			text := tokenizer.Text()
			output.Write(text)
		}
	}
}
