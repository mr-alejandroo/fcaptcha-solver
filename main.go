package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"funcaptchaapi/routes"
	utils "funcaptchaapi/utils"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

const (
	Port        = 2323
	CheckPeriod = 1 * time.Minute
)

func main() {
	e := echo.New()

	// Debug Setting
	e.Logger.SetOutput(io.Discard)
	e.Debug = false

	// Middleware
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins:     []string{"*"}, // Allow all origins
		AllowMethods:     []string{"*"}, // Allow all methods
		AllowHeaders:     []string{"*"}, // Allow all headers
		AllowCredentials: true,          // Allow cookies and credentials
	}))

	// Solver
	e.POST("/createTask", routes.CreateTaskRoute)
	e.POST("/getTask", routes.GetTaskRoute)
	e.GET("/getPlatforms", routes.GetPlatformDetails)

	// Decrypt Endpoints
	e.POST("/decryptBda", decryptBdaRoute)

	// Start server
	fmt.Printf("Server is running on PORT: %d\n", Port)
	if err := e.Start(fmt.Sprintf(":%d", Port)); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}

// Utility Routes
func decryptBdaRoute(c echo.Context) error {
	type BdaRequest struct {
		Bda       string `json:"bda"`
		UserAgent string `json:"user_agent"`
		XArkValue string `json:"x_ark_value"`
	}

	var req BdaRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]interface{}{"success": false, "error": "invalid request"})
	}

	// base64
	decodedBda, err := base64.StdEncoding.DecodeString(req.Bda)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]interface{}{"success": false, "error": "failed to decode bda"})
	}

	// load struct
	var encryptedData utils.EncryptedData
	if err := json.Unmarshal(decodedBda, &encryptedData); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]interface{}{"success": false, "error": "failed to parse encrypted data"})
	}

	u := utils.Utils{}
	key := u.GenkeyGO(req.UserAgent+req.XArkValue, encryptedData.S)
	iv, err := hex.DecodeString(encryptedData.IV)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]interface{}{"success": false, "error": "invalid IV format"})
	}

	// decode ciphertext
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedData.CT)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]interface{}{"success": false, "error": "failed to decode ciphertext"})
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]interface{}{"success": false, "error": "failed to initialize AES cipher"})
	}

	if len(ciphertext) < aes.BlockSize {
		return c.JSON(http.StatusBadRequest, map[string]interface{}{"success": false, "error": "ciphertext too short"})
	}

	// verify block size
	if len(iv) != aes.BlockSize {
		return c.JSON(http.StatusBadRequest, map[string]interface{}{"success": false, "error": "invalid IV length"})
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	decrypted := make([]byte, len(ciphertext))
	mode.CryptBlocks(decrypted, ciphertext)

	if len(decrypted) == 0 {
		return c.JSON(http.StatusBadRequest, map[string]interface{}{"success": false, "error": "error decrypting - decrypted data is empty"})
	}

	paddingLen := int(decrypted[len(decrypted)-1])
	if paddingLen > len(decrypted) || paddingLen == 0 {
		return c.JSON(http.StatusBadRequest, map[string]interface{}{"success": false, "error": "error decrypting - invalid padding length"})
	}

	for _, paddingByte := range decrypted[len(decrypted)-paddingLen:] {
		if int(paddingByte) != paddingLen {
			return c.JSON(http.StatusBadRequest, map[string]interface{}{"success": false, "error": "error decrypting - invalid padding byte found"})
		}
	}

	decrypted = decrypted[:len(decrypted)-paddingLen]

	escapedDecrypted := ""
	for _, r := range string(decrypted) {
		if r < 32 || r == 127 || (r >= 128 && r < 160) {
			escapedDecrypted += fmt.Sprintf("\\u%04x", r)
		} else {
			escapedDecrypted += string(r)
		}
	}

	// Detect JSON type
	var result interface{}
	if len(decrypted) > 0 && decrypted[0] == '[' {
		// Decrypted data is an array
		var dataArray []interface{}
		if err := json.Unmarshal(decrypted, &dataArray); err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]interface{}{"success": false, "error": "failed to parse decrypted array"})
		}
		result = dataArray
	} else {
		// Decrypted data is an object
		var dataObject map[string]interface{}
		if err := json.Unmarshal(decrypted, &dataObject); err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]interface{}{"success": false, "error": "failed to parse decrypted object"})
		}
		result = dataObject
	}

	return c.JSON(http.StatusOK, result)
}
