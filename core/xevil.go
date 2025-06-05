package core

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strconv"
	"time"
)

type XEvilResponse struct {
	Status  int    `json:"status"`
	Request string `json:"request"`
}

var XEvilUrl = "http://IP:PORT"
var XEvilKey = "fdsfsdfsdf"

func SubmitImageToXEvil(image, instruction string) (string, error) {
	url := fmt.Sprintf("%s/in.php", XEvilUrl)
	method := "POST"

	payload := &bytes.Buffer{}
	writer := multipart.NewWriter(payload)

	if err := writer.WriteField("method", "base64"); err != nil {
		return "", err
	}
	if err := writer.WriteField("body", image); err != nil {
		return "", err
	}
	if err := writer.WriteField("imginstructions", instruction); err != nil {
		return "", err
	}
	if err := writer.WriteField("key", XEvilKey); err != nil {
		return "", err
	}
	if err := writer.WriteField("recaptcha", "1"); err != nil {
		return "", err
	}
	if err := writer.WriteField("json", "1"); err != nil {
		return "", err
	}

	if err := writer.Close(); err != nil {
		return "", err
	}

	client := &http.Client{}
	req, err := http.NewRequest(method, url, payload)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	res, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return "", err
	}

	var response XEvilResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return "", fmt.Errorf("invalid response format: %s", string(body))
	}

	if response.Status != 1 {
		return "", errors.New("failed to submit image to XEvil")
	}

	return response.Request, nil
}

func FetchXEvilResult(requestID string) (int, error) {
	url := fmt.Sprintf("%s/res.php?id=%s&json=1&action=get", XEvilUrl, requestID)
	client := &http.Client{}

	for {
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return 0, err
		}

		res, err := client.Do(req)
		if err != nil {
			return 0, err
		}
		defer res.Body.Close()

		body, err := io.ReadAll(res.Body)
		if err != nil {
			return 0, err
		}

		var response XEvilResponse
		if err := json.Unmarshal(body, &response); err != nil {
			return 0, fmt.Errorf("invalid response format: %s", string(body))
		}

		// Check status
		if response.Status == 1 {
			result, err := strconv.Atoi(response.Request)
			if err != nil {
				return 0, fmt.Errorf("invalid request number: %s", response.Request)
			}
			return result - 1, nil
		}

		time.Sleep(1 * time.Second)
	}
}

func SolveXEvil(image, instruction string) (int, error) {
	requestID, err := SubmitImageToXEvil(image, instruction)
	if err != nil {
		return 0, fmt.Errorf("failed to submit image: %v", err)
	}

	correctIndex, err := FetchXEvilResult(requestID)
	if err != nil {
		return 0, fmt.Errorf("failed to fetch XEvil result: %v", err)
	}

	return correctIndex, nil
}
