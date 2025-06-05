package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"

	fhttp "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"

	"testing"
)

type TlsBrowserleaksResponse struct {
	UserAgent  string `json:"user_agent"`
	Ja3Hash    string `json:"ja3_hash"`
	Ja3Text    string `json:"ja3_text"`
	Ja3NHash   string `json:"ja3n_hash"`
	Ja3NText   string `json:"ja3n_text"`
	Ja4        string `json:"ja4"`
	Ja4R       string `json:"ja4_r"`
	Ja4O       string `json:"ja4_o"`
	Ja4Ro      string `json:"ja4_ro"`
	AkamaiHash string `json:"akamai_hash"`
	AkamaiText string `json:"akamai_text"`
	TLS        struct {
		CipherSuite []struct {
			Name  string `json:"name"`
			Value int    `json:"value"`
		} `json:"cipher_suite"`
		ConnectionVersion []struct {
			Name  string `json:"name"`
			Value int    `json:"value"`
		} `json:"connection_version"`
		RecordVersion []struct {
			Name  string `json:"name"`
			Value int    `json:"value"`
		} `json:"record_version"`
		HandshakeVersion []struct {
			Name  string `json:"name"`
			Value int    `json:"value"`
		} `json:"handshake_version"`
		CipherSuites []struct {
			Name  string `json:"name"`
			Value int    `json:"value"`
		} `json:"cipher_suites"`
		Extensions []struct {
			Name  string `json:"name"`
			Value int    `json:"value"`
			Data  struct {
				SupportedVersions []struct {
					Name  string `json:"name"`
					Value int    `json:"value"`
				} `json:"supported_versions"`
			} `json:"data,omitempty"`
		} `json:"extensions"`
	} `json:"tls"`
	HTTP2 []struct {
		Type                string   `json:"type"`
		Length              int      `json:"length"`
		Settings            []string `json:"settings,omitempty"`
		WindowSizeIncrement int      `json:"window_size_increment,omitempty"`
		StreamID            int      `json:"stream_id,omitempty"`
		Headers             []string `json:"headers,omitempty"`
		Flags               []string `json:"flags,omitempty"`
		Priority            struct {
			Weight    int `json:"weight"`
			DepID     int `json:"dep_id"`
			Exclusive int `json:"exclusive"`
		} `json:"priority,omitempty"`
	} `json:"http2"`
}

func loadJsonFile(filename string) (*TlsBrowserleaksResponse, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}

	var parsedData TlsBrowserleaksResponse
	err = json.Unmarshal(data, &parsedData)
	if err != nil {
		return nil, err
	}

	return &parsedData, nil
}

func runTest(t *testing.T, config TestConfig) {
	fmt.Printf("\nRunning test with profile: %v\n", config.Profile)

	jar := tls_client.NewCookieJar()
	options := []tls_client.HttpClientOption{
		tls_client.WithTimeoutSeconds(15),
		tls_client.WithClientProfile(config.Profile),
		tls_client.WithCookieJar(jar),
		tls_client.WithRandomTLSExtensionOrder(),
	}

	client, err := tls_client.NewHttpClient(tls_client.NewNoopLogger(), options...)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	req, err := fhttp.NewRequest("GET", "https://tls.browserleaks.com/json", nil)
	if err != nil {
		log.Fatal(err)
	}

	req.Header.Add("User-Agent", config.UserAgent)
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Accept-Encoding", "gzip, deflate, br")
	req.Header.Add("Accept-Language", "en-US,en;q=0.9")
	req.Header.Add("Connection", "keep-alive")

	res, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		fmt.Println("Error reading response body:", err)
		return
	}

	var apiResponse TlsBrowserleaksResponse
	err = json.Unmarshal(body, &apiResponse)
	if err != nil {
		fmt.Println("Error: Response is not valid JSON:", err)
		return
	}

	// Load FP from json
	expectedData, err := loadJsonFile(config.JSONFile)
	if err != nil {
		fmt.Println("Error loading expected JSON file:", err)
		return
	}

	// Compare
	fmt.Println("Comparison Results:")
	if apiResponse.Ja3NHash != expectedData.Ja3NHash {
		fmt.Printf("❌ JA3N Hash Mismatch:\n  API: %s\n  JSON: %s\n", apiResponse.Ja3NHash, expectedData.Ja3NHash)
	} else {
		fmt.Println("✅ JA3N Hash matches.")
	}

	if apiResponse.AkamaiHash != expectedData.AkamaiHash {
		fmt.Printf("❌ Akamai Hash Mismatch:\n  API: %s\n  JSON: %s\n", apiResponse.AkamaiHash, expectedData.AkamaiHash)
	} else {
		fmt.Println("✅ Akamai Hash matches.")
	}

	if apiResponse.AkamaiText != expectedData.AkamaiText {
		fmt.Printf("❌ Akamai Text Mismatch:\n  API: %s\n  JSON: %s\n", apiResponse.AkamaiText, expectedData.AkamaiText)
	} else {
		fmt.Println("✅ Akamai Text matches.")
	}

	filename := fmt.Sprintf("tls_compare/own_%v.json", config.Profile)
	file, err := os.Create(filename)
	if err != nil {
		fmt.Println("Error creating file:", err)
		return
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	err = encoder.Encode(apiResponse)
	if err != nil {
		fmt.Println("Error writing to file:", err)
		return
	}

	fmt.Printf("Response successfully saved to %s\n", filename)
}

type TestConfig struct {
	Profile   profiles.ClientProfile
	JSONFile  string
	UserAgent string
}

func TestMultipleFingerprints(t *testing.T) {
	testConfigs := []TestConfig{
		{
			Profile:   profiles.Chrome_133,
			JSONFile:  "tls_compare/chrome_133.json",
			UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
		},
		{
			Profile:   profiles.Firefox_133,
			JSONFile:  "tls_compare/firefox_135.json",
			UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0",
		},
	}

	for _, config := range testConfigs {
		runTest(t, config)
	}
}
