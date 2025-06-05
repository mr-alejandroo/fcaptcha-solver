package utils

import (
	"fmt"
	"io"
	"log"
	"net/http"

	fhttp "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/fhttp/http2"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
	tls "github.com/bogdanfinn/utls"
	"github.com/labstack/echo/v4"
)

var Chrome130Profile = profiles.NewClientProfile(
	tls.ClientHelloID{
		Client:  "Chrome",
		Version: "130",
		Seed:    nil,
		SpecFactory: func() (tls.ClientHelloSpec, error) {
			cipherSuites := []uint16{
				tls.GREASE_PLACEHOLDER,
				tls.TLS_AES_128_GCM_SHA256,
				tls.TLS_AES_256_GCM_SHA384,
				tls.TLS_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, // ?
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,   // ?
				tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_RSA_WITH_AES_128_CBC_SHA,
				tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			}

			extensions := []tls.TLSExtension{
				&tls.UtlsGREASEExtension{},
				&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}}, //?
				&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
					tls.GREASE_PLACEHOLDER,
					tls.X25519Kyber768Draft00,
					tls.X25519,
					tls.CurveP256,
					tls.CurveP384,
				}},
				&tls.SCTExtension{},           //?
				&tls.SessionTicketExtension{}, //?
				&tls.SupportedVersionsExtension{Versions: []uint16{
					tls.GREASE_PLACEHOLDER,
					tls.VersionTLS13,
					tls.VersionTLS12,
				}},
				&tls.PSKKeyExchangeModesExtension{Modes: []uint8{
					tls.PskModeDHE,
				}},
				&tls.StatusRequestExtension{},
				&tls.ApplicationSettingsExtension{SupportedProtocols: []string{
					"h2",
				}},
				&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
					tls.ECDSAWithP256AndSHA256,
					tls.PSSWithSHA256,
					tls.PKCS1WithSHA256,
					tls.ECDSAWithP384AndSHA384,
					tls.PSSWithSHA384,
					tls.PKCS1WithSHA384,
					tls.PSSWithSHA512,
					tls.PKCS1WithSHA512,
				}},
				&tls.SNIExtension{},
				tls.BoringGREASEECH(),
				&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
					{Group: tls.CurveID(tls.GREASE_PLACEHOLDER), Data: []byte{00}},
					{Group: tls.X25519Kyber768Draft00},
					{Group: tls.X25519},
				}},
				&tls.RenegotiationInfoExtension{},
				&tls.SupportedPointsExtension{SupportedPoints: []byte{
					0,
				}},
				&tls.UtlsCompressCertExtension{
					Algorithms: []tls.CertCompressionAlgo{
						tls.CertCompressionBrotli,
					},
				},
				&tls.ExtendedMasterSecretExtension{},
				&tls.UtlsGREASEExtension{},
			}

			return tls.ClientHelloSpec{
				CipherSuites:       cipherSuites,
				CompressionMethods: []byte{tls.CompressionNone},
				Extensions:         extensions,
			}, nil
		},
	},
	map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:   65536,
		http2.SettingEnablePush:        0,
		http2.SettingInitialWindowSize: 6291456,
		http2.SettingMaxHeaderListSize: 262144,
	},
	[]http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingEnablePush,
		http2.SettingInitialWindowSize,
		http2.SettingMaxHeaderListSize,
	},
	[]string{
		":method",
		":authority",
		":scheme",
		":path",
	},
	uint32(15663105),
	nil,
	nil,
)

func GetChrome132Profile() profiles.ClientProfile {
	ja3 := "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,11-10-51-43-16-17613-0-45-27-65037-18-5-13-35-23-65281-41,4588-29-23-24,0"

	signatureAlgorithms := []string{
		"ECDSAWithP256AndSHA256",
		"PSSWithSHA256",
		"PKCS1WithSHA256",
		"ECDSAWithP384AndSHA384",
		"PSSWithSHA384",
		"PKCS1WithSHA384",
		"PSSWithSHA512",
		"PKCS1WithSHA512",
	}
	supportedVersions := []string{"GREASE", "1.3", "1.2"}
	supportedGroups := []string{"GREASE", "X25519", "secp256r1", "secp384r1"}

	alpnProtocols := []string{"h2", "http/1.1"}
	alpsProtocols := []string{"h2"}

	cipherSuites := []tls_client.CandidateCipherSuites{
		{
			KdfId:  "HKDF_SHA256",
			AeadId: "AEAD_AES_128_GCM",
		},
		{
			KdfId:  "HKDF_SHA256",
			AeadId: "AEAD_AES_256_GCM",
		},
		{
			KdfId:  "HKDF_SHA256",
			AeadId: "AEAD_CHACHA20_POLY1305",
		},
	}

	curvePriorities := []uint16{128, 160, 192, 224}

	specFunc, err := tls_client.GetSpecFactoryFromJa3String(
		ja3, signatureAlgorithms, signatureAlgorithms, supportedVersions,
		supportedGroups, alpnProtocols, alpsProtocols, cipherSuites, curvePriorities, "brotli",
	)
	if err != nil {
		log.Println("Error generating TLS Spec:", err.Error())
	}

	settings := map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:      65536,
		http2.SettingMaxConcurrentStreams: 1000,
		http2.SettingInitialWindowSize:    6291456,
		http2.SettingMaxHeaderListSize:    262144,
	}
	settingsOrder := []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingMaxConcurrentStreams,
		http2.SettingInitialWindowSize,
		http2.SettingMaxHeaderListSize,
	}

	pseudoHeaderOrder := []string{
		":method",
		":authority",
		":scheme",
		":path",
	}

	connectionFlow := uint32(15663105)

	chromeProfile := profiles.NewClientProfile(
		tls.ClientHelloID{
			Client:      "Chrome132",
			Version:     "1",
			Seed:        nil,
			SpecFactory: specFunc,
		},
		settings,
		settingsOrder,
		pseudoHeaderOrder,
		connectionFlow,
		nil,
		nil,
	)

	return chromeProfile
}

var Chrome_133 = profiles.NewClientProfile(
	tls.ClientHelloID{
		Client:               "Chrome",
		RandomExtensionOrder: false,
		Version:              "133",
		Seed:                 nil,
		SpecFactory: func() (tls.ClientHelloSpec, error) {
			return tls.ClientHelloSpec{
				CipherSuites: []uint16{
					tls.GREASE_PLACEHOLDER,
					tls.TLS_AES_128_GCM_SHA256,
					tls.TLS_AES_256_GCM_SHA384,
					tls.TLS_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_RSA_WITH_AES_256_CBC_SHA,
				},
				CompressionMethods: []byte{tls.CompressionNone},
				Extensions: []tls.TLSExtension{
					&tls.UtlsGREASEExtension{},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
						tls.ECDSAWithP256AndSHA256,
						tls.PSSWithSHA256,
						tls.PKCS1WithSHA256,
						tls.ECDSAWithP384AndSHA384,
						tls.PSSWithSHA384,
						tls.PKCS1WithSHA384,
						tls.PSSWithSHA512,
						tls.PKCS1WithSHA512,
					}},
					tls.BoringGREASEECH(),
					&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
					&tls.SCTExtension{},
					&tls.UtlsCompressCertExtension{Algorithms: []tls.CertCompressionAlgo{
						tls.CertCompressionBrotli,
					}},
					&tls.ALPNExtension{AlpnProtocols: []string{
						"h2",
						"http/1.1",
					}},
					&tls.StatusRequestExtension{},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.GREASE_PLACEHOLDER,
						4588, // Unknown (4588) from key_share
						tls.X25519,
						tls.CurveP256,
						tls.CurveP384,
					}},
					&tls.ApplicationSettingsExtension{SupportedProtocols: []string{
						"h2",
					}},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{tls.PointFormatUncompressed}},
					&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
						{Group: tls.CurveID(tls.GREASE_PLACEHOLDER), Data: []byte{0}},
						{Group: 4588},
						{Group: tls.X25519},
					}},
					&tls.SessionTicketExtension{},
					&tls.SupportedVersionsExtension{Versions: []uint16{
						tls.GREASE_PLACEHOLDER,
						tls.VersionTLS13,
						tls.VersionTLS12,
					}},
					&tls.PSKKeyExchangeModesExtension{Modes: []uint8{tls.PskModeDHE}},
					&tls.SNIExtension{},
					&tls.ExtendedMasterSecretExtension{},
					&tls.UtlsGREASEExtension{},
				},
			}, nil
		},
	},
	map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:   65536,
		http2.SettingEnablePush:        0,
		http2.SettingInitialWindowSize: 6291456,
		http2.SettingMaxHeaderListSize: 262144,
	},
	[]http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingEnablePush,
		http2.SettingInitialWindowSize,
		http2.SettingMaxHeaderListSize,
	},
	[]string{
		":method",
		":authority",
		":scheme",
		":path",
	},
	uint32(15663105),
	nil,
	nil,
)

func NewChrome130Client() (tls_client.HttpClient, error) {
	jar := tls_client.NewCookieJar()
	options := []tls_client.HttpClientOption{
		tls_client.WithTimeoutSeconds(15),
		tls_client.WithClientProfile(profiles.Chrome_124),
		tls_client.WithCookieJar(jar),
	}

	client, err := tls_client.NewHttpClient(tls_client.NewNoopLogger(), options...)
	if err != nil {
		log.Printf("Failed to create client: %v", err)
		return nil, fmt.Errorf("failed to create client")
	}
	return client, nil
}

func QueryTLSApiRoute(c echo.Context) error {
	client, err := NewChrome130Client()
	if err != nil {
		c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to create client"})
		return err
	}

	req, err := fhttp.NewRequest("GET", "https://tls.peet.ws/api/all", nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to create request"})
		return fmt.Errorf("failed to create request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, map[string]string{"error": "request failed"})
		return fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to read response body"})
		return fmt.Errorf("failed to read response body: %v", err)
	}

	return c.JSONBlob(http.StatusOK, body)
}
