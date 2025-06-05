package core

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	utils "funcaptchaapi/utils"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
	"github.com/google/uuid"
)

var (
	CapiVersion       = "2.11.4"
	EnforcementHash   = "9eab88fb89440e9080505ec7f1f1b658"
	UpdateInterval    = 45 * time.Minute
	versionPattern    = regexp.MustCompile(`\d+\.\d+\.\d+`)
	dataBrandsPattern = regexp.MustCompile(`"([^"]+)";v="\d+"`)
)

var Hosts sync.Map
var JsContent string
var UseLocalHost bool
var HealthCheckLock sync.Mutex

func init() {
	log.SetFlags(0)

	// Args
	flag.BoolVar(&UseLocalHost, "use-local-host", false, "If set, forces usage of local host http://0.0.0.0:9999")
	flag.Parse()
}

type FuncaptchaTask struct {
	// Manage
	Status string
	ID     string

	// Site Specific
	Preset  utils.Preset
	SiteUrl string
	SiteKey string
	ApiURL  string
	Blob    string

	// Request Data
	Platform             string
	UserAgent            string
	BoostrapVersion      string
	XArkValue            string
	Locale               string
	AcceptLanguageHeader string
	DataBrandsHeader     interface{}
	IsMobileHeader       interface{}
	OsPlatform           interface{}

	// Referrers
	EnforcementHtmlReferrer string
	GameCoreReferrer        string

	// Dynamic Data
	Client                       tls_client.HttpClient
	WindowAncestorOriginsData    []string
	ClientConfigSitedataLocation string
	WindowTreeStructureData      string
	WindowTreeIndexData          []int

	// Challenge
	GameID          string
	GameType        int
	FinalToken      string
	SessionToken    string
	RContinent      string
	DapibCode       string
	DecryptionKey   string
	Waves           int
	GameName        string
	GameInstruction string

	// Util Functions
	Utils utils.Utils

	// API
	Hardcoded   bool
	ProcessTime float64
	ErrorReason string
}

func NewFuncaptchaTask(blob string, proxy string, platform string, hardcoded bool, preset utils.Preset) (*FuncaptchaTask, error) {
	// Funcap Data
	boostrapVersion := "1.25.0" // fallback

	// Random Platform
	isValidPlatform := false
	for _, p := range Platforms {
		if p == platform {
			isValidPlatform = true
			break
		}
	}

	if platform == "" || !isValidPlatform {
		platform = Platforms[rand.Intn(len(Platforms))]

	}

	// Browser Data
	userAgent := PlatformData["user_agent"][platform].(string)
	dataBrands := PlatformData["data_brands"][platform]
	isMobileHeader := PlatformData["sec_ch_ua_mobile"][platform]
	osPlatform := PlatformData["sec_ch_ua_platform"][platform]
	tlsProfile := PlatformData["tls"][platform].(profiles.ClientProfile)

	// Language
	locale := "en-US"
	acceptLanguageHeader := fmt.Sprintf("%s,%s;q=0.9", locale, strings.Split(locale, "-")[0])

	var timeout = 15
	if preset.IsCustomVersion {
		timeout = 30
	}

	// HTTP Client
	jar := tls_client.NewCookieJar()
	options := []tls_client.HttpClientOption{
		tls_client.WithTimeoutSeconds(timeout),
		tls_client.WithClientProfile(tlsProfile),
		tls_client.WithProxyUrl(proxy),
		tls_client.WithCookieJar(jar),
		tls_client.WithRandomTLSExtensionOrder(),
	}

	client, err := tls_client.NewHttpClient(tls_client.NewNoopLogger(), options...)
	if err != nil {
		log.Printf("Failed to create client: %v", err)
		return nil, fmt.Errorf("failed to create client")
	}

	// Create Task
	task := &FuncaptchaTask{
		ID:     strings.ReplaceAll(uuid.New().String(), "-", ""),
		Status: "processing",

		// Site Specific
		Preset:  preset,
		SiteUrl: preset.SiteURL,
		SiteKey: preset.SiteKey,
		ApiURL:  preset.APIURL,
		Blob:    blob,

		// Config
		Platform:        platform,
		UserAgent:       userAgent,
		BoostrapVersion: boostrapVersion,
		Client:          client,
		Locale:          locale,

		Hardcoded: hardcoded,

		// Referrers
		EnforcementHtmlReferrer: fmt.Sprintf("%s/v2/%s/enforcement.%s.html", preset.APIURL, CapiVersion, EnforcementHash),

		// site bda specific
		WindowAncestorOriginsData:    preset.Data.WindowAncestorOrigins,
		ClientConfigSitedataLocation: preset.Data.ClientConfigSitedataLocationHref,
		WindowTreeStructureData:      preset.Data.WindowTreeStructure,
		WindowTreeIndexData:          preset.Data.WindowTreeIndex,

		AcceptLanguageHeader: acceptLanguageHeader,
		DataBrandsHeader:     dataBrands,
		IsMobileHeader:       isMobileHeader,
		OsPlatform:           osPlatform,
	}

	// Dynamic
	task.XArkValue = task.Utils.XArkValue()

	return task, nil
}

// Initial
func (task *FuncaptchaTask) FetchChallengeData() (utils.ChallengeData, bool, error) {
	reqURL := fmt.Sprintf("%s/fc/gt2/public_key/%s", task.ApiURL, task.SiteKey)

	var bda string
	if task.Hardcoded {
		if task.Platform == "iphone" {
			bda = task.GenerateBdaHardcodeIOS(task.Platform)
		} else if task.Platform == "chrome" || task.Platform == "edge" {
			bda = task.GenerateBdaHardcodeDesktop(task.Platform)
		} else {
			return utils.ChallengeData{}, false, fmt.Errorf("hardcoded mode not supported for %s", task.Platform)
		}
	} else {
		bda = task.GenerateBda(task.Platform)
	}

	// testing only
	//bda = "eyJjdCI6IlR4cHZOV2RyWlZiRVN6RDU5K2hGUnNOTGhEOHRjTDBsM2Y3Znl4eWg1UW1iZHRLSGhDVVU3UXJaNVBNem0yaloxUjVid29aclZLNHk1Ym1QZkJ3OVY2MTVTZU5MWXRZVmtJWENnUmMrdUc5S3ZNRUdMd05rbzU4ZFZqZGZoVUNYY0lKbGVOenFNV0JQKzBmVmI4b3ZhSEVlQXZSdlJUd3ArREpFRU05OWx3c2g5cFhjUWViYTVhSU90ZngvWUljQ0VIcEtrVDBGcHVPTlBRVXkvV0I5K1IwcWhwY2lITGtiN2paZkZOUEd0R2RkVDlIL3VxaFRHVzVDRVBLdi93T1NhcmcvczY5Y0MvME5lVExSaWRnYnNJZjVRVmdYajdMQWdHdGN4cFVFSEtmeHdxZzVBK3BYOUlpREFjOTNaMHJ5Zlo1YjBkM1RBaDBkYmJXd1JNSHFDQnFjMkVTZEdVREJDcDFJcHFDek9md1EwQncxN2k5bjZhblppclpOaDRGNkxROHJhUUNXQUR1M1pFSElmcXRtSmhtRlJSWlhUaVdQZk03RG9LL1laYU5nZmM4am15TjRjclZHRE1ZNlJpdnZBSGo2cDBhK3VRWklnc2hhLzNlWmt5WG5SMEdoN1FtK2ViNExFWEVnY3dsSDRkeDdjR0w5K1hUcmtxd0VHWlo2Q2kzRFltR1BGVjRpL1lpbHdNS29ZbmJ3SitwZTcvb1NGeUtCOUR1Yit2R0ZNUmFxWEtpM1hpUFBpTnZpUUVBSWdZbWF3OXFsWnhMUDhOTVRuZHFHZUhLek1oa1B4cTZMalMzd2RaOGtKYWVyaHhhdVQ2dEZUZWdxZUw5R3Vrb2NIcEtVbWl4ZUJNZndlcGNYc3BwSFArTlRGQW1wK1JyQ0RUVTN4ZnZJZHpVZEF5RFRPcUFhb1VkS1RjbGNRWkdFNUQyMjlmYzVNV3RPWS92YmZwc1NVU1JDWXFKQ1N2UXlZcGpPb0tTZkRxV05vQVZTRmVWL0hRWi84TnErZ3E1VWtZTzgyQnF6OWlIR2t5WXlNc3NsdVBnVmoreFBsMVg1RUhBN0J0NG1wVCs4czlybU1TOWZXcURsdXdzVnBzTlRWVFRLZWVJR3FNdGZBd01lZG4vWFMzRVVYeEJ1dFE0TW9QZHZoMngvWGVlSkp1MVhqOWpZQmEzYm1RYTlubU1Ybm05R09FbkR2ZU9XMjRsOGNhdXZZUGdiNEZIcWxLUVErT1hqNno4N2I2WFl4UVNSV056WGk1V2lkUWlDM01PZVY0VGpmL3VBRWhMQWgzNXVldGF3cW5jNE1abzdFdDdzSVBpcFNzelBEdkUwSERyZ0dSUDA4Q0JvT212bER5UzNTQlRLR2FJYWNWQkViMDBVK1BCb3JDSW96bWlQY2x0c0F0ZCs2aHRtUjFiMDV2Qnk4bW9TRzRLeitEWkhocEtvYXlKTW1zWjhaVlZQUGNBaXRmaEJyTkYxeFBKQjl6MlQ4eUY0UVo0enJnL09RZHI0ckFpT1N5R0l1UWNLVDV5R2s0U0tBUGN4cTg5OUdmdVpuSFJGMWxpSGdoTWI1TnFkUkx0N2l5akcxT0Vrd2FKNmwyU01GSHdseWIvSjdJR1ZSKzdVNkREYWNqUlEvQUt6ekpoejNRR2Vob3FzdEx5S2tTM2FqbmNDL1JlNUpkdDBTbitwSlA2KzBXR2R0QjVocjM0MitNVHpGbnhlYVoyaTRVMXN2ZHE3eEh4S1Fvd21mang2MWRZNmtISC85S29oempTaW00NTFtSWlSQVczVWtYZG9VODRPNWIwWlI3UDNUMkxjOU5RMmgveUxGUHM5RDJVYmZFTmFyWE5lTmp5cmVqZ3A5M084eWw5SHpPZkVLdGFnS0VTbUluL2loRUh2WHZxLzljK2FpTTFremZzUk0xQzhJQ0RLV3YyRFd5OWZyNUFyYlBUTFArZkxVQXZOOVNOTXBmZFB4RTBLaG5mTXN3enZXOUt5dWEwbDZ0L21FTDdwRXdCZU5ZcUg5T09LUFFOODJaSjdKZlh0YnhzRVNtWDVUekpVMTFBbzVHOFJNWE5VTFB1M3ZOdXVxVWtUZEVVRG9LZk5kTkgxQ0M1WmtGcUVpK1l3Wmo3c01XK2pkVDEyWEU2SlE1dTN2bU9EaXd1THF6Sm1LTk1XcFlpaU81UFQ2SUFFRk5MbVdYc1JzaVpWUVNiSE91a0F0dkt3Z0NUUmRERFdiWEhMZFVIN1F5U25oRUtFVFc0UkhFWHhKL1RKWWRHdWwyNnJKNHVhN0xuMFQ2RDJDMll3dCt1YlI1bXA0bWxHQTNQbGcxS2Z2Ynl1NWRoNitjK3ZhbUhnQ2J2QTRYVHNDNFlReVZnZHhWOU00Q25zTzBZQXU3MU1KRFAwRnhRNDB2ZVJTK25HTVZYWG03bHNmTmhJeFpWLytpdjBlK1ZaUXFuVitwWjE1d2hOVURqcTBWbnI3NmZMa0tyKzZ5djZkZ2I4elBtL0o0ZXFPMHpGM2grQ3ZmbVlnM0hSZUtPT3FsVWtXVWJzeS9JMzQzRkdOeUkvbGZZY3NrWWgzRGREZXhGZDFQdjJMYTllUUhoYU52UllJeEFUaU9Mci9JaVlWUXpkcG56alkzdWNYejJWc2hyRDhiTDU1YXVWZFRPY3ZvVFNRU3VOU3JxT0NhUFM1QjBZZW5QWGJhWkx2WlNIam5Ra05ybTdpUjFvd1dvZVlqT0xhdktmVUNsUjVsVldyZVdoWlN5bnpMN0J0bkZBS1BaRVZUK2pEanZ5dzVpRUFpUmdhcE12WFRUMTJLNUNiL0dpaWpNTWlwSkFFdE11a2RLdzM1WkFCSlh6QU15WjdZblM3b2o2YkNsR1FCVmJZemFSWGdmUkdZMlpPaGtwb0JxUmlPQktiQUZWTVN2K2k2ZElZanI4OUNiRHBKR3A1dmhBVU5NemdLZEZOV3VybE83akc3bnVaRHViTWcxTmpOWUkzby82Um5mS0JDT1VwR0tPeTNEbG04OGJkVGZkZnlveHhxZ21FOUMrTWxIa1RURUFxTytNZ21jTXhjdGhQaG1FOEZZR3Q5WmZTN3R5MWhWK2ZFN2ZBSVNvNFhqSmxMT0gxdkRqZERqMEVUeTlTcldMVHNuYjVxVTB1eFdtS2Rxd0FkUlFzTUJWdGJwcDVldW50R1dkVnNzekRSMFAvK29QaUNwVmg5Z1N4R2Y1SGtEQzVQVy9zYnlJSWtwNm5udWtjZHEwZ285engwczVlYk1jWUg0bDZYb0ljeEg4WVBrYXUzTkRVMVZ6UTExajBSdElwV3gyc2QrbDlrSEVxRkFWcHpKaWlRZlJyaE9pVFNTa2ZWREFUdE93UlJNSnlNM1VMbEd5S2hScHZTVm5WYXJuRFB4ZHgzZGR6M1hWbmxrc1FOVCtXK0pWVjlhcWsrSnUwaGFmczN3aCtiQVZzQUQ1Y0dmSDMwYXVvOW8ycHlMVXZ0R1hKVDV2K3hlQW43enBLUXI1L04wbW9WeUZUU2xVTWg3Nll4WXFUOGsyaHVLMFMwbmtFb2FVL1A1cE5UclhoclhQU1EzV3EzbjNadkJrckxRRGVSczhEWmFNTUZxS1hXL2dXYUpENE1mSnllVVBDWGZnQ2w5MnRoZTN6d3ZMYnhNa0o2ZGJ4V2UrMEQ2SkNFSmgrVzVnQ1EzQjByOFdMMTdmZjdxVVlaLzFOTmJSVERHNmI4elJMUlZyZnpIQ0NaUmtjelVQN25OWksrM1VaUjkydjJESU4yQXk1ZnZoQXdyM3p3ZlZTdFJNbUdSK0dhNUJCeGc5RHZtdmV6YU9KREFhNjBLSG1idGpVTVJTdkJITEUrSGxwTm9sVVAwNTZ2N05lSGg5WXp4emtoRW1QbCtHSVZreUVXOFFmMWlDcjZob3F5NW1IRmFBYktNLzhnTnhoZ2hqQkg1UGZFMGlIcDBCN0dIWTFhQXRBd1JwdURsYlVyekxkTVVlc1JnRXEyRWpUWnUzTTVzVFA5UlJZV1h6OGRDcFg1allQZU5LZjVzN1dtb3pUWk1Ebk5jWFR4b1pxVFRXUmdhVU9uSlVKWEdsK21Nb2dKc2k5TnFlWW9zSzFNcHU5R2c4aUlaNmVOdTh5VFlVWkFEWlhHQll5dmM5VG16aldadDZ4ZjEzQU1hejQ0WHFBbk95MGlVaUNOdmo0MzJ4Q3V3SzBydVZWUHB5czNCN2JTeHJYVjlyMFRBWlhhT1Bzek9lSUQ3RlBnWlFQZ0JRbWtlQkp4VllOL04wOXFXODh3TnR1ZTBiZmkvQ0R0MDEvZStuMWMvZ3JPa2tWTzlJUS9jWStGRWxJdVdwdlQ2Z3JQL2RCTFY4b1V2cnR6ZDdWWkxDakllZjlNWVczM3h5dE1TU2NnNjA4SjNzN0xvb2YxV1NjQVRwSTdQWC9ZUDlEN3N3V2x6UUtOVk9iaVBadXJMeEdwbE9hZGVLeGR4UWI1TS9kekljZTJJSVFuTGowblZFM3F5bXdQZ2NWR2hsZTB3VGpEQ2hvektVVm1lc1ppS3Bsd0RiL3NzTU9kcmFmTGRxRlMvL3JGYkRwc0pXTmdZd2dXYVNqek5OZmVoa0pjWEdtWUZrVUthcXcySHFWTTVEc21Nb2J3TzREcUxnT3pFS0hVdUFmZGVFUlY3bXZQSmxrYjRlN0JjRXhaenQvdFgvdlM3YUo0MjB1SE1HM3FrZ3hpWkpNdXRiSkkvRTlHY2VoY1lsRkpNTHFROTloMVZMM282MTRmdzBwQ3ptRnlGTHB3MEpvWUpPZmZ6U050MDdDZko1OFV6Vk1CWlVYTSt6cko3aGF6U3JVWGRybm4rOGVWYVgxT3NoYjB3OXpSbG10dXducTlIOHJFR3h6S2h2bTRVcWwvZDlQTUEwSGd6T0YvRzNXcFpMZGxpNVZTUjExMGNZb1hNYllhVFlycm1USjl1Wm1EZk9DQUkxdGNva1V4dVZlejdwY3YrUHlxRDhaZHFiR0g1YmZSTkZZWERsbHBsN01YN2VBNkJNcTU5WnhXQzgrZlFiRGFkVW9MaFl1NTlraDJ0aDRVYjY1cXh3S3BxNHNrRGhpZ1NPU0FvSGlCbWZkdkQrZGpZeHY0KzdMVHUzVHk4bnJYdUhqTnErVGlmU2ZSVk5wS09lM29uVDNYMk9vRXA0Ym9jbkZveU5kaXlIOTBVb05jdDFzc1lESjNyMVIwdklFTzBrZlhqQ3FOTkhGV0J2dG5GbHNnWU5seU5zbUJRdHF0ZlFmSmY5dHFxdVhTQ1VZdDlYQ0FaVDV6VXhnZmFZdlZhTHRMRlhGem9meUFrUld6UmwyTUV1RU1KQXFmTXJPaFN5RWc5RFZFZWJMOUpHY29URmQvZ0U4YUcxVGNKUndtayt5SHZGZCthZ2FGMERVZHo3cmFXT3RzK3BiNno0UVlCSGorWDRoTFRCWkQvOFR2N1J1UXZuU2pLVFdvbTdJVFNFLzdyMTI3bmtFZTFnazhRY2hZdzZWZVVUOVFIQ2JnT25RSFhkWTVTL01zYXlMaDUrOVRaaVh2RDZ5cGFDTnlMZXNHZHA3emt5NXpGVHdOL3hkOVRGeWVJWS8yS2U4NFhIK2owZFRGLzMwT2FsUkZxb2JZY1RzdDVyOCszeWg2V1RmWDV0WTg2TlZwY1psMHArY2d4Uyt3VGpaMnlWZEJXeHFpWXNrdjYzWDNWTERHMEhoWmxPb0lkVEJ3N09aNWtIYXlONjhwY3lnTGlISW4zY25ySXZxcmFsQVJPRFpkeWRjdHJadEVtWWcyZVZOMlV5UWdmR004ME5DcnZiNUJ3c3J2cVdYbFY1d0ZzaTJSaXFQRGZjTHFNRk5vczE2Wm1iSUxjckFtRk81cFgxU1ZQSWRsOTE4clVzL2luc0tRRW03K1ZHclZtSXdzcnNzVXA2Y0dEVnluMklxcEVmQVU2STZ2Z2N3alBHdGN1YndaK09rK0VxeGt2b2pwYS92NWo1MHE2c2tKWERrK2hpU3AwYXJFUHdCaGh1cHNlZ0R6QWhrd1J3dUFORFY2dVR4bGNxdlh3QThnNFRKVWlDSUk1M2lDb3R4ckowTEpwUFJvcnNXeFAyT0VDZWFQVVNjdGY0SjN4VElqNll1K01QVTM4QVQzUUxCRDFONTI4SkRIRTFIVHUzRTNvVHREWlhCYk80TUFLUFRXTEdieEJHZHVkSXBaUTVmc0dLdnRpc09ZS1M4ajJZcnBQNmErU0FpS1JKWHp0bjUrVmU0V0NBVXFVVGRZQWUySXJFdXBSNlU5OGd4NnBJWmZmZmd2cjVPcjRxTEdPRUtrc1kyZUtLV1lnVUswUDd2Ky9GVkZiSWJZWEhoVEkxVnFwQ1llMVJ2SmkyNnIrbmgyWFR1aXoyUEloSDY5VEkxRW14NFJiRlp6QVVyU1hzV0lhWUw4OWNUVkhOSHhUQ2UyU1JKUzFHc1ZHNTFWVm1GRkxXRldkZFcwcWNyQnMvSUoxeTZXSnhlL2RHbGpEK2FheVBGZm5MdGR1QlJFbkVLblRtQnhWMCt3dllKbjJsdkZaT1ozRGJLV09UR3dSYW5CYW9CTjY0Q1ozSnZUaFJNMXRnRVp5TmZuRHBRQlFjTFdMRkhueFlZdXNSRkY1RVNnYm5BRFNXRDZTWVY4M1c2ZmpEUU5yTnB0MzdPN2h4cWpDNkthNllMNmRSMFh6TzQ0WXFuRGZmTVYyYWM3QTY3c3RNQm82T2U2K0dPUno3T0dlODZDeG5nUTJvZUlxdysweVN0SUVzVnZ5S3JyMld3U0ZobTBKdkNINjkxMmM5dVJRT1ptczhrUTlLbWNLb3NuR05YQzJTREF5Qk01bHF5bFFWdXlZbDhyVUw2QWhzTUdBcVJUZFJFMlFEQXpTMFdibjdhNktMb2loeGRtLzA4alVkTEt5RnppbFJFem92RlZLQUtRakdMTy9ZTWZvTWk3RklJN1VxcFhDdThqSXdZMjdEUlc2NW5yNUFoTXdXa1haK2hVYjVyNmx5M2RldGVvOEdUVFZleHV1UEJFb1cwSnVFV2dENUdVZXpsa2x3ZWtDRDl1aDRBNno2eGRidWlIQjJOVjdFcFdlcE9nK2pnZ2xOTmVyK2lyWnBwb3dDbFFZNENTaXJpSTlWU0s2YjRKNGxpUEhUbk1YVlVZQ2dpWFdyOUFGUEhEVlVPdDJPL25VOEZYYUpodWJjUlY3QnpBTTg5MUx4a2UycjU2ZXB3bzRQTW9Qd1RJOER5d2REU2ZYeEdHbnR2eUlpelB6NGxrSnJBVmJBa3BOcVQ0MzluYml1SWJTckRGV3liZ1Myb01oMVFGMmZ0TGJ2RFZxRWwzdFI2d1owVkRVVFFuYU0zcWdZNHRoNkF2TjhzSUxwNEIvLytpZXhMeUFKMVI4L3BjcE43Y1FYazk2UUloRXA3bndwVTRaU2hncTVwYVVyTm85QXJJWGQyQVIxTEYxNVd4ZVdDMWxVTitkZkVBWDBObGVLMk5KMVFuazlWRzloRDFBZytIam44L1kwdE10WlhqR3Jlb3l2c0FSZXBmRUxXK2t3bndYbm1GTjJyMm5JbEkzcC9URUcydTBoNGo2T0kwbmhyWUhjVmZhb2lUYUE0S3ZWazY0YlNtL1M2L2YxaCtUS1IxT294NkVHVGpuVVZyVVFBVjVVeDZRbS9paUY4eFlHNGpVM01UU0dTeXRYWlZtdzNQZ0MySHVyTThaZWkxbHkxRzQ3NHU0eWw2dmtQbVk2Sm43MC9VWXBvVURwYTBlSjFWanN6OFNoenh5NklBNkhweEJxWWh5V1VhOVFLVUZuVmEwNFpPdHh4U0JGVG5hQitmUUJqb3Z1TGV5Q0FDRHhsRVVZcnU1VC82RmRiTUo4bVVWWjAxajRib3U2b1pRU0N4S292NDhoMUFleFRxVTRBRXp3aldvVEo1RTM5TU5qMmo1elc2WWtDZU92cmxqOHlPWjhKR2g5anVQWWZCMU1RakJWVTR4UklWc2N3bkcyL3RncDRmUVYzbE5jN01UWldaUTk3WW1oUWZYSDMzVkhSZkROZitKb2lFZHQxZG1TSVBmK2FmRXhBKytOaW42UGRTMFdpMFhkOEREbXhuUnpPY29jMXZGTzk1aXpwb0JKKytPZkllQzNmcHFYK09CMnBZT1NPMTVQUHJGclhyMWpvMHhQbFJGMGI1Y2lZM0xsV3RiM2hQTHhaaldOaTVnU1lXbmsyKzRueFFnS1BqekpWVHpUVWp5M2dYbmRwb2NYRXBFOG90VmlZQlJQdFl4eVNJZTlQZXJzeTRqdTYwM3VRYjk2RXhqODZxRGdjL0JpN2d6a0Q3TDVJRkl4eXVpNjhHSlFURnV2YlhsNFNjb3krS3dkQTNyMnhZeWRxb1ZCWHFCZUwzc0RnTVIza2lKVWpnOHM2UjlBUmczYUsxWm1RSGh5aEhQM3RqTnVnZUxDaVI5dzVDU0VVenZ0czliMWFFUzNJSFhYMFBHT21GZEowaHhTSEI2UVdaUHJaZlVSK3N5c2VoemNBTHJPOEtYR2JqbGVXbXUzc3pTei9ESk00YlowblVwTDZQendmdENIL0JQbVFTUWtYc0FDclQ0eWhJaVFvdjJhY1RBSkFudUFEU1pyNmR2VUpFNHN0N0ZqVjJhdFVCd1d3dnZPU2VwWStKUS9lbHRqdG55a0ZXVVdXYlZWZjJRYStZVjJMWEpGb2x5UWxMc3BOdmNnaDBrVFlsOFRNckZWS0pURnRRVWR2MlF3cGk0NmpOVko3US8rUWdYemZMb1NNUkd0M1BzZ1FST202OUU1cnY0V25Ja1QvSlFYY0J4dFUvS21DbmZjczJVWmxuU1VYYjBjOFRPZFh3NEZOcDlKelJCeHl4YzlMK0JxVFdmem1oYWFOYVJGSS9IQmpDaFFlQXVaeFQyZlhYMGJDUjM1OVpyRTVjVVNnV3lTMmJYbWwrUHRLSk9pNUxKMXZmZWFYNDMzQnhkbTd2WWxyT2JaejhPSnhMNzZNd3BWbGtKSEtYUlRyNmo1V09kSHI1S2g5T2tzNlJFQlFUc21VR2c5empLS2ZGQlBkdGRubUN6R0VYOVZyZzB2WllkVHQwclhrUGpIVlZnaG9XUks5Q0dtK1J1ZktDT1pMVnIyRS9KRFB5cHQ2Wkh6WTZPVlY4OTZPTGZLZjRzSVBrTkc0NXVWdXNyVzZ4TVhxM1orazhseW1Ub281c1VIVEJYQUxXM21YVThkZ0FlK1cwWDlQQmt4VHl5QThiSTBKdU1VZUlud2hnZlhkN0lrVUc0VmJpTVh3TmxXeUp6V3BhaXUxVmtUUDRUeUt4czZEMER1TFBNc0g2TWVWVEQycHV0MWVrOTFmTXJybVBlYjlLUEhaTnNGVVZJMnQ3RlVlcTh2aTd3bGVaUnZ6QmVjd08wSGV2cWhQUXBmblNnNi91L3V4RGZUeUZ4V2tRVGxQay9ZdGZjTGhIWk1xVmNvR0Y3SDgwNlNjMm85eHd0b01SMFExYnlEVkZSbGFQaWYrUHZOSlQ0bWoyWEtFWEtoZGRrRmtkRWljdTZkKzh3YmNMdkxnd2IvN2xadDNmZENWbklRSXlGNUFXQnpTS3d2OVRrY2IwSzI3TlhtRVhtTjlIcmR6WGdhTm1HdldzSG11MmZsWmpxT3FaTkFzdGpEZ3hXdG9BUXdnWlR4WmZEY2U2bmVsMmlyY09wdWxMZFNZeEwrWVhaZ3pKQzE5OSszTlRMV2RmSXV3VHNuV1BRdW8zRTJVd3Z2MzcxT1R0WlpQZlhUSHp2cDZPdmR2THlFc1AyOUFsWml4Z1BJNytQS1FUSzd1SGZkWlBZMlRURzNOR0VGc01UQlhPblNsOGJMeDBHS2hzSXBzNG1VeW8vcnRBYkVSZVlHb3RYVXo0Q2tZS0NZZCtIMXJyekdKa3YwRHhCMVI4L3ptY0dkWkRzQklaUWhVR000eTVDRW5sR1ZVMVR3YjVjTTEyOWYwZC9SaWZNamk5aFF0TDZzY1EyMGpRMWVsT0JMeWY2UzZ5VVBnS2pTK29wQmVraWlsK1JRSFRWL3h2MEk4Z2w4enFQNlVCVVpFM1FJeWpBdjdIZVpHdGlKWStqQnk0Z2FZRlBvOE1SSXNkeWd0TVBkNURSdEtTWmtXZ1J5dHlScnRrckpKM1k3NVFKTmY0Z0c2Zk45NWtSVmNrN3ZrNEhMWEtNaFJCMjRmWTdwTzQzSGJuVkR0VWdKWVdnVTVHakliY0pEdXoxeUZSRDh2VWhIMEgyVjE2Vmp5dGZpOExlbDA2d1VTVXpXSjd5ZzVNWFVRRTBocnZvN3ltMFNlVU9BMW9IWk9tb2FrYTNHS0RIdVpZTFduSUZyRHZMWlJHd01OT2xZSE9FZGh1VFV5UDc0MU84anNvbzIrck9QMHN6WG9VV25ZcmEySGNhTFdPVWUySUx3alpGcjB2YkRlRkp1SWI3dnU0NDQ0UXlFNDhWdzFENUFzVndQL0JVc3ZwU3NpR0NpeldVb3ZWSWpxOUlTRktiejN0V2MrSlBtdDFmUVA5c1NjQUFwTFM1VHFnUm9hTFRzUGtOZnNYcklYeTROSmpqTWNkbXlLNlA2K3VEQlRNYlV0eGI3TkJKdEgvckoxZW8ra1dZeG9QVmZuNnM4cUlhNStrbEI5OVllTUc0S0dGWEVlL1A0aFBSOHBsTlpaaEgyY3h5S1FjbmY5eFYxZlhUQUNqRjJiOUpWZ25tOTNOZjM1S29vMTBOVlRvVXErUVBtRjdBVldiUHlUUENsMVdCOUpJaTdYY0ZySjB3UExwYllUNFdXNDlycWJLekFXdDI3Y3kzZk9IREh0dU14anlCcDFpRlRrS1JSZXVwQVdPeHFFMFNBNW1KU280Unc0a1J1YWpBN3BMRXZaS1ltWkhXUHFLZHh5NkdNdUVJWFNYL0dQTFhuT0kyVk5NdXpaZkJHa0xBc3pBN2FTUXcya1JNVTV6bUxFd1BPWFdTKzhhRTBUMDZMWHNPeVUxd1VZQjVnc0pZOGxScFNobmxqdEt0RUIzWWEwMDh3cG9vci9KVW9naWp6RzZhTW15a1dLR0Fobk1sNm9KV2g1bjVsUnhUVUNiRmIydzR0czRUdjZBaW81L0tkTHVzR2h2WDFNZFJ4ZEsxWlBWVlkyR09pRnprZU1XS1R0OGdsSFBKUnpiRm5wWmk5Uk5melFYOVk3VTVsZGIzYVZ2TmVGZHZVZTBhUjZEZTg0TEtTMzdFSE1CVlZxRGhER1lGUUVKSEpCMmppRFVjenlCcWMwV1FYb0JqK1RORnRCTFlPMFhVaHAyclZCbElrMFRDamhPWUxsVUxaeEZpNnRGVThJS080UkY0YnpEeVF4T2xTbFV1bGVPZmU3eVdaZThiUFBzZG1Pb3Z5c3ZwSkYxbFh1MFJrS05pSElQKzltV2cxNjZ1aHluMVJ6Y3JWY01wS2s1dWNuQUp2VVh2a1QyM1o1UGRDWDJuZS9kTjRtUm50cFdmUmJSajBlZzJaK1RRODJuZjQydEdrb3RJMzlOT3IrdXE5V2FSUVBqd205VXFOVENPY0FIazFDSDFkRDlJRG5oUUNKSU1sYm1UOTQwdWNVZFE0QkNKL1ZRZ1o2WVhTRTFkTTVlSDZlUGFHNzU3eEZhcVFlM1JsM2hOUHNZQ3N0REVmSlBTK1lJUlR0Y0tJL1ZUcGE2VDRRSjJOT0RCU0U5MUlRNDY0dEc0dVZkR3k2L1pwMTNpMmdkWVY1anRRSjdmQTlsRVRsTlZ4ZUdDanpRQ1dqd3k4RHpWWGg3NnBIWEowZXNybUJBV2V1SU1LUERBOVBndDVMeElxVXhPOHVWMUVUZlhmWFk0QWZYbDBvOUk1aVdlUVlaeVQ1RXZwdXhEcFRJNzJqcDY3WllFZDQrL1JwVUtRdkpUNGZMbXN4Y25HcytrQ0NzUkllWSs5VnhqZVhFSnNzeHJ6QTRjdERZMTdiUUhyZkFYQnhZWExPQUJnNWJ4RmVQMXJXcWRENFMxMTQxeitBTFQwU2tvUzgzbm9aU0xOeVlSOFpvQSsxSHJzc3dXVjR4RllnOEtzcnhJMmNBd09aQklTSTQ3TnpxSFhSV2JPelFsUUlhSzRqUVgyaUtzNDZpamlWeDl1ZEQ1QlNnamw0czFhTVZvRXlJNW5mbEZEUWFjQk5aK0RkVG9ydlFORVFwQzF5QXVBZzNQUWhxcXA5bzNmRGxNS0hmemZZRVdVZUVLYTZRd0VyemFtY1kycVZVTjdJWTdmN3RPb2NTOTRSakt2KzNoalhNKytDY3lVN1VUaU9SSkFpYldxd29Ram5QU2JJMUFKTGwwVUg2ZGREbENGbVNOdWtOQlN1dm0yVGIyTTlCaktoVjQ4SUJOZFlDbEZWT1RrYzY2aWd1RFhBVDhKcm9vQ254d3l5aW1lSjgwbTlYdFB6c2cxVHBSYkkvTVBSa0tCdW1SMW1uUzhUblpUSndIWDBZR1hJdnFzWlVJZnJwKzQ5dlU4Zy9DMVNTOEhNZzhxWXJTdWdPRTEvbHZZVkovYS82eWRDbVoxcHNtT1NrT1phOXM3MC9UYzI4SXVwbkpNcmVzNDdoMy9HbjBiNVpVZDA0S29LZ0tLZStVckJBbTQwS1pGOStjeHFTa1pNM0xzOEcyMnBYTThNYXRQTklNdmkra2IxSlFHanpXVDNyQjJ5aHZPWGI3Z0h4aG54b2w2czRKRzY2eExwMUFyYlNjM25EMzR3OENxdEd4bWVVa2ZyWUNnU3V0dE9PY0ttdUtNZnlSaXNsakhwTHlZb3lwUTBIYVZGVDNMejE3ZW9UTFlSZWhTa01uUXdGSUQ4Tk1vV0ZIaXdxYkdySzdYeHNzdFcrd2d3Q29CNmtJcDJmRFE2ZmVWVTg2eHlkUXRLWHRqNTVTM0F2WlRqZ1hKTFhWS1ByVHhTTWtYUC9BRU54a2kvakxMTVpkSWsrVVdzYWhuZ253UXRYNk85djVtdFJ1YnU5M01UYzZ6SVNSalFEU1F3RTN3RnBNSCs1YmFIc3luWmx1c2dMS1M3WjJscXlOUEhCWWtCR2JTVTJuSjRRTW9UcVJrd2FsS3A2Ri90b3hLem5NQ2N3QmV0Z1NiVWRVQW5Ud3dWb3FsS2p5WVVhVmF5TVRwVlcyYXpLVXhLUndtSzdDM1J5a2xRcXZ1R1FZNmZ3NzIycHhVY0hNV2d0OVZsU1R1RlBsYlpwbHpEV0RkVWI2L01mRG5XZUI4T050a2krRDgycHRuN3k0aEVlQXZHcEpsai8xWnNqUThFdjhjQzlhN1ZldlZmQjMvZ2RlR2VPeTN0OTlxQStnSzZPb29YK0hYeDV6b0JpZG5nNTVDZXc9PSIsInMiOiI2NGQ0YTcwMDdhM2UzMWM5IiwiaXYiOiJlYzI4YjhkMDlkYzdiMTQyN2Q5ODY2NzdmZjAxMWNhMSJ9"
	//fmt.Println(bda)

	escapedUserAgent := strings.ReplaceAll(url.QueryEscape(task.UserAgent), "+", "%20")
	escapedUserAgent = strings.ReplaceAll(escapedUserAgent, "%28", "(")
	escapedUserAgent = strings.ReplaceAll(escapedUserAgent, "%29", ")")

	data := []string{
		fmt.Sprintf("bda=%s", url.QueryEscape(bda)),
		fmt.Sprintf("public_key=%s", url.QueryEscape(task.SiteKey)),
		fmt.Sprintf("site=%s", url.QueryEscape(task.SiteUrl)),
		fmt.Sprintf("userbrowser=%s", escapedUserAgent),
		fmt.Sprintf("capi_version=%s", url.QueryEscape(CapiVersion)),
		fmt.Sprintf("capi_mode=%s", url.QueryEscape(task.Preset.CapiMode)),
		fmt.Sprintf("style_theme=%s", url.QueryEscape(task.Preset.StyleTheme)),
		fmt.Sprintf("rnd=%s", fmt.Sprintf("%.17f", rand.Float64())),
	}

	// Extra Data
	if len(task.Preset.ExtraArgs) > 0 {
		for key, value := range task.Preset.ExtraArgs {
			data = append(data, fmt.Sprintf("%s=%s", key, url.QueryEscape(fmt.Sprintf("%v", value))))
		}
	}

	if task.Preset.BlobRequired {
		queryBlob := url.QueryEscape(task.Blob)
		data = append(data, fmt.Sprintf("data[blob]=%s", queryBlob))
	}

	// Format Payload
	payload := strings.Join(data, "&")
	//fmt.Println(payload)

	// Create Request
	req, err := fhttp.NewRequest("POST", reqURL, strings.NewReader(payload))
	if err != nil {
		return utils.ChallengeData{}, false, err
	}

	// Headers
	req.Header = fhttp.Header{
		"x-ark-esync-value":        {task.XArkValue},
		"user-agent":               {task.UserAgent},
		"content-type":             {`application/x-www-form-urlencoded; charset=UTF-8`},
		"accept":                   {`*/*`},
		"origin":                   {task.ApiURL},
		"sec-fetch-site":           {`same-origin`},
		"sec-fetch-mode":           {`cors`},
		"sec-fetch-storage-access": {`active`},
		"sec-fetch-dest":           {`empty`},
		"referer":                  {task.EnforcementHtmlReferrer},
		"accept-encoding":          {`gzip, deflate, br, zstd`},
		"accept-language":          {task.AcceptLanguageHeader},
		"priority":                 {`u=1, i`},
		fhttp.HeaderOrderKey: {
			"host",
			"content-length",
			"sec-ch-ua-platform",
			"x-ark-esync-value",
			"user-agent",
			"sec-ch-ua",
			"content-type",
			"sec-ch-ua-mobile",
			"accept",
			"origin",
			"sec-fetch-site",
			"sec-fetch-mode",
			"sec-fetch-dest",
			"sec-fetch-storage-access",
			"referer",
			"accept-encoding",
			"accept-language",
			"cookie",
			"priority",
		},
		fhttp.PHeaderOrderKey: {":method", ":authority", ":scheme", ":path"},
	}

	if task.Platform == "firefox" {
		req.Header = fhttp.Header{
			"x-ark-esync-value":        {task.XArkValue},
			"user-agent":               {task.UserAgent},
			"content-type":             {`application/x-www-form-urlencoded; charset=UTF-8`},
			"accept":                   {`*/*`},
			"origin":                   {task.ApiURL},
			"sec-fetch-site":           {`same-origin`},
			"sec-fetch-mode":           {`cors`},
			"sec-fetch-storage-access": {`active`},
			"sec-fetch-dest":           {`empty`},
			"referer":                  {task.EnforcementHtmlReferrer},
			"accept-encoding":          {`gzip, deflate, br, zstd`},
			"accept-language":          {task.AcceptLanguageHeader},
			"priority":                 {`u=1, i`},
			"te":                       {"trailers"},
			fhttp.HeaderOrderKey: {
				"user-agent",
				"accept",
				"accept-language",
				"accept-encoding",
				"referer",
				"content-type",
				"x-ark-esync-value",
				"content-length",
				"origin",
				"cookie",
				"sec-fetch-dest",
				"sec-fetch-mode",
				"sec-fetch-site",
				"te",
			},
			fhttp.PHeaderOrderKey: {":method", ":path", ":authority", ":scheme"},
		}
	}
	// Iphone Headers
	if task.Platform == "iphone" {
		req.Header = fhttp.Header{
			"accept":            {`*/*`},
			"content-type":      {`application/x-www-form-urlencoded; charset=UTF-8`},
			"sec-fetch-site":    {`same-origin`},
			"origin":            {task.ApiURL},
			"sec-fetch-mode":    {`cors`},
			"user-agent":        {task.UserAgent},
			"referer":           {task.Preset.APIURL + "/"},
			"sec-fetch-dest":    {`empty`},
			"x-ark-esync-value": {task.XArkValue},
			"accept-language":   {task.AcceptLanguageHeader},
			"priority":          {`u=3, i`},
			"accept-encoding":   {`gzip, deflate, br`},
			fhttp.HeaderOrderKey: {
				"host",
				"accept",
				"content-type",
				"sec-fetch-site",
				"origin",
				"content-length",
				"sec-fetch-mode",
				"user-agent",
				"referer",
				"sec-fetch-dest",
				"x-ark-esync-value",
				"accept-language",
				"priority",
				"accept-encoding",
			},
		}
	}

	if task.DataBrandsHeader != nil {
		req.Header["sec-ch-ua-platform"] = []string{task.OsPlatform.(string)}
		req.Header["sec-ch-ua"] = []string{task.DataBrandsHeader.(string)}
		req.Header["sec-ch-ua-mobile"] = []string{task.IsMobileHeader.(string)}
	}

	if task.Preset.MobileKey {
		req.Header["x-requested-with"] = []string{task.Preset.AppPackage}
		req.Header[fhttp.HeaderOrderKey] = append(req.Header["Header-Order"], "x-requested-with")
	}

	resp, err := task.Client.Do(req)
	if err != nil {
		return utils.ChallengeData{}, false, fmt.Errorf("proxy error: %v", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return utils.ChallengeData{}, false, err
	}

	// Check bad blob
	var errorResponse struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(bodyBytes, &errorResponse); err == nil && errorResponse.Error == "DENIED ACCESS" {
		return utils.ChallengeData{}, true, nil
	}

	// Data
	var challengeData utils.ChallengeData
	if err := json.Unmarshal(bodyBytes, &challengeData); err != nil {
		return utils.ChallengeData{}, false, err
	}

	return challengeData, false, nil
}

func (task *FuncaptchaTask) FetchTaskData() (utils.TaskData, error) {
	reqURL := fmt.Sprintf("%s/fc/gfct/", task.ApiURL)

	// Payload
	formData := url.Values{
		"token":                 {task.SessionToken},
		"sid":                   {task.RContinent},
		"render_type":           {"canvas"},
		"lang":                  {"en"},
		"isAudioGame":           {"false"},
		"is_compatibility_mode": {"false"},
		"apiBreakerVersion":     {"green"},
		"analytics_tier":        {"40"},
	}

	req, err := fhttp.NewRequest("POST", reqURL, bytes.NewBufferString(formData.Encode()))
	if err != nil {
		return utils.TaskData{}, fmt.Errorf("failed to create POST request: %w", err)
	}

	headers := map[string]string{
		"Cache-Control":        "no-cache",
		"X-NewRelic-Timestamp": task.Utils.NewRelicTime(),
		"X-Requested-With":     "XMLHttpRequest",
		"User-Agent":           task.UserAgent,
		//
		"Accept":       "*/*",
		"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
		"Origin":       task.ApiURL,
		//
		"Sec-Fetch-Site": "same-origin",
		"Sec-Fetch-Mode": "cors",
		"Sec-Fetch-Dest": "empty",
		//
		"Referer":         task.EnforcementHtmlReferrer,
		"Accept-Encoding": "gzip, deflate, br",
		"Accept-Language": task.AcceptLanguageHeader,
		"Priority":        "u=1, i",
	}

	if task.DataBrandsHeader != nil {
		headers["sec-ch-ua"] = task.DataBrandsHeader.(string)
		headers["sec-ch-ua-mobile"] = task.IsMobileHeader.(string)
		headers["sec-ch-ua-platform"] = task.OsPlatform.(string)
	}

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	// Request
	resp, err := task.Client.Do(req)
	if err != nil {
		return utils.TaskData{}, fmt.Errorf("proxy error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return utils.TaskData{}, fmt.Errorf("task data request returned invalid status code: %d", resp.StatusCode)
	}

	var taskData utils.TaskData
	if err := json.NewDecoder(resp.Body).Decode(&taskData); err != nil {
		return utils.TaskData{}, fmt.Errorf("failed to parse response JSON into TaskData struct: %w", err)
	}

	return taskData, nil
}

// Passive
func (task *FuncaptchaTask) Callback(data url.Values) error {
	requestURL := fmt.Sprintf("%s/fc/a/", task.ApiURL)

	// Headers
	headers := map[string]string{
		"Accept":               "*/*",
		"Accept-Encoding":      "deflate, br, zstd",
		"Accept-Language":      task.AcceptLanguageHeader,
		"Cache-Control":        "no-cache",
		"Connection":           "keep-alive",
		"Content-Type":         "application/x-www-form-urlencoded; charset=UTF-8",
		"Origin":               task.ApiURL,
		"Referer":              task.GameCoreReferrer,
		"Sec-Fetch-Dest":       "empty",
		"Sec-Fetch-Mode":       "cors",
		"Sec-Fetch-Site":       "same-origin",
		"User-Agent":           task.UserAgent,
		"X-NewRelic-Timestamp": task.Utils.NewRelicTime(),
		"X-Requested-With":     "XMLHttpRequest",
	}

	if task.DataBrandsHeader != nil {
		headers["sec-ch-ua"] = task.DataBrandsHeader.(string)
		headers["sec-ch-ua-mobile"] = task.IsMobileHeader.(string)
		headers["sec-ch-ua-platform"] = task.OsPlatform.(string)
	}

	reqBody := bytes.NewBufferString(data.Encode())

	req, err := fhttp.NewRequest("POST", requestURL, reqBody)
	if err != nil {
		return fmt.Errorf("failed to create new POST request: %w", err)
	}

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	// Send request
	resp, err := task.Client.Do(req)
	if err != nil {
		return fmt.Errorf("proxy error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("received non-200 response: %d", resp.StatusCode)
	}

	return nil
}

// Solving
func (task *FuncaptchaTask) FetchDapibCode(dapibURL string) (string, error) {
	// Request
	req, err := fhttp.NewRequest("GET", dapibURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create GET request for dapib code: %w", err)
	}

	// Headers
	headers := map[string]string{
		"Origin":          task.ApiURL,
		"User-Agent":      task.UserAgent,
		"Accept":          "*/*",
		"Sec-Fetch-Site":  "same-origin",
		"Sec-Fetch-Mode":  "cors",
		"Sec-Fetch-Dest":  "script",
		"Referer":         task.GameCoreReferrer,
		"Accept-Encoding": "gzip, deflate, br",
		"Accept-Language": task.AcceptLanguageHeader,
	}

	if task.DataBrandsHeader != nil {
		headers["sec-ch-ua"] = task.DataBrandsHeader.(string)
		headers["sec-ch-ua-mobile"] = task.IsMobileHeader.(string)
		headers["sec-ch-ua-platform"] = task.OsPlatform.(string)
	}

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	// Send Request
	resp, err := task.Client.Do(req)
	if err != nil {
		return "", fmt.Errorf("proxy error: %v", err)
	}
	defer resp.Body.Close()

	// Response Body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read dapib response: %w", err)
	}

	// Check if not 200
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("dapib request returned non-200 status code: %d", resp.StatusCode)
	}

	return string(body), nil
}

func (task *FuncaptchaTask) SubmitSupressed() error {
	reqURL := fmt.Sprintf("%s/fc/a/", task.ApiURL)

	headers := map[string]string{
		"User-Agent":      task.UserAgent,
		"Accept":          "*/*",
		"Sec-Fetch-Site":  "same-origin",
		"Sec-Fetch-Mode":  "no-cors",
		"Sec-Fetch-Dest":  "script",
		"Referer":         task.EnforcementHtmlReferrer,
		"Accept-Language": task.AcceptLanguageHeader,
	}

	if task.DataBrandsHeader != nil {
		headers["sec-ch-ua"] = task.DataBrandsHeader.(string)
		headers["sec-ch-ua-mobile"] = task.IsMobileHeader.(string)
		headers["sec-ch-ua-platform"] = task.OsPlatform.(string)
	}

	queryParams := url.Values{
		"callback":         {fmt.Sprintf("__jsonp_%d", time.Now().UnixNano()/int64(time.Millisecond))},
		"category":         {"loaded"},
		"action":           {"game loaded"},
		"session_token":    {task.SessionToken},
		"data[public_key]": {task.SiteKey},
		"data[site]":       {task.SiteUrl},
	}

	// Request
	req, err := fhttp.NewRequest("GET", reqURL+"?"+queryParams.Encode(), nil)
	if err != nil {
		return fmt.Errorf("failed to create suppressed request: %v", err)
	}

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	resp, err := task.Client.Do(req)
	if err != nil {
		return fmt.Errorf("proxy error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("suppressed request returned non-200 status code: %d", resp.StatusCode)
	}

	return nil
}

func (task *FuncaptchaTask) FetchInitialDecryptKey() error {
	reqURL := fmt.Sprintf("%s/fc/ekey/", task.ApiURL)

	xRequestedID, err := task.Utils.GenerateXRequestedID(task.SessionToken)
	if err != nil {
		return fmt.Errorf("failed to generate xRequestedID")
	}

	reqHeaders := map[string]string{
		"Accept":               "*/*",
		"Accept-Encoding":      "deflate, br, zstd",
		"Accept-Language":      task.AcceptLanguageHeader,
		"Cache-Control":        "no-cache",
		"Connection":           "keep-alive",
		"Content-Type":         "application/x-www-form-urlencoded; charset=UTF-8",
		"Origin":               task.ApiURL,
		"Referer":              task.EnforcementHtmlReferrer,
		"Sec-Fetch-Dest":       "empty",
		"Sec-Fetch-Mode":       "cors",
		"Sec-Fetch-Site":       "same-origin",
		"X-NewRelic-Timestamp": task.Utils.NewRelicTime(),
		"X-Requested-With":     "XMLHttpRequest",
		"X-Requested-ID":       xRequestedID,
	}

	formData := url.Values{
		"session_token": {task.SessionToken},
		"game_token":    {task.GameID},
		"sid":           {task.RContinent},
	}

	// Request
	req, err := fhttp.NewRequest("POST", reqURL, bytes.NewBufferString(formData.Encode()))
	if err != nil {
		return fmt.Errorf("failed to create suppressed request: %v", err)
	}

	for key, value := range reqHeaders {
		req.Header.Set(key, value)
	}

	resp, err := task.Client.Do(req)
	if err != nil {
		return fmt.Errorf("proxy error: %v", err)
	}
	defer resp.Body.Close()

	// Check if not 200
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("request returned invalid status code: %d", resp.StatusCode)
	}

	var responseJSON map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&responseJSON); err != nil {
		return fmt.Errorf("failed to parse response JSON: %v", err)
	}

	// Extract DecryptionKey
	decryptionKey, ok := responseJSON["decryption_key"].(string)
	if !ok || decryptionKey == "" {
		return fmt.Errorf("decryption_key is missing or empty in the response")
	}

	task.DecryptionKey = decryptionKey

	return nil
}

func (task *FuncaptchaTask) Answer(result string, answers []string, answerIndex int) (utils.SolveResult, error) {
	requestURL := fmt.Sprintf("%s/fc/ca/", task.ApiURL)

	location := utils.LocationData{
		LeftArrow:    [2]int{40, 113},  // Left arrow
		RightArrow:   [2]int{280, 113}, // Right arrow
		SubmitButton: [2]int{175, 146}, // Submit button
	}

	startOffset := 20
	encodeBase64 := true

	// bio := task.Utils.GenerateMM()
	bio := utils.GenerateBio(answerIndex, task.GameType, location, startOffset, encodeBase64)

	// Payload
	data := []string{
		fmt.Sprintf("session_token=%s", url.QueryEscape(task.SessionToken)),
		fmt.Sprintf("game_token=%s", url.QueryEscape(task.GameID)),
		fmt.Sprintf("sid=%s", url.QueryEscape(task.RContinent)),
		fmt.Sprintf("guess=%s", url.QueryEscape(result)),
		fmt.Sprintf("render_type=%s", url.QueryEscape("canvas")),
		fmt.Sprintf("analytics_tier=%s", url.QueryEscape("40")),
		fmt.Sprintf("bio=%s", url.QueryEscape(bio)),
		fmt.Sprintf("is_compatibility_mode=%s", url.QueryEscape("false")),
	}

	if task.DapibCode != "" {
		tguess := task.Utils.TGuess(task.SessionToken, answers, task.DapibCode)
		data = append(data, fmt.Sprintf("tguess=%s", url.QueryEscape(tguess)))
	}

	xRequestedID, err := task.Utils.GenerateXRequestedID(task.SessionToken)
	if err != nil {
		return utils.SolveResult{}, fmt.Errorf("failed to generate xRequestedID")
	}

	headers := map[string]string{
		"X-NewRelic-Timestamp": task.Utils.NewRelicTime(),
		"Accept-Language":      task.AcceptLanguageHeader,
		"Referer":              task.GameCoreReferrer,
		"X-Requested-ID":       xRequestedID,
		"User-Agent":           task.UserAgent,
		"Content-Type":         "application/x-www-form-urlencoded; charset=UTF-8",
		"Accept-Encoding":      "deflate, br, zstd",
		"Accept":               "*/*",
		"Cache-Control":        "no-cache",
		"X-Requested-With":     "XMLHttpRequest",
		"Origin":               task.ApiURL,
		"Sec-Fetch-Site":       "same-origin",
		"Sec-Fetch-Mode":       "cors",
		"Sec-Fetch-Dest":       "empty",
		"Priority":             "u=1, i",
	}

	if task.DataBrandsHeader != nil {
		headers["sec-ch-ua"] = task.DataBrandsHeader.(string)
		headers["sec-ch-ua-mobile"] = task.IsMobileHeader.(string)
		headers["sec-ch-ua-platform"] = task.OsPlatform.(string)
	}

	// Create Request
	payload := strings.Join(data, "&")
	req, err := fhttp.NewRequest("POST", requestURL, strings.NewReader(payload))
	if err != nil {
		return utils.SolveResult{}, fmt.Errorf("failed to create new HTTP request: %w", err)
	}

	// Headers
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	// Send request
	resp, err := task.Client.Do(req)
	if err != nil {
		return utils.SolveResult{}, fmt.Errorf("proxy error: %v", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return utils.SolveResult{}, fmt.Errorf("failed to read answer response")
	}

	var solveData utils.SolveResult
	if err := json.Unmarshal(bodyBytes, &solveData); err != nil {
		return utils.SolveResult{}, fmt.Errorf("failed to parse response JSON into TaskData struct: %w", err)
	}

	return solveData, nil
}

// Extra
func FetchLatestVersion() {
	ticker := time.NewTicker(1 * time.Hour) // Run hourly
	defer ticker.Stop()

	for {
		// Check if an update is needed
		url := "https://snap-api.arkoselabs.com/v2/EA4B65CB-594A-438E-B4B5-D0DBA28C9334/api.js"

		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			log.Printf("Failed to create request: %s\n", err)
			<-ticker.C
			continue
		}

		// Headers map
		headers := map[string]string{
			"Origin":             "https://iframe.arkoselabs.com",
			"Sec-Ch-Ua-Platform": `"Windows"`,
			"User-Agent":         "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
			"Sec-Ch-Ua":          `"Chromium";v="130", "Google Chrome";v="130", "Not?A_Brand";v="99"`,
			"Sec-Ch-Ua-Mobile":   "?0",
			"Accept":             "*/*",
			"Sec-Fetch-Site":     "same-site",
			"Sec-Fetch-Mode":     "cors",
			"Sec-Fetch-Dest":     "script",
			"Referer":            "https://iframe.arkoselabs.com/",
			"Accept-Language":    "en-US,en;q=0.9",
		}

		// Set headers from map
		for key, value := range headers {
			req.Header.Set(key, value)
		}

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			log.Printf("Failed to send request: %s\n", err)
			<-ticker.C
			continue
		}

		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Printf("Failed to read response body: %s\n", err)
			<-ticker.C
			continue
		}
		resp.Body.Close()

		body := string(bodyBytes)

		versionPattern := regexp.MustCompile(`(\d+\.\d+\.\d+)/enforcement\.([a-f0-9]+)\.html`)
		matches := versionPattern.FindStringSubmatch(body)
		if len(matches) == 3 {
			capiVersion := matches[1]
			enforcementHash := matches[2]

			CapiVersion = capiVersion
			EnforcementHash = enforcementHash

		} else {
			log.Println("Failed to extract capiVersion and enforcementHash; skipping update.")
		}

		<-ticker.C // Wait for next tick
	}
}

func (task *FuncaptchaTask) FetchImage(imgURL string) ([]byte, error) {
	req, err := fhttp.NewRequest("GET", imgURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	headers := map[string]string{
		"Accept":                   "*/*",
		"Accept-Encoding":          "gzip, deflate, br, zstd",
		"Accept-Language":          task.AcceptLanguageHeader,
		"Priority":                 "u=1, i",
		"Referer":                  task.GameCoreReferrer,
		"Sec-Fetch-Dest":           "empty",
		"Sec-Fetch-Mode":           "cors",
		"Sec-Fetch-Site":           "same-origin",
		"Sec-Fetch-Storage-Access": "active",
		"User-Agent":               task.UserAgent,
	}

	if task.DataBrandsHeader != nil {
		headers["sec-ch-ua"] = task.DataBrandsHeader.(string)
		headers["sec-ch-ua-mobile"] = task.IsMobileHeader.(string)
		headers["sec-ch-ua-platform"] = task.OsPlatform.(string)
	}

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	resp, err := task.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch image: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch image, status code: %d", resp.StatusCode)
	}

	// Get Image
	imgContent, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read image content: %v", err)
	}

	return imgContent, nil
}

// func (task *FuncaptchaTask) SolveImage(base64Img string) (utils.AIResult, error) {
// 	for {
// 		// Pick available host
// 		host, err := PickAvailableHost()
// 		if err != nil {
// 			return utils.AIResult{}, fmt.Errorf("no available hosts: %s", err)
// 		}

// 		// Solve URL
// 		solveURL := fmt.Sprintf("%s/solve", host.Hostname)
// 		solvePayload := map[string]interface{}{
// 			"image":       base64Img,
// 			"game":        task.GameName,
// 			"instruction": task.GameInstruction,
// 			"game_type":   task.GameType,
// 		}
// 		payloadBytes, _ := json.Marshal(solvePayload)

// 		solveResp, err := http.Post(solveURL, "application/json", bytes.NewBuffer(payloadBytes))
// 		if err != nil {
// 			log.Printf("Host %s failed to respond, removing from available hosts: %v", host.Hostname, err)
// 			go PerformHealthCheck(host) // Trigger health check in a goroutine
// 			continue                    // Try next
// 		}
// 		defer solveResp.Body.Close()

// 		// Check if not 200
// 		if solveResp.StatusCode != http.StatusOK {
// 			log.Printf("AI bad response - Host: %s, Status Code: %d", host.Hostname, solveResp.StatusCode)
// 			go PerformHealthCheck(host) // Trigger health check in a goroutine
// 			continue
// 		}

// 		// Decode
// 		var predictResult utils.AIResult
// 		if err := json.NewDecoder(solveResp.Body).Decode(&predictResult); err != nil {
// 			return utils.AIResult{}, fmt.Errorf("failed to read image answer response - %s", err)
// 		}

// 		return predictResult, nil
// 	}
// }

// Main
func (task *FuncaptchaTask) Solve() error {
	defer handlePanic(task)

	// Generate Challenge Data
	challengeData, isBlobInvalid, err := task.FetchChallengeData()
	if err != nil {
		return fmt.Errorf("failed to generate challenge data - %s", err)
	} else if isBlobInvalid {
		return fmt.Errorf("invalid blob")
	}

	// Session Values
	task.FinalToken = challengeData.Token
	task.SessionToken = strings.Split(challengeData.Token, "|")[0]
	task.RContinent = strings.Split(strings.Split(challengeData.Token, "|r=")[1], "|")[0]

	if challengeData.ChallengeUrlCDN != "" { // Bootstrap Version
		version := versionPattern.FindString(challengeData.ChallengeUrlCDN)
		if version != "" {
			task.BoostrapVersion = version
		}
	}

	// Init request
	initResponse, err := task.Client.Get(fmt.Sprintf("%s/fc/gc/?token=%s", task.ApiURL, task.SessionToken)) // !
	if err != nil {
		return fmt.Errorf("failed to send init request - proxy error - %s", err)
	}

	if initResponse.StatusCode != 200 {
		return fmt.Errorf("bad init response code - %d", initResponse.StatusCode)
	}

	task.GameCoreReferrer = fmt.Sprintf(
		"%s/fc/assets/ec-game-core/game-core/%s/standard/index.html?session=%s&r=%s&meta=3&meta_width=300&metabgclr=transparent"+
			"&metaiconclr=#555555&guitextcolor=#000000&pk=%s&dc=1&at=40&ag=101&cdn_url=%s/cdn/fc"+
			"&lurl=https://audio-%s.arkoselabs.com&surl=%s&smurl=%s/cdn/fc/assets/style-manager&theme=default",
		task.ApiURL,
		task.BoostrapVersion,
		task.SessionToken,
		task.RContinent,
		task.SiteKey,
		task.ApiURL,
		task.RContinent,
		task.ApiURL,
		task.ApiURL,
	) // ? not fully accurate, but its only the UI flags - maybe ignore?

	// * CALLBACK - Enforcement.HTML
	callbackData := url.Values{
		"sid":                   {task.RContinent},
		"session_token":         {task.SessionToken},
		"analytics_tier":        {"40"},
		"disableCookies":        {"true"},
		"render_type":           {"canvas"},
		"is_compatibility_mode": {"false"},
		"category":              {"Site URL"},
		"action":                {task.EnforcementHtmlReferrer},
	}
	if err := task.Callback(callbackData); err != nil {
		return fmt.Errorf("callback error - %s", err)
	}

	// * CHECK IF SUPRESSED
	if strings.Contains(challengeData.Token, "sup=1|") {
		task.GameName = "Supressed"
		err = task.SubmitSupressed()
		if err != nil {
			return fmt.Errorf("failed to handle supressed token - %s", err)
		} else {
			return nil
		}
	}

	// * IMAGE SOLVING Start
	result, err := task.FetchTaskData()
	if err != nil {
		return fmt.Errorf("failed to fetch task data - %s", err)
	}

	// Parse Task Data
	task.GameID = result.ChallengeID
	gameData := result.GameData
	task.GameType = gameData.GameType
	task.Waves = gameData.Waves

	task.GameName = gameData.InstructionString
	if task.GameName == "" && gameData.GameVariant != "" {
		task.GameName = gameData.GameVariant
	} else if task.GameName == "" {
		return fmt.Errorf("no valid game data found")
	}

	instructionKey := fmt.Sprintf("%d.instructions-%s", gameData.GameType, task.GameName)
	task.GameInstruction = utils.StripHTML(result.StringTable[instructionKey])

	// * CALLBACK - Game Loaded
	callbackData1 := url.Values{
		"sid":                   {task.RContinent},
		"session_token":         {task.SessionToken},
		"analytics_tier":        {"40"},
		"disableCookies":        {"true"},
		"game_token":            {task.GameID},
		"game_type":             {"4"},
		"render_type":           {"canvas"},
		"is_compatibility_mode": {"false"},
		"category":              {"loaded"},
		"action":                {"game loaded"},
	}
	if err := task.Callback(callbackData1); err != nil {
		return fmt.Errorf("callback error - %s", err)
	}

	// * CALLBACK - User Clicked Verify
	cs := task.Utils.GenerateCS()
	g := task.Utils.GenerateG()
	callbackData2 := url.Values{
		"sid":                   {task.RContinent},
		"session_token":         {task.SessionToken},
		"analytics_tier":        {"40"},
		"disableCookies":        {"true"},
		"game_token":            {task.GameID},
		"game_type":             {"4"},
		"render_type":           {"canvas"},
		"is_compatibility_mode": {"false"},
		"category":              {"begin app"},
		"action":                {"user clicked verify"},
		"cs_":                   {cs},
		"ct_":                   {strconv.Itoa(rand.Intn(90) + 10)},
		"g_":                    {g},
		"h_":                    {task.Utils.GenerateH(cs, g)},
		"pt_":                   {fmt.Sprintf("%f", task.Utils.GeneratePT())},
		"aht_":                  {task.Utils.GenerateAHT()},
	}
	if err := task.Callback(callbackData2); err != nil {
		return fmt.Errorf("callback error - %s", err)
	}

	// Check waves amount
	if task.Waves >= 10 { // not worth solving
		return fmt.Errorf("too many waves %d", task.Waves)
	}

	// Fetch dapib code
	if result.DapibUrl != "" {
		task.DapibCode, err = task.FetchDapibCode(result.DapibUrl)
		if err != nil {
			return fmt.Errorf("failed to solve dapib")
		}
	}

	// Encrypted Mode
	if gameData.CustomGUI.EncryptedMode == 1 {
		err := task.FetchInitialDecryptKey()
		if err != nil {
			return fmt.Errorf("failed to decrypt encrypted image")
		}
	}

	// * IMAGE SOLVING
	answers := []string{}
	var solveResult utils.SolveResult

	for _, imgURL := range gameData.CustomGUI.ChallengeImgs {
		imgContent, err := task.FetchImage(imgURL)
		if err != nil {
			return fmt.Errorf("failed to get image - %s", err)
		}

		// Check if Encoded
		var base64Img string
		if gameData.CustomGUI.EncryptedMode == 1 {
			// Parse imgContent as JSON
			var imgJSON string
			err = json.Unmarshal(imgContent, &imgJSON)
			if err != nil {
				return fmt.Errorf("failed to parse encrypted image content as JSON - %s", err)
			}

			// Decrypt Image
			base64Img, err = task.Utils.DecryptImage(imgJSON, task.DecryptionKey)
			if err != nil {
				return fmt.Errorf("failed to decrypt image - %s", err)
			}
		} else {
			base64Img = base64.StdEncoding.EncodeToString(imgContent)
		}

		// ! ADD YOUR OWN SOLVER HERE
		// Get Image Answer
		// predictResult, err := task.SolveImage(base64Img)
		// if err != nil {
		// 	return fmt.Errorf("AI Failed to solve: %s", err)
		// }
		// index := predictResult.Result

		var index int
		xevilGames := []string{"numericalmatch", "icon_connect", "train_coordinates", "lumber_length", "3d_rollball_objects", "hopscotch_highsec", "hand_number_puzzle", "rockstack"}
		solveMyself := []string{}

		if contains(xevilGames, task.GameName) { // XEVIL
			index, err = SolveXEvil(base64Img, task.GameInstruction)
			if err != nil {
				return fmt.Errorf("failed to solve image - %s", err)
			}

		} else if contains(solveMyself, task.GameName) { // YOUR SOLVER HERE
			// predictResult, err := task.SolveImage(base64Img)
			// if err != nil {
			// 	return fmt.Errorf("AI Failed to solve: %s", err)
			// }
			index = 0
		} else {
			index, err = SolveXEvil(base64Img, task.GameInstruction)
			if err != nil {
				return fmt.Errorf("failed to solve image - %s", err)
			}
		}

		// Append index to answers
		if task.GameType == 4 {
			answers = append(answers, fmt.Sprintf(`{"index":%d}`, index))

		} else if task.GameType == 3 {
			answersMap := task.Utils.GridAnswerDict(index)
			jsonAnswer, err := json.Marshal(answersMap)
			if err != nil {
				return fmt.Errorf("failed to marshal grid answer dict gametype3 - %s", err)
			}

			// Add to answer list
			jsonAnswerString := strings.ReplaceAll(string(jsonAnswer), " ", "")
			answers = append(answers, jsonAnswerString)
		}

		// Encrypt result & submit
		formattedAnswers := fmt.Sprintf("[%s]", strings.Join(answers, ","))
		encryptedResult, err := task.Utils.EncryptDouble(task.SessionToken, formattedAnswers)
		if err != nil {
			return fmt.Errorf("error encrypting answer to image- %s", err)
		}
		solveResult, err = task.Answer(encryptedResult, answers, index)
		if err != nil {
			return fmt.Errorf("error submitting answer - %s", err)
		}

		if gameData.CustomGUI.EncryptedMode == 1 {
			task.DecryptionKey = solveResult.DecryptionKey
		}
	}

	// Check if solved
	if solveResult.Solved {
		return nil
	} else {
		return fmt.Errorf("image recognition failed / game not supported")
	}
}

// ===== HANDLE PANIC ======
func logErrorToFile(taskID string, message string) {
	file, err := os.OpenFile("error_log.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}
	defer file.Close()

	logger := log.New(file, "", log.LstdFlags)

	buf := make([]byte, 1024)
	n := runtime.Stack(buf, false)

	logger.Printf("Task ID: %s\nError: %s\nStack Trace: %s\n", taskID, message, string(buf[:n]))
}

// Panic handler function
func handlePanic(task *FuncaptchaTask) {
	if r := recover(); r != nil {
		logErrorToFile(task.ID, fmt.Sprintf("%v", r))

		// Update task status to "error"
		task.Status = "error"
		task.ErrorReason = "unexpected error"
	}
}

func contains(slice []string, item string) bool {
	for _, v := range slice {
		if v == item {
			return true
		}
	}
	return false
}
