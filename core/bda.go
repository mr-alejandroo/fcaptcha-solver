package core

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	utils "funcaptchaapi/utils"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/tls-client/profiles"
	"github.com/google/uuid"
	"github.com/oschwald/geoip2-golang"
)

var useDatabaseFP = true

type WebglEntry struct {
	Webgl                 []WebglDetails `json:"webgl"`
	WebglUnmaskedRenderer string         `json:"webgl_unmasked_renderer"`
}

type WebglDetails struct {
	WebglExtensions             string `json:"webgl_extensions"`
	WebglExtensionsHash         string `json:"webgl_extensions_hash"`
	WebglRenderer               string `json:"webgl_renderer"`
	WebglVendor                 string `json:"webgl_vendor"`
	WebglVersion                string `json:"webgl_version"`
	WebglShadingLanguageVersion string `json:"webgl_shading_language_version"`
	WebglAliasedLineWidthRange  string `json:"webgl_aliased_line_width_range"`
	WebglAliasedPointSizeRange  string `json:"webgl_aliased_point_size_range"`
	WebglAntialiasing           bool   `json:"webgl_antialiasing"`
	WebglBits                   string `json:"webgl_bits"`
	WebglMaxParams              string `json:"webgl_max_params"`
	WebglMaxViewportDims        string `json:"webgl_max_viewport_dims"`
	WebglUnmaskedVendor         string `json:"webgl_unmasked_vendor"`
	WebglUnmaskedRenderer       string `json:"webgl_unmasked_renderer"`
	WebglVsfParams              string `json:"webgl_vsf_params"`
	WebglVsiParams              string `json:"webgl_vsi_params"`
	WebglFsfParams              string `json:"webgl_fsf_params"`
	WebglFsiParams              string `json:"webgl_fsi_params"`
}

var Webgls []WebglEntry
var GeoIPDatabase *geoip2.Reader

var ChromeFingerprints []utils.Fingerprint
var EdgeFingerprints []utils.Fingerprint
var FirefoxFingerprints []utils.Fingerprint
var IphoneFingerprints []utils.Fingerprint

func (task *FuncaptchaTask) ConvertFingerprintToWebglEntry(fingerprint utils.Fingerprint) WebglDetails {
	extensionsJoined := strings.Join(fingerprint.WebglExtensions, ";")

	extensionsHash := task.Utils.X64Hash128GO(extensionsJoined, 0)

	details := WebglDetails{
		WebglExtensions:             extensionsJoined,
		WebglExtensionsHash:         extensionsHash,
		WebglRenderer:               fingerprint.WebglRenderer,
		WebglVendor:                 fingerprint.WebglVendor,
		WebglVersion:                fingerprint.WebglVersion,
		WebglShadingLanguageVersion: fingerprint.WebglShadingLanguageVersion,
		WebglAliasedLineWidthRange:  fingerprint.WebglAliasedLineWidthRange,
		WebglAliasedPointSizeRange:  fingerprint.WebglAliasedPointSizeRange,
		WebglBits:                   fingerprint.WebglBits,
		WebglMaxParams:              fingerprint.WebglMaxParams,
		WebglMaxViewportDims:        fingerprint.WebglMaxViewportDims,
		WebglUnmaskedVendor:         fingerprint.WebglUnmaskedVendor,
		WebglUnmaskedRenderer:       fingerprint.WebglUnmaskedRenderer,
		WebglVsfParams:              fingerprint.WebglVsfParams,
		WebglVsiParams:              fingerprint.WebglVsiParams,
		WebglFsfParams:              fingerprint.WebglFsfParams,
		WebglFsiParams:              fingerprint.WebglFsiParams,
	}

	return details
}

// Format WebGL
func ProcessWebGL2(data []map[string]interface{}) string {
	var result []string

	for _, item := range data {
		if key, ok := item["key"]; ok {
			result = append(result, fmt.Sprintf("%v", key))
		}

		if value, ok := item["value"]; ok {
			result = append(result, fmt.Sprintf("%v", value))
		}
	}

	return strings.Join(result, ",") + ",webgl_hash_webgl,"
}

var Platforms = []string{"chrome", "edge", "iphone", "firefox"}

var PlatformData = map[string]map[string]interface{}{
	"tls": {
		"chrome":  profiles.Chrome_133,
		"edge":    profiles.Chrome_131,
		"iphone":  profiles.Safari_IOS_18_0,
		"firefox": profiles.Firefox_133,
	},
	"user_agent": {
		"chrome":  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
		"edge":    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
		"iphone":  "Mozilla/5.0 (iPhone; CPU iPhone OS 18_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Mobile/15E148 Safari/604.1",
		"firefox": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0",
	},
	"data_brands": {
		"chrome":  `"Not(A:Brand";v="99", "Google Chrome";v="133", "Chromium";v="133"`, //`"Not A(Brand";v="8", "Chromium";v="132", "Google Chrome";v="132"`,
		"edge":    `"Microsoft Edge";v="131", "Chromium";v="131", "Not_A Brand";v="24"`,
		"iphone":  nil,
		"firefox": nil,
	},
	"sec_ch_ua_mobile": {
		"chrome":  `?0`,
		"edge":    `?0`,
		"iphone":  nil,
		"firefox": nil,
	},
	"sec_ch_ua_platform": {
		"chrome":  `"Windows"`,
		"edge":    `"Windows"`,
		"iphone":  nil,
		"firefox": nil,
	},
	"screen_orientation": {
		"chrome":  `landscape-primary`,
		"edge":    `landscape-primary`,
		"iphone":  `portrait-primary`,
		"firefox": `landscape-primary`,
	},
	"navigator_permission_hash": {
		"chrome":  utils.Md5Hash("accelerometer|background-sync|camera|clipboard-read|clipboard-write|geolocation|gyroscope|magnetometer|microphone|midi|notifications|payment-handler|persistent-storage"),
		"edge":    utils.Md5Hash("accelerometer|background-sync|camera|clipboard-read|clipboard-write|geolocation|gyroscope|magnetometer|microphone|midi|notifications|payment-handler|persistent-storage"),
		"iphone":  "57e48421c8755c660127af661537d6b0",
		"firefox": `ff08c9a4035a62f27f41104aa682c277`,
	},
	"css_pointer": {
		"chrome":  `fine`,
		"edge":    `fine`,
		"iphone":  `coarse`,
		"firefox": `fine`,
	},
	"browser_object_checks": {
		"chrome":  utils.Md5Hash("chrome"),
		"edge":    utils.Md5Hash("chrome"),
		"iphone":  nil,
		"firefox": nil,
	},
	"is_mobile": {
		"chrome":  false,
		"edge":    false,
		"iphone":  nil,
		"firefox": nil,
	},
	"network_rtt_type": {
		"chrome":  nil,
		"edge":    nil,
		"iphone":  nil,
		"firefox": nil,
	},
	"navigator_pdf_enabled": {
		"chrome":  true,
		"edge":    true,
		"iphone":  true,
		"firefox": true,
	},
	"browser_checks": {
		"chrome":  DesktopAPIChecks,
		"edge":    DesktopAPIChecks,
		"iphone":  IphoneAPIChecks,
		"firefox": FirefoxAPIChecks,
	},
	"pixel_ratio": {
		"chrome":  "1",
		"edge":    "1",
		"iphone":  "3",
		"firefox": "1",
	},
	"local_storage": {
		"chrome":  "true",
		"edge":    "true",
		"iphone":  "true",
		"firefox": "true",
	},
	"operating_platform": {
		"chrome":  "Win32",
		"edge":    "Win32",
		"iphone":  "iPhone",
		"firefox": "Win32",
	},
	"supported_touch_types": {
		"chrome":  "0,false,false",
		"edge":    "0,false,false",
		"iphone":  "5,true,true",
		"firefox": "0,false,false",
	},
	"audio_codecs": {
		"chrome":  "{\"ogg\":\"probably\",\"mp3\":\"probably\",\"wav\":\"probably\",\"m4a\":\"maybe\",\"aac\":\"probably\"}",
		"edge":    "{\"ogg\":\"probably\",\"mp3\":\"probably\",\"wav\":\"probably\",\"m4a\":\"maybe\",\"aac\":\"probably\"}",
		"iphone":  `{"ogg":"","mp3":"maybe","wav":"probably","m4a":"maybe","aac":"maybe"}`,
		"firefox": "{\"ogg\":\"probably\",\"mp3\":\"maybe\",\"wav\":\"probably\",\"m4a\":\"maybe\",\"aac\":\"maybe\"}",
	},
	"audio_codecs_hash": {
		"chrome":  utils.Md5Hash(`{"audio/mp4; codecs=\"mp4a.40\"":{"canPlay":"maybe","mediaSource":false},"audio/mp4; codecs=\"mp4a.40.1\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"mp4a.40.2\"":{"canPlay":"probably","mediaSource":true},"audio/mp4; codecs=\"mp4a.40.3\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"mp4a.40.4\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"mp4a.40.5\"":{"canPlay":"probably","mediaSource":true},"audio/mp4; codecs=\"mp4a.40.6\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"mp4a.40.7\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"mp4a.40.8\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"mp4a.40.9\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"mp4a.40.12\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"mp4a.40.13\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"mp4a.40.14\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"mp4a.40.15\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"mp4a.40.16\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"mp4a.40.17\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"mp4a.40.19\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"mp4a.40.20\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"mp4a.40.21\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"mp4a.40.22\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"mp4a.40.23\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"mp4a.40.24\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"mp4a.40.25\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"mp4a.40.26\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"mp4a.40.27\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"mp4a.40.28\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"mp4a.40.29\"":{"canPlay":"probably","mediaSource":true},"audio/mp4; codecs=\"mp4a.40.32\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"mp4a.40.33\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"mp4a.40.34\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"mp4a.40.35\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"mp4a.40.36\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"mp4a.66\"":{"canPlay":"probably","mediaSource":false},"audio/mp4; codecs=\"mp4a.67\"":{"canPlay":"probably","mediaSource":true},"audio/mp4; codecs=\"mp4a.68\"":{"canPlay":"probably","mediaSource":false},"audio/mp4; codecs=\"mp4a.69\"":{"canPlay":"probably","mediaSource":false},"audio/mp4; codecs=\"mp4a.6B\"":{"canPlay":"probably","mediaSource":false},"audio/mp4; codecs=\"mp3\"":{"canPlay":"probably","mediaSource":false},"audio/mp4; codecs=\"flac\"":{"canPlay":"probably","mediaSource":true},"audio/mp4; codecs=\"bogus\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"aac\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"ac3\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"A52\"":{"canPlay":"","mediaSource":false},"audio/mpeg; codecs=\"mp3\"":{"canPlay":"probably","mediaSource":false},"audio/wav; codecs=\"0\"":{"canPlay":"","mediaSource":false},"audio/wav; codecs=\"2\"":{"canPlay":"","mediaSource":false},"audio/wave; codecs=\"0\"":{"canPlay":"","mediaSource":false},"audio/wave; codecs=\"1\"":{"canPlay":"","mediaSource":false},"audio/wave; codecs=\"2\"":{"canPlay":"","mediaSource":false},"audio/x-wav; codecs=\"0\"":{"canPlay":"","mediaSource":false},"audio/x-wav; codecs=\"1\"":{"canPlay":"probably","mediaSource":false},"audio/x-wav; codecs=\"2\"":{"canPlay":"","mediaSource":false},"audio/x-pn-wav; codecs=\"0\"":{"canPlay":"","mediaSource":false},"audio/x-pn-wav; codecs=\"1\"":{"canPlay":"","mediaSource":false},"audio/x-pn-wav; codecs=\"2\"":{"canPlay":"","mediaSource":false}}`),
		"edge":    utils.Md5Hash(`{"audio/mp4; codecs=\"mp4a.40\"":{"canPlay":"maybe","mediaSource":false},"audio/mp4; codecs=\"mp4a.40.1\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"mp4a.40.2\"":{"canPlay":"probably","mediaSource":true},"audio/mp4; codecs=\"mp4a.40.3\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"mp4a.40.4\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"mp4a.40.5\"":{"canPlay":"probably","mediaSource":true},"audio/mp4; codecs=\"mp4a.40.6\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"mp4a.40.7\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"mp4a.40.8\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"mp4a.40.9\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"mp4a.40.12\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"mp4a.40.13\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"mp4a.40.14\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"mp4a.40.15\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"mp4a.40.16\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"mp4a.40.17\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"mp4a.40.19\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"mp4a.40.20\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"mp4a.40.21\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"mp4a.40.22\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"mp4a.40.23\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"mp4a.40.24\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"mp4a.40.25\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"mp4a.40.26\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"mp4a.40.27\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"mp4a.40.28\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"mp4a.40.29\"":{"canPlay":"probably","mediaSource":true},"audio/mp4; codecs=\"mp4a.40.32\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"mp4a.40.33\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"mp4a.40.34\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"mp4a.40.35\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"mp4a.40.36\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"mp4a.66\"":{"canPlay":"probably","mediaSource":false},"audio/mp4; codecs=\"mp4a.67\"":{"canPlay":"probably","mediaSource":true},"audio/mp4; codecs=\"mp4a.68\"":{"canPlay":"probably","mediaSource":false},"audio/mp4; codecs=\"mp4a.69\"":{"canPlay":"probably","mediaSource":false},"audio/mp4; codecs=\"mp4a.6B\"":{"canPlay":"probably","mediaSource":false},"audio/mp4; codecs=\"mp3\"":{"canPlay":"probably","mediaSource":false},"audio/mp4; codecs=\"flac\"":{"canPlay":"probably","mediaSource":true},"audio/mp4; codecs=\"bogus\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"aac\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"ac3\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"A52\"":{"canPlay":"","mediaSource":false},"audio/mpeg; codecs=\"mp3\"":{"canPlay":"probably","mediaSource":false},"audio/wav; codecs=\"0\"":{"canPlay":"","mediaSource":false},"audio/wav; codecs=\"2\"":{"canPlay":"","mediaSource":false},"audio/wave; codecs=\"0\"":{"canPlay":"","mediaSource":false},"audio/wave; codecs=\"1\"":{"canPlay":"","mediaSource":false},"audio/wave; codecs=\"2\"":{"canPlay":"","mediaSource":false},"audio/x-wav; codecs=\"0\"":{"canPlay":"","mediaSource":false},"audio/x-wav; codecs=\"1\"":{"canPlay":"probably","mediaSource":false},"audio/x-wav; codecs=\"2\"":{"canPlay":"","mediaSource":false},"audio/x-pn-wav; codecs=\"0\"":{"canPlay":"","mediaSource":false},"audio/x-pn-wav; codecs=\"1\"":{"canPlay":"","mediaSource":false},"audio/x-pn-wav; codecs=\"2\"":{"canPlay":"","mediaSource":false}}`),
		"iphone":  `e59ea13c844d414ebfb7c926baad28da`,
		"firefox": "588ffca01a8bf2ec31455c3240121124",
	},
	"video_codecs": {
		"chrome":  "{\"ogg\":\"\",\"h264\":\"probably\",\"webm\":\"probably\",\"mpeg4v\":\"\",\"mpeg4a\":\"\",\"theora\":\"\"}",
		"edge":    "{\"ogg\":\"\",\"h264\":\"probably\",\"webm\":\"probably\",\"mpeg4v\":\"\",\"mpeg4a\":\"\",\"theora\":\"\"}",
		"iphone":  `{"ogg":"","h264":"probably","webm":"probably","mpeg4v":"probably","mpeg4a":"probably","theora":""}`,
		"firefox": "{\"ogg\":\"\",\"h264\":\"probably\",\"webm\":\"probably\",\"mpeg4v\":\"\",\"mpeg4a\":\"\",\"theora\":\"\"}",
	},
	"video_codecs_hash": {
		"chrome":  utils.Md5Hash(`{"video/mp4; codecs=\"hev1.1.6.L93.90\"":{"canPlay":"probably","mediaSource":true},"video/mp4; codecs=\"hvc1.1.6.L93.90\"":{"canPlay":"probably","mediaSource":true},"video/mp4; codecs=\"hev1.1.6.L93.B0\"":{"canPlay":"probably","mediaSource":true},"video/mp4; codecs=\"hvc1.1.6.L93.B0\"":{"canPlay":"probably","mediaSource":true},"video/mp4; codecs=\"vp09.00.10.08\"":{"canPlay":"probably","mediaSource":true},"video/mp4; codecs=\"vp09.00.50.08\"":{"canPlay":"probably","mediaSource":true},"video/mp4; codecs=\"vp09.01.20.08.01\"":{"canPlay":"probably","mediaSource":true},"video/mp4; codecs=\"vp09.01.20.08.01.01.01.01.00\"":{"canPlay":"probably","mediaSource":true},"video/mp4; codecs=\"vp09.02.10.10.01.09.16.09.01\"":{"canPlay":"probably","mediaSource":true},"video/mp4; codecs=\"av01.0.08M.08\"":{"canPlay":"probably","mediaSource":true},"video/webm; codecs=\"vorbis\"":{"canPlay":"probably","mediaSource":true},"video/webm; codecs=\"vp8\"":{"canPlay":"probably","mediaSource":true},"video/webm; codecs=\"vp8.0\"":{"canPlay":"probably","mediaSource":false},"video/webm; codecs=\"vp8.0, vorbis\"":{"canPlay":"probably","mediaSource":false},"video/webm; codecs=\"vp8, opus\"":{"canPlay":"probably","mediaSource":true},"video/webm; codecs=\"vp9\"":{"canPlay":"probably","mediaSource":true},"video/webm; codecs=\"vp9, vorbis\"":{"canPlay":"probably","mediaSource":true},"video/webm; codecs=\"vp9, opus\"":{"canPlay":"probably","mediaSource":true},"video/x-matroska; codecs=\"theora\"":{"canPlay":"","mediaSource":false},"application/x-mpegURL; codecs=\"avc1.42E01E\"":{"canPlay":"","mediaSource":false},"video/ogg; codecs=\"dirac, vorbis\"":{"canPlay":"","mediaSource":false},"video/ogg; codecs=\"theora, speex\"":{"canPlay":"","mediaSource":false},"video/ogg; codecs=\"theora, vorbis\"":{"canPlay":"","mediaSource":false},"video/ogg; codecs=\"theora, flac\"":{"canPlay":"","mediaSource":false},"video/ogg; codecs=\"dirac, flac\"":{"canPlay":"","mediaSource":false},"video/ogg; codecs=\"flac\"":{"canPlay":"probably","mediaSource":false},"video/3gpp; codecs=\"mp4v.20.8, samr\"":{"canPlay":"","mediaSource":false}}`),
		"edge":    utils.Md5Hash(`{"video/mp4; codecs=\"hev1.1.6.L93.90\"":{"canPlay":"probably","mediaSource":true},"video/mp4; codecs=\"hvc1.1.6.L93.90\"":{"canPlay":"probably","mediaSource":true},"video/mp4; codecs=\"hev1.1.6.L93.B0\"":{"canPlay":"probably","mediaSource":true},"video/mp4; codecs=\"hvc1.1.6.L93.B0\"":{"canPlay":"probably","mediaSource":true},"video/mp4; codecs=\"vp09.00.10.08\"":{"canPlay":"probably","mediaSource":true},"video/mp4; codecs=\"vp09.00.50.08\"":{"canPlay":"probably","mediaSource":true},"video/mp4; codecs=\"vp09.01.20.08.01\"":{"canPlay":"probably","mediaSource":true},"video/mp4; codecs=\"vp09.01.20.08.01.01.01.01.00\"":{"canPlay":"probably","mediaSource":true},"video/mp4; codecs=\"vp09.02.10.10.01.09.16.09.01\"":{"canPlay":"probably","mediaSource":true},"video/mp4; codecs=\"av01.0.08M.08\"":{"canPlay":"probably","mediaSource":true},"video/webm; codecs=\"vorbis\"":{"canPlay":"probably","mediaSource":true},"video/webm; codecs=\"vp8\"":{"canPlay":"probably","mediaSource":true},"video/webm; codecs=\"vp8.0\"":{"canPlay":"probably","mediaSource":false},"video/webm; codecs=\"vp8.0, vorbis\"":{"canPlay":"probably","mediaSource":false},"video/webm; codecs=\"vp8, opus\"":{"canPlay":"probably","mediaSource":true},"video/webm; codecs=\"vp9\"":{"canPlay":"probably","mediaSource":true},"video/webm; codecs=\"vp9, vorbis\"":{"canPlay":"probably","mediaSource":true},"video/webm; codecs=\"vp9, opus\"":{"canPlay":"probably","mediaSource":true},"video/x-matroska; codecs=\"theora\"":{"canPlay":"","mediaSource":false},"application/x-mpegURL; codecs=\"avc1.42E01E\"":{"canPlay":"","mediaSource":false},"video/ogg; codecs=\"dirac, vorbis\"":{"canPlay":"","mediaSource":false},"video/ogg; codecs=\"theora, speex\"":{"canPlay":"","mediaSource":false},"video/ogg; codecs=\"theora, vorbis\"":{"canPlay":"","mediaSource":false},"video/ogg; codecs=\"theora, flac\"":{"canPlay":"","mediaSource":false},"video/ogg; codecs=\"dirac, flac\"":{"canPlay":"","mediaSource":false},"video/ogg; codecs=\"flac\"":{"canPlay":"probably","mediaSource":false},"video/3gpp; codecs=\"mp4v.20.8, samr\"":{"canPlay":"","mediaSource":false}}`),
		"iphone":  `fb12160d5db2a92b7c6752a23d332c74`,
		"firefox": "79e55edb77b76413a783131b5af0e56b",
	},
	"css_color_gamut": {
		"chrome":  "srgb",
		"edge":    "srgb",
		"iphone":  `p3`,
		"firefox": "srgb",
	},
	"math_fingerprint": {
		"chrome":  "0ce80c69b75667d69baedc0a70c82da7",
		"edge":    utils.Md5Hash("1.4474840516030247,0.881373587019543,1.1071487177940904,0.5493061443340548,1.4645918875615231,-0.40677759702517235,-0.6534063185820197,9.199870313877772e+307,1.718281828459045,100.01040630344929,0.4828823513147936,1.9275814160560204e-50,7.888609052210102e+269,1.2246467991473532e-16,-0.7181630308570678,11.548739357257748,9.199870313877772e+307,-3.3537128705376014,0.12238344189440875"),
		"iphone":  `e4889aec3d9e3cdc6602c187bc80a578`,
		"firefox": "d1f0d718dc35469b254ef63603d70944",
	},
	"supported_math_functions": {
		"chrome":  utils.Md5Hash("abs,acos,acosh,asin,asinh,atan,atanh,atan2,ceil,cbrt,expm1,clz32,cos,cosh,exp,floor,fround,hypot,imul,log,log1p,log2,log10,max,min,pow,random,round,sign,sin,sinh,sqrt,tan,tanh,trunc"),
		"edge":    utils.Md5Hash("abs,acos,acosh,asin,asinh,atan,atanh,atan2,ceil,cbrt,expm1,clz32,cos,cosh,exp,floor,fround,hypot,imul,log,log1p,log2,log10,max,min,pow,random,round,sign,sin,sinh,sqrt,tan,tanh,trunc"),
		"iphone":  `cc04bb6a20778adde727893fb7507f9d`,
		"firefox": "f9f3630d1909c565ac99760b679d5be2",
	},
}

// navigator_pdf_enabled
var DesktopAPIChecks = []string{
	"permission_status: true",
	"eye_dropper: true",
	"audio_data: true",
	"writable_stream: true",
	"css_style_rule: true",
	"navigator_ua: true",
	"barcode_detector: false",
	"display_names: true",
	"contacts_manager: false",
	"svg_discard_element: false",
	"usb: defined",
	"media_device: defined",
	"playback_quality: true",
}

var FirefoxAPIChecks = []string{
	"permission_status: true",
	"eye_dropper: false",
	"audio_data: true",
	"writable_stream: true",
	"css_style_rule: true",
	"navigator_ua: false",
	"barcode_detector: false",
	"display_names: true",
	"contacts_manager: false",
	"svg_discard_element: false",
	"usb: NA",
	"media_device: defined",
	"playback_quality: true",
}

var IphoneAPIChecks = []string{
	"permission_status: true",
	"eye_dropper: false",
	"audio_data: false",
	"writable_stream: true",
	"css_style_rule: true",
	"navigator_ua: false",
	"barcode_detector: false",
	"display_names: true",
	"contacts_manager: false",
	"svg_discard_element: false",
	"usb: NA",
	"media_device: defined",
	"playback_quality: true",
}

func GetAllFingerprints(jsonPath string) ([]utils.Fingerprint, error) {
	file, err := os.Open(jsonPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	bytes, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	var fingerprints []utils.Fingerprint
	if err := json.Unmarshal(bytes, &fingerprints); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	return fingerprints, nil
}

func init() {
	// IP Database
	db, err := geoip2.Open("GeoLite2-City.mmdb")
	if err != nil {
		log.Fatal(err)
	}
	GeoIPDatabase = db

	// Fingerprints from DB
	ChromeFingerprints, err = GetAllFingerprints("./fps/chrome.json")
	if err != nil {
		log.Fatal(err)
	}

	// EDGE
	EdgeFingerprints, err = GetAllFingerprints("./fps/chrome.json")
	if err != nil {
		log.Fatal(err)
	}

	// FIREFOX
	FirefoxFingerprints, err = GetAllFingerprints("./fps/chrome.json")
	if err != nil {
		log.Fatal(err)
	}

	// IPHONE
	IphoneFingerprints, err = GetAllFingerprints("./fps/chrome.json")
	if err != nil {
		log.Fatal(err)
	}
}

func (task *FuncaptchaTask) GenerateBda(platform string) string {
	// Database Fingerprint
	var fingerprint *utils.Fingerprint
	if platform == "chrome" {
		randomIndex := rand.Intn(len(ChromeFingerprints))
		fingerprint = &ChromeFingerprints[randomIndex]
	} else if platform == "edge" {
		randomIndex := rand.Intn(len(EdgeFingerprints))
		fingerprint = &EdgeFingerprints[randomIndex]
	} else if platform == "iphone" {
		randomIndex := rand.Intn(len(IphoneFingerprints))
		fingerprint = &IphoneFingerprints[randomIndex]
	} else if platform == "firefox" {
		randomIndex := rand.Intn(len(FirefoxFingerprints))
		fingerprint = &FirefoxFingerprints[randomIndex]
	}

	// Current Time
	timeNow := time.Now().UnixNano() / int64(time.Millisecond)

	// Screen Resolutions
	resolutions := [][]int{
		{3440, 1440, 3440, 1400},
		{1924, 1007, 1924, 1007},
		{1920, 1080, 1920, 1040},
		{1920, 1080, 1920, 1032},
		{1920, 1080, 1920, 1050},
	}

	// Screen Resolution
	resolution := resolutions[rand.Intn(len(resolutions))]
	width := resolution[0]
	height := resolution[1]

	awidth := resolution[2]
	aheight := resolution[3]

	// Canvas Fingerprint
	var cfp string
	if useDatabaseFP {
		cfp = strconv.Itoa(fingerprint.CFP)
	} else {
		cfp = fallbackCanvas[rand.Intn(len(fallbackCanvas))]
	}

	// Audio Fingerprint
	audioFP := audioFps[rand.Intn(len(audioFps))]

	// Generate BS Values
	deviceMemoryOptions := []int{6, 8, 10}
	deviceMemory := deviceMemoryOptions[rand.Intn(len(deviceMemoryOptions))]

	screenPixelDepth := 24

	// Platform Differences
	isMobile := PlatformData["is_mobile"][platform]
	cssPointer := PlatformData["css_pointer"][platform].(string)
	navigatorPermissionsHash := PlatformData["navigator_permission_hash"][platform]
	screenOrientation := PlatformData["screen_orientation"][platform].(string)
	networkRTTType := PlatformData["network_rtt_type"][platform]
	NavigatorPdfEnabled := PlatformData["navigator_pdf_enabled"][platform].(bool)
	browserAPIChecks := PlatformData["browser_checks"][platform].([]string)

	audioCodecs := PlatformData["audio_codecs"][platform].(string)
	audioCodecsHash := PlatformData["audio_codecs_hash"][platform].(string)

	videoCodecs := PlatformData["video_codecs"][platform].(string)
	videoCodecsHash := PlatformData["video_codecs_hash"][platform].(string)

	cssColorGarmut := PlatformData["css_color_gamut"][platform].(string)

	mathFingerprint := PlatformData["math_fingerprint"][platform].(string)
	supportedMathFunctions := PlatformData["supported_math_functions"][platform].(string)
	pixelRatio := PlatformData["pixel_ratio"][platform].(string)
	localStorage := PlatformData["local_storage"][platform].(string)
	operatingPlatform := PlatformData["operating_platform"][platform].(string)
	supportedTouchTypes := PlatformData["supported_touch_types"][platform].(string)
	browserObjectChecks := PlatformData["browser_object_checks"][platform]

	// Fonts
	var jsfFonts string
	if platform == "iphone" {
		jsfFonts = "Arial,Arial Hebrew,Arial Rounded MT Bold,Courier,Courier New,Georgia,Helvetica,Helvetica Neue,Impact,LUCIDA GRANDE,Monaco,Palatino,Times,Times New Roman,Trebuchet MS,Verdana"
	} else if task.Preset.Name == "outlook_register" {
		jsfFonts = "Arial,Arial Black,Arial Narrow,Book Antiqua,Bookman Old Style,Calibri,Cambria,Cambria Math,Century,Comic Sans MS,Consolas,Courier,Courier New,Georgia,Helvetica,Impact,Lucida Console,Lucida Sans Unicode,Microsoft Sans Serif,MS Gothic,MS Outlook,MS PGothic,MS Reference Sans Serif,MS Sans Serif,MS Serif,Palatino Linotype,Segoe Print,Segoe Script,Segoe UI,Segoe UI Light,Segoe UI Semibold,Segoe UI Symbol,Tahoma,Times,Times New Roman,Trebuchet MS,Verdana,Wingdings,Wingdings 2,Wingdings 3"
	} else if platform == "firefox" {
		jsfFonts = "Arial,Arial Black,Calibri,Cambria,Cambria Math,Comic Sans MS,Consolas,Courier,Courier New,Georgia,Helvetica,Impact,Lucida Console,Lucida Sans Unicode,Microsoft Sans Serif,MS Gothic,MS PGothic,MS Sans Serif,MS Serif,Palatino Linotype,Segoe Print,Segoe Script,Segoe UI,Segoe UI Light,Segoe UI Symbol,Tahoma,Times,Times New Roman,Trebuchet MS,Verdana,Wingdings"
	} else {
		jsfFonts = "Arial,Arial Black,Arial Narrow,Calibri,Cambria,Cambria Math,Comic Sans MS,Consolas,Courier,Courier New,Georgia,Helvetica,Impact,Lucida Console,Lucida Sans Unicode,Microsoft Sans Serif,MS Gothic,MS PGothic,MS Sans Serif,MS Serif,Palatino Linotype,Segoe Print,Segoe Script,Segoe UI,Segoe UI Light,Segoe UI Semibold,Segoe UI Symbol,Tahoma,Times,Times New Roman,Trebuchet MS,Verdana,Wingdings"
	}

	var cssMediaQueries int
	var navigatorConnectionDownlink interface{}
	var mediaDevices []string
	var mediaDeviceHash interface{}
	var navigatorBatteryCharging interface{}
	var networkInfoRTT interface{}
	var networkInfoSaveData interface{}
	var navigatorDeviceMemory interface{}
	var rtcPeerConnections int
	var navigatorLanguages string
	var speechVoice interface{}
	var windowOuterWidth int
	var windowOuterHeight int
	var isFirefox bool
	var dnt = "unknown"
	var speechVoiceHash string
	if platform == "iphone" {
		navigatorConnectionDownlink = nil
		networkInfoRTT = nil
		networkInfoSaveData = nil
		navigatorDeviceMemory = nil
		width = 844
		awidth = 844

		height = 390
		aheight = 390

		windowOuterWidth = height
		windowOuterHeight = width

		cssMediaQueries = 1
		audioFP = "124.04346622781304"
		navigatorBatteryCharging = nil
		mediaDevices = []string{}
		mediaDeviceHash = "d751713988987e9331980363e24189ce"
		rtcPeerConnections = 1
		deviceMemory = 4

		navigatorLanguages = task.Locale

		speechVoice = "Tünde || hu-HU"
	} else {
		rtcPeerConnections = 5
		navigatorDeviceMemory = deviceMemory
		networkInfoRTT = nil
		networkInfoSaveData = false
		navigatorBatteryCharging = true
		navigatorConnectionDownlink = 10

		windowOuterWidth = width
		windowOuterHeight = height
		cssMediaQueries = 0

		mediaDevices = []string{"audioinput", "videoinput", "audiooutput"}
		mediaDeviceHash = "199eba60310b53c200cc783906883c67"

		navigatorLanguages = task.Locale + ",en"

		speechVoice = "Microsoft David - English (United States) || en-US"
		speechVoiceHash = "b24bd471a2b801a80c0e3592b0c0c362"
	}

	if platform == "firefox" {
		rtcPeerConnections = 1
		dnt = "unspecified"

		navigatorDeviceMemory = nil
		networkInfoSaveData = nil
		networkRTTType = nil
		networkInfoRTT = nil

		speechVoice = nil
		navigatorBatteryCharging = nil
		mediaDevices = nil
		mediaDeviceHash = nil
		isFirefox = true

		navigatorConnectionDownlink = nil
		task.WindowAncestorOriginsData = nil
		speechVoice = nil
		speechVoiceHash = "41ef43a7ff4f91debda50670676b7b98"

	}

	// Build fp1
	fp1 := []string{
		fmt.Sprintf("DNT:%s", dnt),
		fmt.Sprintf("L:%s", task.Locale),
		fmt.Sprintf("D:%d", screenPixelDepth),
		fmt.Sprintf("PR:%s", pixelRatio),
		fmt.Sprintf("S:%d,%d", width, height),
		fmt.Sprintf("AS:%d,%d", awidth, aheight),
		fmt.Sprintf("TO:%d", task.GetTimezoneOffset()),
		"SS:true",                               // - !!window.sessionStorage;
		fmt.Sprintf("LS:%s", localStorage),      // - !!window.localStorage;
		"IDB:true",                              // - !!window.indexedDB;
		"B:false",                               // - !!document.body && !!document.body.addBehavior
		"ODB:false",                             // - !!window.openDatabase
		"CPUC:unknown",                          // - navigator.cpuClass ? navigator.cpuClass : "unknown"
		fmt.Sprintf("PK:%s", operatingPlatform), // - navigator.platform ? navigator.platform : "unknown")
		fmt.Sprintf("CFP:%s", cfp),              // - GPU Fingerprint
		"FR:false",                              //
		"FOS:false",                             //
		"FB:false",                              //
		fmt.Sprintf("JSF:%s", jsfFonts),         // Fonts
		"P:Chrome PDF Viewer,Chromium PDF Viewer,Microsoft Edge PDF Viewer,PDF Viewer,WebKit built-in PDF", // Extensions
		fmt.Sprintf("T:%s", supportedTouchTypes),
		fmt.Sprintf("H:%d", deviceMemory),
		"SWF:false",
	}

	var webglD WebglDetails
	if useDatabaseFP {
		webglD = task.ConvertFingerprintToWebglEntry(*fingerprint)
	} else {
		webgl := Webgls[rand.Intn(len(Webgls))]
		webglD = webgl.Webgl[rand.Intn(len(webgl.Webgl))]
	}

	// WebGL Data
	// fmt.Println(webglD.WebglUnmaskedVendor)
	// fmt.Println(webglD.WebglUnmaskedRenderer)
	// fmt.Println(fingerprint.CFP)

	if platform == "iphone" {
		webglD.WebglExtensions = "ANGLE_instanced_arrays;EXT_blend_minmax;EXT_clip_control;EXT_color_buffer_half_float;EXT_depth_clamp;EXT_frag_depth;EXT_polygon_offset_clamp;EXT_shader_texture_lod;EXT_texture_filter_anisotropic;EXT_texture_mirror_clamp_to_edge;EXT_sRGB;KHR_parallel_shader_compile;OES_element_index_uint;OES_fbo_render_mipmap;OES_standard_derivatives;OES_texture_float;OES_texture_half_float;OES_texture_half_float_linear;OES_vertex_array_object;WEBGL_blend_func_extended;WEBGL_color_buffer_float;WEBGL_compressed_texture_astc;WEBGL_compressed_texture_etc;WEBGL_compressed_texture_etc1;WEBGL_compressed_texture_pvrtc;WEBKIT_WEBGL_compressed_texture_pvrtc;WEBGL_debug_renderer_info;WEBGL_debug_shaders;WEBGL_depth_texture;WEBGL_draw_buffers;WEBGL_lose_context;WEBGL_multi_draw;WEBGL_polygon_mode"
		webglD.WebglExtensionsHash = "b9305a4cc5ac1ccff2c39ed3c518c526"
	}

	enhanced_fp := []map[string]interface{}{
		{"key": "webgl_extensions", "value": webglD.WebglExtensions},
		{"key": "webgl_extensions_hash", "value": webglD.WebglExtensionsHash},
		{"key": "webgl_renderer", "value": webglD.WebglRenderer},
		{"key": "webgl_vendor", "value": webglD.WebglVendor},
		{"key": "webgl_version", "value": webglD.WebglVersion},
		{"key": "webgl_shading_language_version", "value": webglD.WebglShadingLanguageVersion},
		{"key": "webgl_aliased_line_width_range", "value": webglD.WebglAliasedLineWidthRange},
		{"key": "webgl_aliased_point_size_range", "value": webglD.WebglAliasedPointSizeRange},
		{"key": "webgl_antialiasing", "value": "yes"},
		{"key": "webgl_bits", "value": webglD.WebglBits},
		{"key": "webgl_max_params", "value": webglD.WebglMaxParams},
		{"key": "webgl_max_viewport_dims", "value": webglD.WebglMaxViewportDims},
		{"key": "webgl_unmasked_vendor", "value": webglD.WebglUnmaskedVendor},
		{"key": "webgl_unmasked_renderer", "value": webglD.WebglUnmaskedRenderer},
		{"key": "webgl_vsf_params", "value": webglD.WebglVsfParams},
		{"key": "webgl_vsi_params", "value": webglD.WebglVsiParams},
		{"key": "webgl_fsf_params", "value": webglD.WebglFsfParams},
		{"key": "webgl_fsi_params", "value": webglD.WebglFsiParams},
	}

	// WebGL Hash
	webglHashInput := ProcessWebGL2(enhanced_fp)
	webglHash := task.Utils.X64Hash128GO(webglHashInput, 0)

	enhanced_fp = append(enhanced_fp, map[string]interface{}{
		"key":   "webgl_hash_webgl",
		"value": webglHash,
	})

	// Form data
	var documentRefferer string
	documentRefferer = task.SiteUrl + "/"
	if task.Preset.Data.EmptyDocumentReferrer {
		documentRefferer = ""
	}

	// Data Brands
	var dataBrandsNoVersion interface{}

	if task.DataBrandsHeader != nil {
		dataBrandsNoVersion = strings.Join(func(matches [][]string) []string {
			brands := make([]string, len(matches))
			for i, match := range matches {
				brands[i] = match[1]
			}
			return brands
		}(dataBrandsPattern.FindAllStringSubmatch(task.DataBrandsHeader.(string), -1)), ",")
	}

	// Enhanced_FP
	enhanced_fp_more := []map[string]interface{}{
		{"key": "user_agent_data_brands", "value": dataBrandsNoVersion},
		{"key": "user_agent_data_mobile", "value": isMobile},
		{"key": "navigator_connection_downlink", "value": navigatorConnectionDownlink},
		{"key": "navigator_connection_downlink_max", "value": nil},
		{"key": "network_info_rtt", "value": networkInfoRTT},
		{"key": "network_info_save_data", "value": networkInfoSaveData},
		{"key": "network_info_rtt_type", "value": networkRTTType},
		{"key": "screen_pixel_depth", "value": screenPixelDepth},
		{"key": "navigator_device_memory", "value": navigatorDeviceMemory},
		{"key": "navigator_pdf_viewer_enabled", "value": NavigatorPdfEnabled},
		{"key": "navigator_languages", "value": navigatorLanguages},
		{"key": "window_inner_width", "value": 0},
		{"key": "window_inner_height", "value": 0},
		{"key": "window_outer_width", "value": windowOuterWidth},
		{"key": "window_outer_height", "value": windowOuterHeight},
		{"key": "browser_detection_firefox", "value": isFirefox},
		{"key": "browser_detection_brave", "value": false},
		{"key": "browser_api_checks", "value": browserAPIChecks},
		{"key": "browser_object_checks", "value": browserObjectChecks},
		{"key": "29s83ih9", "value": utils.Md5Hash("false") + "\u2063"},
		{"key": "audio_codecs", "value": audioCodecs},
		{"key": "audio_codecs_extended_hash", "value": audioCodecsHash},
		{"key": "video_codecs", "value": videoCodecs},
		{"key": "video_codecs_extended_hash", "value": videoCodecsHash},
		{"key": "media_query_dark_mode", "value": false},
		{"key": "css_media_queries", "value": cssMediaQueries},
		{"key": "css_color_gamut", "value": cssColorGarmut},
		{"key": "css_contrast", "value": "no-preference"},
		{"key": "css_monochrome", "value": false},
		{"key": "css_pointer", "value": cssPointer},
		{"key": "css_grid_support", "value": false},
		{"key": "headless_browser_phantom", "value": false},
		{"key": "headless_browser_selenium", "value": false},
		{"key": "headless_browser_nightmare_js", "value": false},
		{"key": "headless_browser_generic", "value": 4}, //  4 = normal chrome - unflagged
		{"key": "1l2l5234ar2", "value": fmt.Sprintf("%d\u2063", timeNow)},
		{"key": "document__referrer", "value": documentRefferer},
		{"key": "window__ancestor_origins", "value": task.WindowAncestorOriginsData},
		{"key": "window__tree_index", "value": task.WindowTreeIndexData},
		{"key": "window__tree_structure", "value": task.WindowTreeStructureData},
		{"key": "window__location_href", "value": task.EnforcementHtmlReferrer},
		{"key": "client_config__sitedata_location_href", "value": task.ClientConfigSitedataLocation},
		{"key": "client_config__language", "value": task.Preset.Data.ClientConfigLanguage},
		{"key": "client_config__surl", "value": task.ApiURL},
		{"key": "c8480e29a", "value": utils.Md5Hash(task.ApiURL) + "\u2062"},
		{"key": "client_config__triggered_inline", "value": task.Preset.Data.ClientConfigTriggeredInline},
		{"key": "mobile_sdk__is_sdk", "value": false},
		{"key": "audio_fingerprint", "value": audioFP},
		{"key": "navigator_battery_charging", "value": navigatorBatteryCharging},
		{"key": "media_device_kinds", "value": mediaDevices},
		{"key": "media_devices_hash", "value": mediaDeviceHash},
		{"key": "navigator_permissions_hash", "value": navigatorPermissionsHash},
		{"key": "math_fingerprint", "value": mathFingerprint},
		{"key": "supported_math_functions", "value": supportedMathFunctions},
		{"key": "screen_orientation", "value": screenOrientation},
		{"key": "rtc_peer_connection", "value": rtcPeerConnections},
		{"key": "4b4b269e68", "value": uuid.New().String()},
		{"key": "6a62b2a558", "value": EnforcementHash},
		{"key": "speech_default_voice", "value": speechVoice},
		{"key": "speech_voices_hash", "value": speechVoiceHash},
		{"key": "4ca87df3d1", "value": "Ow=="},
		{"key": "867e25e5d4", "value": "Ow=="},
		{"key": "d4a306884c", "value": "Ow=="},
	}

	// Append enhanced_fp_more to enhanced_fp
	for _, item := range enhanced_fp_more {
		key, keyOk := item["key"].(string)
		value, valueOk := item["value"]

		if keyOk && valueOk {
			enhanced_fp = append(enhanced_fp, map[string]interface{}{
				"key":   key,
				"value": value,
			})
		} else {
			// Something bad
			fmt.Printf("Warning: item %+v is missing a valid key or value\n", item)
		}
	}

	// Get fp1 hash
	processedFp1 := task.Utils.ProcessFP(fp1)

	nValue := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%d", int(timeNow/1000))))

	// JSBD
	jsbdValue := buildJSBDValue(task.Platform)

	var constantBSValue string
	if platform == "iphone" {
		constantBSValue = "1d99c2530fa1a96e676f9b1a1a9bcb58"
	} else if platform == "firefox" {
		constantBSValue = "5ab5738955e0611421b686bc95655ad0"
	} else {
		constantBSValue = "72627afbfd19a741c7da1732218301ac"
	}

	// Build fp
	fp := []map[string]interface{}{
		{"key": "api_type", "value": "js"},
		{"key": "f", "value": task.Utils.X64Hash128GO(processedFp1, 0)}, // hash
		{"key": "n", "value": nValue},                                   // time
		{"key": "wh", "value": fmt.Sprintf("%s|%s", strings.ReplaceAll(uuid.New().String(), "-", ""), constantBSValue)}, // uuid + static
		{"key": "enhanced_fp", "value": enhanced_fp},                                       // ? fingerprint
		{"key": "fe", "value": fp1},                                                        // ? fingerprint
		{"key": "ife_hash", "value": task.Utils.X64Hash128GO(strings.Join(fp1, ", "), 38)}, // hash
		{"key": "jsbd", "value": jsbdValue},                                                // ? fingerprint
	}

	// Serialize fp to JSON
	fpJsonBytes, err := json.Marshal(fp)
	if err != nil {
		log.Fatalf("Failed to marshal fp: %v", err)
	}

	// Encrypt
	encryptedDict, err := task.Utils.MakeEncryptedDict(string(fpJsonBytes), task.UserAgent, task.XArkValue)
	if err != nil {
		log.Fatalf("Failed to make encrypted dict: %v", err)
	}

	// Base64
	return base64.StdEncoding.EncodeToString([]byte(encryptedDict))
}

// JSBD
func buildJSBDValue(platform string) string {
	var nce bool
	if platform == "iphone" {
		nce = false
	} else {
		nce = true
	}
	jsbd := []struct {
		Key   string
		Value interface{}
	}{
		{"HL", rand.Intn(20) + 1}, // window.history.length
		{"NCE", nce},              // navigator.cookieEnabled
		{"DT", ""},                // document.title
		{"NWD", "false"},          // JSON.stringify(navigator.webdriver)
		{"DMTO", 1},               // hardcoded
		{"DOTO", 1},               // hardcoded
	}

	var jsbdResult []string
	for _, item := range jsbd {
		// Format each item as a key-value JSON pair
		jsbdResult = append(jsbdResult, fmt.Sprintf(`"%s":%v`, item.Key, formatValue(item.Value)))
	}

	return "{" + strings.Join(jsbdResult, ",") + "}"
}

func formatValue(v interface{}) string {
	switch v := v.(type) {
	case string:
		return fmt.Sprintf(`"%s"`, v)
	case bool:
		return fmt.Sprintf(`%t`, v)
	default:
		return fmt.Sprintf(`%v`, v)
	}
}

// Proxy Timezone
type IPInfoResponse struct {
	TimeZone struct {
		Name string `json:"name"`
	} `json:"time_zone"`
}

func (task *FuncaptchaTask) GetTimezoneOffset() int {
	url := "https://ipinfo.io/ip"

	req, err := fhttp.NewRequest("GET", url, nil)
	if err != nil {
		return getFallbackOffset()
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "application/json")

	resp, err := task.Client.Do(req)
	if err != nil {
		return getFallbackOffset()
	}
	defer resp.Body.Close()

	// Read IP from body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return getFallbackOffset()
	}
	ipStr := string(body)

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return getFallbackOffset()
	}

	// Lookup info from MaxMind
	record, err := GeoIPDatabase.City(ip)
	if err != nil || record.Location.TimeZone == "" {
		return getFallbackOffset()
	}

	// Load timezone and calculate offset
	location, err := time.LoadLocation(record.Location.TimeZone)
	if err != nil {
		return getFallbackOffset()
	}

	now := time.Now().In(location)
	_, offsetSeconds := now.Zone()
	offsetMinutes := offsetSeconds / 60

	return -offsetMinutes
}

func getFallbackOffset() int {
	fallbackOffsets := []int{-120, -140, -160}
	return fallbackOffsets[rand.Intn(len(fallbackOffsets))]
}

// Audio
var audioFps = []string{
	"124.08072766105033", "124.04651710136386", "124.0807279153014", "124.04344968475198",
	"124.08072784824617", "124.0396717004187", "35.73832903057337", "124.0807277960921",
	"124.08075528279005", "124.08072790785081", "124.08072256811283", "124.04345259929687",
	"124.0434496849557", "124.0434806260746", "124.08072782589443", "64.39679384598276",
	"124.0434485301812", "124.04423786447296", "124.04453790388652", "124.08072786314733",
	"124.04569787243236", "124.08072787804849", "124.04211016517365", "124.08072793765314",
	"124.03962087413674", "124.04457049137272", "124.04344884395687", "35.73833402246237",
	"124.0434474653739", "124.04855314017914", "124.04347524535842", "35.10893232002854",
	"124.08072787802666", "124.04048140646773", "28.601430902344873", "35.749968223273754",
	"35.74996031448245", "124.0434752900619", "124.04347657808103", "124.04215029208717",
	"124.08072781844385", "124.04369539513573", "124.04384341745754", "124.04557180271513",
	"35.74996626004577", "124.0807470110085", "124.04066697827511", "124.08072783334501",
	"124.40494026464876", "124.0434488439787", "35.7383295930922", "124.03549310178641",
	"124.04304748237337", "124.08075643483608", "124.0437401577874", "124.05001448364783",
	"124.08072795627959", "124.04345808873768", "124.04051324382453", "124.04347527516074",
	"124.08072796745546", "124.0431715620507", "54.70348421488234",
}

// Canvases
var fallbackCanvas = []string{
	"-1946591325",
	"1815906631",
	"235298495",
	"1850036655",
	"-1661048561",
	"823022740",
	"-1712985017",
	"679642534",
	"512287303",
	"-1570039461",
	"11949726",
	"512287303",
	"-479006826",
	"-1124974951",
	"1999955435",
	"213013447",
	"-1058930346",
	"-1291191045",
	"-1338001587",
	"-1946591325",
	"-70526813",
	"-72944365",
	"1456333650",
	"1732442814",
	"631151448",
}
