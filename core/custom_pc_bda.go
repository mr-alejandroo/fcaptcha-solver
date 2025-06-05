package core

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	utils "funcaptchaapi/utils"
	"log"
	"math/rand"
	"strings"
	"time"

	"github.com/google/uuid"
)

func (task *FuncaptchaTask) GenerateBdaHardcodeDesktop(platform string) string {
	// Database Fingerprint
	randomIndex := rand.Intn(len(ChromeFingerprints))
	fingerprint := &ChromeFingerprints[randomIndex]

	// Get current time
	timeNow := time.Now().UnixNano() / int64(time.Millisecond)

	// Screen Resolutions
	// resolutions := [][]int{
	// 	{3440, 1440, 3440, 1400},
	// 	{1924, 1007, 1924, 1007},
	// 	{1920, 1080, 1920, 1040},
	// 	{1920, 1080, 1920, 1032},
	// 	{1920, 1080, 1920, 1050},
	// }

	// Current Resolution
	// resolution := resolutions[rand.Intn(len(resolutions))]
	// width := resolution[0]
	// height := resolution[1]
	// awidth := resolution[2]
	// aheight := resolution[3]

	cfp := "580753301"

	// Current AudioFP
	screenPixelDepth := 24

	var pixelRatio string
	var localStorage string
	var operatingSystem string
	var supportedTouchTypes string
	if !task.Preset.MobileKey { // WEB
		pixelRatio = "1"
		localStorage = "true"
		operatingSystem = "Win32"
		supportedTouchTypes = "0,false,false"
	} else {
		pixelRatio = "2.75"
		localStorage = "false"
		operatingSystem = "Linux aarch64"
		supportedTouchTypes = "5,true,true"
	}
	// Build fp1
	fp1 := []string{
		"DNT:unknown",
		fmt.Sprintf("L:%s", task.Locale),
		fmt.Sprintf("D:%d", screenPixelDepth),
		fmt.Sprintf("PR:%s", pixelRatio),
		"S:2560,1440",
		"AS:2560,1392",
		fmt.Sprintf("TO:%d", task.GetTimezoneOffset()),
		"SS:true",                             // - !!window.sessionStorage;
		fmt.Sprintf("LS:%s", localStorage),    // - !!window.localStorage;
		"IDB:true",                            // - !!window.indexedDB;
		"B:false",                             // - !!document.body && !!document.body.addBehavior
		"ODB:false",                           // - !!window.openDatabase
		"CPUC:unknown",                        // - navigator.cpuClass ? navigator.cpuClass : "unknown"
		fmt.Sprintf("PK:%s", operatingSystem), // - navigator.platform ? navigator.platform : "unknown")
		fmt.Sprintf("CFP:%s", cfp),            // - GPU Fingerprint
		"FR:false",                            //
		"FOS:false",                           //
		"FB:false",                            //
		"JSF:Arial,Arial Black,Arial Narrow,Calibri,Cambria,Cambria Math,Comic Sans MS,Consolas,Courier,Courier New,Georgia,Helvetica,Impact,Lucida Console,Lucida Sans Unicode,Microsoft Sans Serif,MS Gothic,MS PGothic,MS Sans Serif,MS Serif,Palatino Linotype,Segoe Print,Segoe Script,Segoe UI,Segoe UI Light,Segoe UI Semibold,Segoe UI Symbol,Tahoma,Times,Times New Roman,Trebuchet MS,Verdana,Wingdings", // Fonts
		"P:Chrome PDF Viewer,Chromium PDF Viewer,Microsoft Edge PDF Viewer,PDF Viewer,WebKit built-in PDF", // Extensions
		fmt.Sprintf("T:%s", supportedTouchTypes),
		"H:12",
		"SWF:false",
	}

	var webglD WebglDetails
	if useDatabaseFP {
		webglD = task.ConvertFingerprintToWebglEntry(*fingerprint)
	} else {
		webgl := Webgls[rand.Intn(len(Webgls))]
		webglD = webgl.Webgl[rand.Intn(len(webgl.Webgl))]
	}

	// Mobile / Web Differences
	var screenOrientation string
	var navigatorPermissionsHash interface{}
	var cssPointer string
	var browserObjectChecks interface{}
	var browserAPIChecks []string
	var isMobile bool
	var networkRTTType interface{}
	var NavigatorPdfEnabled bool
	screenOrientation = "landscape-primary"
	navigatorPermissionsHash = utils.Md5Hash("accelerometer|background-sync|camera|clipboard-read|clipboard-write|geolocation|gyroscope|magnetometer|microphone|midi|notifications|payment-handler|persistent-storage")
	cssPointer = "fine"
	browserObjectChecks = utils.Md5Hash("chrome")
	isMobile = false
	networkRTTType = nil
	NavigatorPdfEnabled = true
	browserAPIChecks = []string{
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

	webglD.WebglExtensions = "ANGLE_instanced_arrays;EXT_blend_minmax;EXT_clip_control;EXT_color_buffer_half_float;EXT_depth_clamp;EXT_disjoint_timer_query;EXT_float_blend;EXT_frag_depth;EXT_polygon_offset_clamp;EXT_shader_texture_lod;EXT_texture_compression_bptc;EXT_texture_compression_rgtc;EXT_texture_filter_anisotropic;EXT_texture_mirror_clamp_to_edge;EXT_sRGB;KHR_parallel_shader_compile;OES_element_index_uint;OES_fbo_render_mipmap;OES_standard_derivatives;OES_texture_float;OES_texture_float_linear;OES_texture_half_float;OES_texture_half_float_linear;OES_vertex_array_object;WEBGL_blend_func_extended;WEBGL_color_buffer_float;WEBGL_compressed_texture_s3tc;WEBGL_compressed_texture_s3tc_srgb;WEBGL_debug_renderer_info;WEBGL_debug_shaders;WEBGL_depth_texture;WEBGL_draw_buffers;WEBGL_lose_context;WEBGL_multi_draw;WEBGL_polygon_mode"
	webglD.WebglExtensionsHash = "7300c23f4e6fa34e534fc99c1b628588"
	webglD.WebglAliasedPointSizeRange = "[1, 1024]"
	webglD.WebglMaxViewportDims = "[32767, 32767]"
	webglD.WebglVsfParams = "23,127,127,23,127,127,23,127,127"
	webglD.WebglVsiParams = "0,31,30,0,31,30,0,31,30"
	webglD.WebglFsfParams = "23,127,127,23,127,127,23,127,127"
	webglD.WebglFsiParams = "0,31,30,0,31,30,0,31,30"
	webglD.WebglUnmaskedVendor = "Google Inc. (NVIDIA)"
	webglD.WebglMaxParams = "16,32,16384,1024,16384,16,16384,30,16,16,4095"
	webglD.WebglUnmaskedRenderer = "ANGLE (NVIDIA, NVIDIA GeForce RTX 3080 (0x0000220A) Direct3D11 vs_5_0 ps_5_0, D3D11)"

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

	// Process webgl data and compute hash
	webglHashInput := ProcessWebGL2(enhanced_fp)
	webglHash := task.Utils.X64Hash128GO(webglHashInput, 0)

	enhanced_fp = append(enhanced_fp, map[string]interface{}{
		"key":   "webgl_hash_webgl",
		"value": webglHash,
	})

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

	// Additional enhanced_fp data
	enhanced_fp_more := []map[string]interface{}{
		{"key": "user_agent_data_brands", "value": dataBrandsNoVersion},
		{"key": "user_agent_data_mobile", "value": isMobile},
		{"key": "navigator_connection_downlink", "value": 10},
		{"key": "navigator_connection_downlink_max", "value": nil},
		{"key": "network_info_rtt", "value": nil},
		{"key": "network_info_save_data", "value": false},
		{"key": "network_info_rtt_type", "value": networkRTTType},
		{"key": "screen_pixel_depth", "value": screenPixelDepth},
		{"key": "navigator_device_memory", "value": 8},
		{"key": "navigator_pdf_viewer_enabled", "value": NavigatorPdfEnabled},
		{"key": "navigator_languages", "value": "en-US,en"},
		{"key": "window_inner_width", "value": 0},
		{"key": "window_inner_height", "value": 0},
		{"key": "window_outer_width", "value": 2560},
		{"key": "window_outer_height", "value": 1392},
		{"key": "browser_detection_firefox", "value": false},
		{"key": "browser_detection_brave", "value": false},
		{"key": "browser_api_checks", "value": browserAPIChecks},
		{"key": "browser_object_checks", "value": browserObjectChecks},
		{"key": "29s83ih9", "value": utils.Md5Hash("false") + "\u2063"}, // unicode shit
		{"key": "audio_codecs", "value": "{\"ogg\":\"probably\",\"mp3\":\"probably\",\"wav\":\"probably\",\"m4a\":\"maybe\",\"aac\":\"probably\"}"},
		{"key": "audio_codecs_extended_hash", "value": utils.Md5Hash(`{"audio/mp4; codecs=\"mp4a.40\"":{"canPlay":"maybe","mediaSource":false},"audio/mp4; codecs=\"mp4a.40.1\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"mp4a.40.2\"":{"canPlay":"probably","mediaSource":true},"audio/mp4; codecs=\"mp4a.40.3\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"mp4a.40.4\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"mp4a.40.5\"":{"canPlay":"probably","mediaSource":true},"audio/mp4; codecs=\"mp4a.40.6\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"mp4a.40.7\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"mp4a.40.8\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"mp4a.40.9\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"mp4a.40.12\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"mp4a.40.13\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"mp4a.40.14\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"mp4a.40.15\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"mp4a.40.16\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"mp4a.40.17\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"mp4a.40.19\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"mp4a.40.20\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"mp4a.40.21\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"mp4a.40.22\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"mp4a.40.23\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"mp4a.40.24\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"mp4a.40.25\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"mp4a.40.26\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"mp4a.40.27\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"mp4a.40.28\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"mp4a.40.29\"":{"canPlay":"probably","mediaSource":true},"audio/mp4; codecs=\"mp4a.40.32\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"mp4a.40.33\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"mp4a.40.34\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"mp4a.40.35\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"mp4a.40.36\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"mp4a.66\"":{"canPlay":"probably","mediaSource":false},"audio/mp4; codecs=\"mp4a.67\"":{"canPlay":"probably","mediaSource":true},"audio/mp4; codecs=\"mp4a.68\"":{"canPlay":"probably","mediaSource":false},"audio/mp4; codecs=\"mp4a.69\"":{"canPlay":"probably","mediaSource":false},"audio/mp4; codecs=\"mp4a.6B\"":{"canPlay":"probably","mediaSource":false},"audio/mp4; codecs=\"mp3\"":{"canPlay":"probably","mediaSource":false},"audio/mp4; codecs=\"flac\"":{"canPlay":"probably","mediaSource":true},"audio/mp4; codecs=\"bogus\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"aac\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"ac3\"":{"canPlay":"","mediaSource":false},"audio/mp4; codecs=\"A52\"":{"canPlay":"","mediaSource":false},"audio/mpeg; codecs=\"mp3\"":{"canPlay":"probably","mediaSource":false},"audio/wav; codecs=\"0\"":{"canPlay":"","mediaSource":false},"audio/wav; codecs=\"2\"":{"canPlay":"","mediaSource":false},"audio/wave; codecs=\"0\"":{"canPlay":"","mediaSource":false},"audio/wave; codecs=\"1\"":{"canPlay":"","mediaSource":false},"audio/wave; codecs=\"2\"":{"canPlay":"","mediaSource":false},"audio/x-wav; codecs=\"0\"":{"canPlay":"","mediaSource":false},"audio/x-wav; codecs=\"1\"":{"canPlay":"probably","mediaSource":false},"audio/x-wav; codecs=\"2\"":{"canPlay":"","mediaSource":false},"audio/x-pn-wav; codecs=\"0\"":{"canPlay":"","mediaSource":false},"audio/x-pn-wav; codecs=\"1\"":{"canPlay":"","mediaSource":false},"audio/x-pn-wav; codecs=\"2\"":{"canPlay":"","mediaSource":false}}`)},
		{"key": "video_codecs", "value": "{\"ogg\":\"\",\"h264\":\"probably\",\"webm\":\"probably\",\"mpeg4v\":\"\",\"mpeg4a\":\"\",\"theora\":\"\"}"},
		{"key": "video_codecs_extended_hash", "value": utils.Md5Hash(`{"video/mp4; codecs=\"hev1.1.6.L93.90\"":{"canPlay":"probably","mediaSource":true},"video/mp4; codecs=\"hvc1.1.6.L93.90\"":{"canPlay":"probably","mediaSource":true},"video/mp4; codecs=\"hev1.1.6.L93.B0\"":{"canPlay":"probably","mediaSource":true},"video/mp4; codecs=\"hvc1.1.6.L93.B0\"":{"canPlay":"probably","mediaSource":true},"video/mp4; codecs=\"vp09.00.10.08\"":{"canPlay":"probably","mediaSource":true},"video/mp4; codecs=\"vp09.00.50.08\"":{"canPlay":"probably","mediaSource":true},"video/mp4; codecs=\"vp09.01.20.08.01\"":{"canPlay":"probably","mediaSource":true},"video/mp4; codecs=\"vp09.01.20.08.01.01.01.01.00\"":{"canPlay":"probably","mediaSource":true},"video/mp4; codecs=\"vp09.02.10.10.01.09.16.09.01\"":{"canPlay":"probably","mediaSource":true},"video/mp4; codecs=\"av01.0.08M.08\"":{"canPlay":"probably","mediaSource":true},"video/webm; codecs=\"vorbis\"":{"canPlay":"probably","mediaSource":true},"video/webm; codecs=\"vp8\"":{"canPlay":"probably","mediaSource":true},"video/webm; codecs=\"vp8.0\"":{"canPlay":"probably","mediaSource":false},"video/webm; codecs=\"vp8.0, vorbis\"":{"canPlay":"probably","mediaSource":false},"video/webm; codecs=\"vp8, opus\"":{"canPlay":"probably","mediaSource":true},"video/webm; codecs=\"vp9\"":{"canPlay":"probably","mediaSource":true},"video/webm; codecs=\"vp9, vorbis\"":{"canPlay":"probably","mediaSource":true},"video/webm; codecs=\"vp9, opus\"":{"canPlay":"probably","mediaSource":true},"video/x-matroska; codecs=\"theora\"":{"canPlay":"","mediaSource":false},"application/x-mpegURL; codecs=\"avc1.42E01E\"":{"canPlay":"","mediaSource":false},"video/ogg; codecs=\"dirac, vorbis\"":{"canPlay":"","mediaSource":false},"video/ogg; codecs=\"theora, speex\"":{"canPlay":"","mediaSource":false},"video/ogg; codecs=\"theora, vorbis\"":{"canPlay":"","mediaSource":false},"video/ogg; codecs=\"theora, flac\"":{"canPlay":"","mediaSource":false},"video/ogg; codecs=\"dirac, flac\"":{"canPlay":"","mediaSource":false},"video/ogg; codecs=\"flac\"":{"canPlay":"probably","mediaSource":false},"video/3gpp; codecs=\"mp4v.20.8, samr\"":{"canPlay":"","mediaSource":false}}`)},
		{"key": "media_query_dark_mode", "value": true},
		{"key": "css_media_queries", "value": 0},
		{"key": "css_color_gamut", "value": "srgb"},
		{"key": "css_contrast", "value": "no-preference"},
		{"key": "css_monochrome", "value": false},
		{"key": "css_pointer", "value": cssPointer},
		{"key": "css_grid_support", "value": false},
		{"key": "headless_browser_phantom", "value": false},
		{"key": "headless_browser_selenium", "value": false},
		{"key": "headless_browser_nightmare_js", "value": false},
		{"key": "headless_browser_generic", "value": 4},                   //  4 = normal chrome - unflagged
		{"key": "1l2l5234ar2", "value": fmt.Sprintf("%d\u2062", timeNow)}, // unicode shit
		{"key": "document__referrer", "value": documentRefferer},          // task.SiteUrl + "/"},
		{"key": "window__ancestor_origins", "value": task.WindowAncestorOriginsData},
		{"key": "window__tree_index", "value": task.WindowTreeIndexData},
		{"key": "window__tree_structure", "value": task.WindowTreeStructureData},
		{"key": "window__location_href", "value": task.EnforcementHtmlReferrer},
		{"key": "client_config__sitedata_location_href", "value": task.ClientConfigSitedataLocation},
		{"key": "client_config__language", "value": task.Preset.Data.ClientConfigLanguage},
		{"key": "client_config__surl", "value": task.ApiURL},
		{"key": "c8480e29a", "value": utils.Md5Hash(task.ApiURL) + "\u2062"}, // unicode shit
		{"key": "client_config__triggered_inline", "value": false},
		{"key": "mobile_sdk__is_sdk", "value": false},
		{"key": "audio_fingerprint", "value": "124.04347527516074"},
		{"key": "navigator_battery_charging", "value": true},
		{"key": "media_device_kinds", "value": nil},
		{"key": "media_devices_hash", "value": nil},
		{"key": "navigator_permissions_hash", "value": navigatorPermissionsHash},
		{"key": "math_fingerprint", "value": utils.Md5Hash("1.4474840516030247,0.881373587019543,1.1071487177940904,0.5493061443340548,1.4645918875615231,-0.40677759702517235,-0.6534063185820197,9.199870313877772e+307,1.718281828459045,100.01040630344929,0.4828823513147936,1.9275814160560204e-50,7.888609052210102e+269,1.2246467991473532e-16,-0.7181630308570678,11.548739357257748,9.199870313877772e+307,-3.3537128705376014,0.12238344189440875")},
		{"key": "supported_math_functions", "value": utils.Md5Hash("abs,acos,acosh,asin,asinh,atan,atanh,atan2,ceil,cbrt,expm1,clz32,cos,cosh,exp,floor,fround,hypot,imul,log,log1p,log2,log10,max,min,pow,random,round,sign,sin,sinh,sqrt,tan,tanh,trunc")},
		{"key": "screen_orientation", "value": screenOrientation},
		{"key": "rtc_peer_connection", "value": 5},
		{"key": "4b4b269e68", "value": uuid.New().String()},
		{"key": "6a62b2a558", "value": EnforcementHash},
		{"key": "speech_default_voice", "value": "Microsoft David - English (United States) || en-US"},
		{"key": "speech_voices_hash", "value": "b24bd471a2b801a80c0e3592b0c0c362"},
		{"key": "4ca87df3d1", "value": "NiwwLDY2Myw3NDc7NTY5LDAsMTI1Nyw0ODU7Njc5LDAsMTI1OSw0NzY7ODcwLDAsMTI1NCw0NzM7ODg3LDAsMTI0OSw0NzQ7ODk2LDAsMTI0NCw0NzU7OTAzLDAsMTIzOSw0NzY7OTEwLDAsMTIzMiw0Nzc7OTE0LDAsMTIyNSw0Nzk7OTE5LDAsMTIxNyw0ODA7OTIxLDAsMTIwNSw0ODI7OTI1LDAsMTE5Nyw0ODQ7OTI2LDAsMTE4MCw0ODc7OTMxLDAsMTE3MCw0ODk7OTMxLDAsMTE1OSw0OTA7OTMzLDAsMTE0Nyw0OTI7OTM1LDAsMTEzNCw0OTQ7OTM3LDAsMTEyMCw0OTc7OTQwLDAsMTEwNSw0OTk7OTQyLDAsMTA4OCw1MDE7OTQ0LDAsMTA3MSw1MDM7OTQ2LDAsMTA1Myw1MDY7OTQ3LDAsMTAzNCw1MDg7OTUxLDAsMTAxMyw1MTE7OTUyLDAsOTkyLDUxMzs5NTQsMCw5NjksNTE2Ozk1NiwwLDk0NSw1MTg7OTU4LDAsOTIxLDUyMTs5NjAsMCw4OTYsNTIzOzk2MiwwLDg3MCw1MjU7OTY0LDAsODQzLDUyNzs5NjcsMCw4MTcsNTI5Ozk2OSwwLDc4OSw1MzA7OTcxLDAsNzYxLDUzMTs5NzMsMCw3MzIsNTMyOzk3NSwwLDcwMyw1MzI7OTc3LDAsNjc0LDUzMjs5NzksMCw2NDQsNTMyOzk4MiwwLDU4NCw1MzE7OTg0LDAsNTUzLDUyOTs5ODYsMCw1MjIsNTI3Ozk4OCwwLDQ5MCw1MjU7OTkwLDAsNDU5LDUyMzs5OTMsMCw0MjcsNTIwOzk5NSwwLDM5Niw1MTc7OTk2LDAsMzY0LDUxNDs5OTksMCwzMzQsNTExOzEwMDAsMCwzMDQsNTA3OzEwMDIsMCwyNzYsNTAyOzEwMDYsMCwyNDgsNDk4OzEwMDYsMCwyMjEsNDk0OzEwMTQsMCwxNTAsNDgxOzEwMTgsMCwxMTEsNDczOzEwMjMsMCw2NCw0NjI7MTAyOSwwLDI3LDQ1MjsxMDM0LDAsNiw0NDc7MTczMSwwLDEwLDI5NTsxNzM1LDAsMzcsMzAxOzE3NDEsMCw3MiwzMDg7MTc0OCwwLDEzMywzMjI7MTc1NSwwLDE4OCwzMzY7MTc2MiwwLDI5MywzNjY7MTc2OSwwLDMzOCwzNzk7MTc3NiwwLDM4NCwzOTM7MTc4MywwLDQ1NCw0MTQ7MTc5MCwwLDYxMyw0NjI7MTc5NywwLDY3Niw0Nzk7MTgwNCwwLDc1NCw0OTc7MTgxMSwwLDgwOCw1MDg7MTgxOCwwLDg1OSw1MTc7MTgyNSwwLDkzMyw1Mjg7MTgzMiwwLDk0Niw1MzA7MTgzOSwwLDk5Miw1MzY7MTg0NiwwLDEwMzAsNTQxOzE4NTMsMCwxMDU0LDU0Mzs="},
		{"key": "867e25e5d4", "value": "Ow=="},
		{"key": "d4a306884c", "value": "MjQyNCwwLDE0OzI1NDgsMCwxNDsyNTYxLDEsMTQ7MjU2MiwwLDE0OzI2ODQsMCwxNDsyNzA3LDEsMTQ7MjcyMCwxLDE0OzI3NzksMSwxNDsyNzg3LDAsMTQ7MjgwMywwLDE0OzI4NjgsMCwxNDsyOTQxLDEsMTQ7Mjk0MSwxLDE0OzI5NTUsMSwxNDsyOTk2LDAsNTszMTI0LDAsMTQ7MzIxMSwxLDE0OzMyNzYsMSw1OzMzMzksMCwxNDszNDExLDAsMTQ7MzQyNywxLDE0OzM0NzYsMSwxNDszNzc5LDAsMTI7Mzg1MiwxLDEyOzM5MjUsMCwxNDszOTk1LDEsMTQ7NDA0NCwwLDE0OzQwOTksMCwxNDs0MTIzLDEsMTQ7NDE3MSwxLDE0OzQyNjcsMCwxNDs0MzM5LDEsMTQ7NDQyMCwwLDE0OzQ0OTEsMSwxNDs0NTIzLDAsMTQ7NDYwMywwLDE0OzQ2MTksMSwxNDs0NjU5LDAsMTQ7NDcxNiwxLDE0OzQ3NjQsMSwxNDs0ODAzLDAsMDs0OTIzLDEsMDs1MDUxLDAsMTQ7NTE1NiwwLDE0OzUxNzIsMSwxNDs1MTcyLDAsMTQ7NTI1OSwxLDE0OzUyNjgsMSwxNDs1Mjc1LDAsMTQ7NTM1NiwxLDE0OzUzODAsMCwxNDs1MzgxLDAsMTQ7NTQ1OSwxLDE0OzU0NzYsMSwxNDs1NDc2LDAsMTQ7NTU3MiwxLDE0OzU1NzIsMCwxNDs1NTc1LDAsMTQ7NTY1OSwwLDE0OzU2NjksMSwxNDs1NjcwLDEsMTQ7NTc0MCwxLDE0OzU4OTEsMCwxNDs2MDIwLDEsMTQ7"},
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

	// Process fp1 and compute hashes
	processedFp1 := task.Utils.ProcessFP(fp1)
	nValue := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%d", int(timeNow/1000))))

	// Build fp
	fp := []map[string]interface{}{
		{"key": "api_type", "value": "js"},
		{"key": "f", "value": task.Utils.X64Hash128GO(processedFp1, 0)}, // hash
		{"key": "n", "value": nValue},                                   // time
		{"key": "wh", "value": fmt.Sprintf("%s|72627afbfd19a741c7da1732218301ac", strings.ReplaceAll(uuid.New().String(), "-", ""))}, // uuid + static
		{"key": "enhanced_fp", "value": enhanced_fp},                                            // ? fingerprint
		{"key": "fe", "value": fp1},                                                             // ? fingerprint
		{"key": "ife_hash", "value": task.Utils.X64Hash128GO(strings.Join(fp1, ", "), 38)},      // hash
		{"key": "jsbd", "value": `{"HL":2,"NCE":true,"DT":"","NWD":"false","DMTO":1,"DOTO":1}`}, // ? fingerprint
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
