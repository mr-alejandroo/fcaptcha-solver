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

func (task *FuncaptchaTask) GenerateBdaHardcodeIOS(platform string) string {
	randomIndex := rand.Intn(len(IphoneFingerprints))
	fingerprint := &IphoneFingerprints[randomIndex]

	// TIME
	timeNow := time.Now().UnixNano() / int64(time.Millisecond)
	screenPixelDepth := 24
	var pixelRatio string
	var localStorage string
	pixelRatio = "3"
	localStorage = "true"

	// Build fp1
	fp1 := []string{
		"DNT:unknown",
		"L:en-GB",
		fmt.Sprintf("D:%d", screenPixelDepth),
		fmt.Sprintf("PR:%s", pixelRatio),
		"S:844,390",
		"AS:844,390",
		fmt.Sprintf("TO:%d", task.GetTimezoneOffset()),
		"SS:true",                          // - !!window.sessionStorage;
		fmt.Sprintf("LS:%s", localStorage), // - !!window.localStorage;
		"IDB:true",                         // - !!window.indexedDB;
		"B:false",                          // - !!document.body && !!document.body.addBehavior
		"ODB:false",                        // - !!window.openDatabase
		"CPUC:unknown",                     // - navigator.cpuClass ? navigator.cpuClass : "unknown"
		"PK:iPhone",                        // - navigator.platform ? navigator.platform : "unknown")
		"CFP:-953181136",                   // - GPU Fingerprint
		"FR:false",                         //
		"FOS:false",                        //
		"FB:false",                         //
		"JSF:Arial,Arial Hebrew,Arial Rounded MT Bold,Courier,Courier New,Georgia,Helvetica,Helvetica Neue,Impact,LUCIDA GRANDE,Monaco,Palatino,Times,Times New Roman,Trebuchet MS,Verdana", // Fonts
		"P:Chrome PDF Viewer,Chromium PDF Viewer,Microsoft Edge PDF Viewer,PDF Viewer,WebKit built-in PDF",                                                                                  // Extensions
		"T:5,true,true",
		"H:4",
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
	// var mediaQueryDarkMode bool

	var browserAPIChecks []string

	var networkRTTType interface{}
	var NavigatorPdfEnabled bool
	if !task.Preset.MobileKey { // WEB ONLY
		networkRTTType = nil
		NavigatorPdfEnabled = true
		browserAPIChecks = []string{
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

	}

	//webglD.WebglMaxParams = "16,32,16384,1024,16384,16,16384,30,16,16,4095"
	//webglD.WebglUnmaskedRenderer = "ANGLE (NVIDIA, NVIDIA GeForce RTX 3080 (0x0000220A) Direct3D11 vs_5_0 ps_5_0, D3D11)"

	webglD.WebglExtensions = "ANGLE_instanced_arrays;EXT_blend_minmax;EXT_clip_control;EXT_color_buffer_half_float;EXT_depth_clamp;EXT_frag_depth;EXT_polygon_offset_clamp;EXT_shader_texture_lod;EXT_texture_filter_anisotropic;EXT_texture_mirror_clamp_to_edge;EXT_sRGB;KHR_parallel_shader_compile;OES_element_index_uint;OES_fbo_render_mipmap;OES_standard_derivatives;OES_texture_float;OES_texture_half_float;OES_texture_half_float_linear;OES_vertex_array_object;WEBGL_blend_func_extended;WEBGL_color_buffer_float;WEBGL_compressed_texture_astc;WEBGL_compressed_texture_etc;WEBGL_compressed_texture_etc1;WEBGL_compressed_texture_pvrtc;WEBKIT_WEBGL_compressed_texture_pvrtc;WEBGL_debug_renderer_info;WEBGL_debug_shaders;WEBGL_depth_texture;WEBGL_draw_buffers;WEBGL_lose_context;WEBGL_multi_draw;WEBGL_polygon_mode"
	webglD.WebglExtensionsHash = "b9305a4cc5ac1ccff2c39ed3c518c526"

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
		{"key": "user_agent_data_mobile", "value": nil},
		{"key": "navigator_connection_downlink", "value": nil},
		{"key": "navigator_connection_downlink_max", "value": nil},
		{"key": "network_info_rtt", "value": nil},
		{"key": "network_info_save_data", "value": nil},
		{"key": "network_info_rtt_type", "value": networkRTTType},
		{"key": "screen_pixel_depth", "value": screenPixelDepth},
		{"key": "navigator_device_memory", "value": nil},
		{"key": "navigator_pdf_viewer_enabled", "value": NavigatorPdfEnabled},
		{"key": "navigator_languages", "value": "en-GB"},
		{"key": "window_inner_width", "value": 0},
		{"key": "window_inner_height", "value": 0},
		{"key": "window_outer_width", "value": 390},
		{"key": "window_outer_height", "value": 844},
		{"key": "browser_detection_firefox", "value": false},
		{"key": "browser_detection_brave", "value": false},
		{"key": "browser_api_checks", "value": browserAPIChecks},
		{"key": "browser_object_checks", "value": nil},
		{"key": "29s83ih9", "value": utils.Md5Hash("false") + "\u2063"}, // unicode shit
		{"key": "audio_codecs", "value": `{"ogg":"","mp3":"maybe","wav":"probably","m4a":"maybe","aac":"maybe"}`},
		{"key": "audio_codecs_extended_hash", "value": `e59ea13c844d414ebfb7c926baad28da`},
		{"key": "video_codecs", "value": `{"ogg":"","h264":"probably","webm":"probably","mpeg4v":"probably","mpeg4a":"probably","theora":""}`},
		{"key": "video_codecs_extended_hash", "value": `fb12160d5db2a92b7c6752a23d332c74`},
		{"key": "media_query_dark_mode", "value": false},
		{"key": "css_media_queries", "value": 1},
		{"key": "css_color_gamut", "value": "p3"},
		{"key": "css_contrast", "value": "no-preference"},
		{"key": "css_monochrome", "value": false},
		{"key": "css_pointer", "value": "coarse"},
		{"key": "css_grid_support", "value": false},
		{"key": "headless_browser_phantom", "value": false},
		{"key": "headless_browser_selenium", "value": false},
		{"key": "headless_browser_nightmare_js", "value": false},
		{"key": "headless_browser_generic", "value": 4},                   //  4 = normal chrome - unflagged
		{"key": "1l2l5234ar2", "value": fmt.Sprintf("%d\u2063", timeNow)}, // unicode shit
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
		{"key": "audio_fingerprint", "value": "124.04346622781304"},
		{"key": "navigator_battery_charging", "value": nil},
		{"key": "media_device_kinds", "value": []string{}},
		{"key": "media_devices_hash", "value": "d751713988987e9331980363e24189ce"},
		{"key": "navigator_permissions_hash", "value": "57e48421c8755c660127af661537d6b0"},
		{"key": "math_fingerprint", "value": "e4889aec3d9e3cdc6602c187bc80a578"},
		{"key": "supported_math_functions", "value": "cc04bb6a20778adde727893fb7507f9d"},
		{"key": "screen_orientation", "value": "portrait-primary"},
		{"key": "rtc_peer_connection", "value": 1},
		{"key": "4b4b269e68", "value": uuid.New().String()},
		{"key": "6a62b2a558", "value": EnforcementHash},
		{"key": "speech_default_voice", "value": "Tünde || hu-HU"},
		{"key": "speech_voices_hash", "value": strings.ReplaceAll(uuid.New().String(), "-", "")},
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

	// Process fp1 and compute hashes
	processedFp1 := task.Utils.ProcessFP(fp1)
	nValue := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%d", int(timeNow/1000))))

	var constantBSValue string
	if platform == "iphone" {
		constantBSValue = "1d99c2530fa1a96e676f9b1a1a9bcb58"
	} else {
		constantBSValue = "72627afbfd19a741c7da1732218301ac"
	}
	// Build fp
	fp := []map[string]interface{}{
		{"key": "api_type", "value": "js"},
		{"key": "f", "value": task.Utils.X64Hash128GO(processedFp1, 0)}, // hash
		{"key": "n", "value": nValue},                                   // time
		{"key": "wh", "value": fmt.Sprintf("%s|%s", strings.ReplaceAll(uuid.New().String(), "-", ""), constantBSValue)}, // uuid + static
		{"key": "enhanced_fp", "value": enhanced_fp},                                              // ? fingerprint
		{"key": "fe", "value": fp1},                                                               // ? fingerprint
		{"key": "ife_hash", "value": task.Utils.X64Hash128GO(strings.Join(fp1, ", "), 38)},        // hash
		{"key": "jsbd", "value": `{"HL":16,"NCE":false,"DT":"","NWD":"false","DMTO":1,"DOTO":1}`}, // ? fingerprint
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
