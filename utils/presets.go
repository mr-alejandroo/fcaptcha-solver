package utils

import (
	"fmt"
	"log"
	"reflect"
)

func init() {
	for _, preset := range Presets {
		if err := validateStructFields(preset, "Preset '"+preset.Name+"'"); err != nil {
			log.Println(err)
		}
	}
}

var optionalFields = map[string]bool{
	"ExtraArgs":  true,
	"AppAgent":   true,
	"AppPackage": true,
}

func validateStructFields(data interface{}, context string) error {
	v := reflect.ValueOf(data)
	t := v.Type()

	// Only process structs
	if t.Kind() != reflect.Struct {
		return nil
	}

	for i := 0; i < v.NumField(); i++ {
		field := t.Field(i)
		fieldValue := v.Field(i)

		// Skip optional fields
		if optionalFields[field.Name] {
			continue
		}

		if field.Type.Kind() == reflect.Bool {
			continue
		}

		if field.Type.Kind() == reflect.Interface && fieldValue.IsNil() {
			continue
		}
		// Recurse if nested struct (e.g., PresetData)
		if fieldValue.Kind() == reflect.Struct {
			if err := validateStructFields(fieldValue.Interface(), context+" > "+field.Name); err != nil {
				return err
			}
			continue
		}

		// Log a warning if the field has a zero value (empty)
		if isZero(fieldValue) {
			log.Printf("Warning: %s field '%s' is missing a value", context, field.Name)
		}
	}
	return nil
}

func isZero(v reflect.Value) bool {
	return v.IsZero()
}

type Preset struct {
	Name         string                 `json:"name"`
	SiteURL      string                 `json:"site_url"`
	SiteKey      string                 `json:"site_key"`
	APIURL       string                 `json:"api_url"`
	Data         PresetData             `json:"data"`
	WebsiteName  string                 `json:"website_name"`
	CapiMode     string                 `json:"capi_mode"`
	StyleTheme   string                 `json:"style_theme"`
	MobileKey    bool                   `json:"mobile_key"`
	AppAgent     string                 `json:"app_agent"`
	AppPackage   string                 `json:"app_package"`
	BlobRequired bool                   `json:"blob_required"`
	ExtraArgs    map[string]interface{} `json:"extra_args"`

	// solver only
	IsCustomVersion bool `json:"is_custom_version"`
}

type PresetData struct {
	WindowAncestorOrigins            []string    `json:"window__ancestor_origins"`
	ClientConfigSitedataLocationHref string      `json:"client_config__sitedata_location_href"`
	WindowTreeStructure              string      `json:"window__tree_structure"`
	WindowTreeIndex                  []int       `json:"window__tree_index"`
	ClientConfigLanguage             interface{} `json:"client_config__language"`
	ClientConfigTriggeredInline      bool        `json:"client_config__triggered_inline"`
	EmptyDocumentReferrer            bool        `json:"empty_document_refferer"`
}

var Presets = []Preset{
	// Roblox
	{
		Name:         "roblox_register",
		WebsiteName:  "Roblox",
		SiteURL:      "https://www.roblox.com",
		SiteKey:      "A2A14B1D-1AF3-C791-9BBC-EE33CC7A0A6F",
		APIURL:       "https://arkoselabs.roblox.com",
		CapiMode:     "inline",
		StyleTheme:   "default",
		BlobRequired: true,
		MobileKey:    false,
		Data: PresetData{
			WindowAncestorOrigins: []string{
				"https://www.roblox.com",
				"https://www.roblox.com",
			},
			ClientConfigSitedataLocationHref: "https://www.roblox.com/arkose/iframe",
			ClientConfigLanguage:             nil,
			ClientConfigTriggeredInline:      false,
			WindowTreeStructure:              "[[[]]]",
			WindowTreeIndex:                  []int{0, 0},
		},
	},
	{
		Name:         "roblox_login",
		WebsiteName:  "Roblox",
		SiteURL:      "https://www.roblox.com",
		SiteKey:      "476068BF-9607-4799-B53D-966BE98E2B81",
		APIURL:       "https://arkoselabs.roblox.com",
		CapiMode:     "inline",
		StyleTheme:   "default",
		BlobRequired: true,
		MobileKey:    false,
		Data: PresetData{
			WindowAncestorOrigins: []string{
				"https://www.roblox.com",
				"https://www.roblox.com",
			},
			ClientConfigSitedataLocationHref: "https://www.roblox.com/arkose/iframe",
			ClientConfigLanguage:             nil,
			ClientConfigTriggeredInline:      false,
			WindowTreeStructure:              "[[],[[]]]",
			WindowTreeIndex:                  []int{1, 0},
		},
	},
	// Github
	{
		Name:         "github_register",
		WebsiteName:  "Github",
		SiteURL:      "https://octocaptcha.com",
		SiteKey:      "747B83EC-2CA3-43AD-A7DF-701F286FBABA",
		APIURL:       "https://github-api.arkoselabs.com",
		CapiMode:     "inline",
		StyleTheme:   "default",
		BlobRequired: true,
		MobileKey:    false,
		ExtraArgs: map[string]interface{}{
			"data[origin_page]": "github_signup_redesign",
		},
		Data: PresetData{
			WindowAncestorOrigins: []string{
				"https://octocaptcha.com",
				"https://github.com",
			},
			ClientConfigSitedataLocationHref: "https://github-api.arkoselabs.com/v2/2.9.0/enforcement.b3b1c9343f2ef3887d61d74272d6a3af.html",
			ClientConfigLanguage:             nil,
			ClientConfigTriggeredInline:      false,
			WindowTreeStructure:              "[[[]]]",
			WindowTreeIndex:                  []int{0, 0},
		},
	},
	{
		Name:         "github_report",
		WebsiteName:  "Github",
		SiteURL:      "https://octocaptcha.com",
		SiteKey:      "D72ECCFB-262E-4065-9196-856E70BE98ED",
		APIURL:       "https://github-api.arkoselabs.com",
		CapiMode:     "inline",
		StyleTheme:   "default",
		BlobRequired: true,
		MobileKey:    false,
		Data: PresetData{
			WindowAncestorOrigins: []string{
				"https://octocaptcha.com",
				"https://support.github.com",
			},
			ClientConfigSitedataLocationHref: "https://octocaptcha.com/",
			ClientConfigLanguage:             nil, // technically just copied, idk if correct
			ClientConfigTriggeredInline:      false,
			WindowTreeStructure:              "[[[]]]",
			WindowTreeIndex:                  []int{0, 0},
		},
	},
	{
		Name:         "github_sms",
		WebsiteName:  "Github",
		SiteURL:      "https://octocaptcha.com",
		SiteKey:      "D72ECCFB-262E-4065-9196-856E70BE98ED",
		APIURL:       "https://github-api.arkoselabs.com",
		CapiMode:     "inline",
		StyleTheme:   "default",
		BlobRequired: true,
		MobileKey:    false,
		ExtraArgs: map[string]interface{}{
			"data[origin_page]": "github_two_factor_sms_setup",
		},
		Data: PresetData{
			WindowAncestorOrigins: []string{
				"https://octocaptcha.com",
				"https://support.github.com",
			},
			ClientConfigSitedataLocationHref: "https://octocaptcha.com/",
			ClientConfigLanguage:             nil, // technically just copied, idk if correct
			ClientConfigTriggeredInline:      false,
			WindowTreeStructure:              "[[[]]]",
			WindowTreeIndex:                  []int{0, 0},
		},
	},

	// Snapchat
	{
		Name:         "snapchat_register",
		WebsiteName:  "Snapchat",
		SiteURL:      "https://iframe.arkoselabs.com",
		SiteKey:      "EA4B65CB-594A-438E-B4B5-D0DBA28C9334",
		APIURL:       "https://snap-api.arkoselabs.com",
		CapiMode:     "lightbox",
		StyleTheme:   "default",
		BlobRequired: false,
		MobileKey:    false,
		ExtraArgs: map[string]interface{}{
			"language": "en-us",
		},
		Data: PresetData{
			WindowAncestorOrigins: []string{
				"https://iframe.arkoselabs.com",
				"https://accounts.snapchat.com",
			},
			ClientConfigSitedataLocationHref: "https://iframe.arkoselabs.com/EA4B65CB-594A-438E-B4B5-D0DBA28C9334/lightbox.html",
			ClientConfigLanguage:             "en-us",
			ClientConfigTriggeredInline:      false,
			WindowTreeStructure:              "[[[]]]",
			WindowTreeIndex:                  []int{0, 0},
		},
	},

	// Outlook
	{
		Name:         "outlook_register",
		WebsiteName:  "Outlook",
		SiteURL:      "https://iframe.arkoselabs.com",
		SiteKey:      "B7D8911C-5CC8-A9A3-35B0-554ACEE604DA",
		APIURL:       "https://client-api.arkoselabs.com",
		CapiMode:     "inline",
		StyleTheme:   "default",
		BlobRequired: true,
		MobileKey:    false,
		ExtraArgs: map[string]interface{}{
			"language": "en",
		},
		Data: PresetData{
			WindowAncestorOrigins: []string{
				"https://iframe.arkoselabs.com",
				"https://signup.live.com",
			},
			ClientConfigSitedataLocationHref: "https://iframe.arkoselabs.com/B7D8911C-5CC8-A9A3-35B0-554ACEE604DA/index.html",
			ClientConfigLanguage:             "en-gb",
			ClientConfigTriggeredInline:      false,
			WindowTreeStructure:              "[[],[],[[]]]",
			WindowTreeIndex:                  []int{2, 0},
		},
	},

	// Match.com
	{
		Name:         "match_login",
		WebsiteName:  "Match",
		SiteURL:      "https://match.com",
		SiteKey:      "85800716-F435-4981-864C-8B90602D10F7",
		APIURL:       "https://client-api.arkoselabs.com",
		CapiMode:     "lightbox",
		StyleTheme:   "default",
		BlobRequired: false,
		MobileKey:    false,
		Data: PresetData{
			WindowAncestorOrigins: []string{
				"https://match.com",
			},
			ClientConfigSitedataLocationHref: "https://match.com/login",
			ClientConfigLanguage:             nil,
			ClientConfigTriggeredInline:      false,
			WindowTreeStructure:              "[[[]],[],[]]",
			WindowTreeIndex:                  []int{2},
		},
	},

	// Livelyme
	{
		Name:         "livelyme_login",
		WebsiteName:  "LivelyMe",
		SiteURL:      "https://secure.livelyme.com",
		SiteKey:      "05846D28-284B-8EC4-B45A-ACC6F6759588",
		APIURL:       "https://lively-api.arkoselabs.com",
		CapiMode:     "lightbox",
		StyleTheme:   "default",
		BlobRequired: false,
		MobileKey:    false,
		Data: PresetData{
			WindowAncestorOrigins: []string{
				"https://secure.livelyme.com",
			},
			ClientConfigSitedataLocationHref: "https://secure.livelyme.com/login",
			ClientConfigLanguage:             nil,
			ClientConfigTriggeredInline:      false,
			WindowTreeStructure:              "[[[]],[],[]]",
			WindowTreeIndex:                  []int{2},
		},
	}, // ? NO BLOB

	// EA
	{
		Name:         "ea_register",
		WebsiteName:  "EA",
		SiteURL:      "https://signin.ea.com",
		SiteKey:      "73BEC076-3E53-30F5-B1EB-84F494D43DBA",
		APIURL:       "https://ea-api.arkoselabs.com",
		CapiMode:     "lightbox",
		StyleTheme:   "EADARK",
		BlobRequired: true,
		MobileKey:    false,
		ExtraArgs: map[string]interface{}{
			"language": "en",
		},
		Data: PresetData{
			WindowAncestorOrigins: []string{
				"https://signin.ea.com",
			},
			ClientConfigSitedataLocationHref: "https://signin.ea.com/p/juno/create",
			ClientConfigLanguage:             "en",
			ClientConfigTriggeredInline:      false,
			WindowTreeStructure:              "[[]]",
			WindowTreeIndex:                  []int{0},
		},
	}, // HAS BLOB

	// Blizzard
	{
		Name:         "blizzard_register",
		WebsiteName:  "Blizzard",
		SiteURL:      "https://account.battle.net",
		SiteKey:      "E8A75615-1CBA-5DFF-8032-D16BCF234E10",
		APIURL:       "https://blizzard-api.arkoselabs.com",
		CapiMode:     "lightbox",
		StyleTheme:   "default",
		BlobRequired: true,
		MobileKey:    false,
		Data: PresetData{
			WindowAncestorOrigins: []string{
				"https://account.battle.net",
			},
			ClientConfigSitedataLocationHref: "https://account.battle.net/creation/flow/creation-full",
			ClientConfigLanguage:             nil,
			ClientConfigTriggeredInline:      false,
			WindowTreeStructure:              "[[],[]]",
			WindowTreeIndex:                  []int{1},
		},
	},

	{
		Name:         "adobe_register",
		WebsiteName:  "Adobe R",
		SiteURL:      "https://auth.services.adobe.com",
		SiteKey:      "436DD567-5435-4B14-89A6-2F1188E11334",
		APIURL:       "https://adobe-api.arkoselabs.com",
		CapiMode:     "lightbox",
		StyleTheme:   "default",
		BlobRequired: true,
		MobileKey:    false,
		ExtraArgs: map[string]interface{}{
			"language": "currentLanguage",
		},
		Data: PresetData{
			WindowAncestorOrigins: []string{
				"https://auth.services.adobe.com",
			},
			ClientConfigSitedataLocationHref: "https://auth.services.adobe.com/en_US/deeplink.html#/signup/2",
			ClientConfigLanguage:             "currentLanguage",
			ClientConfigTriggeredInline:      false,
			WindowTreeStructure:              "[[],[],[]]",
			WindowTreeIndex:                  []int{2},
		},
	},

	// Dropbox
	{
		Name:         "dropbox_register",
		WebsiteName:  "DropBox R",
		SiteURL:      "https://dropboxcaptcha.com",
		SiteKey:      "68CECE5D-F360-8653-CA80-3CF99353DDD2",
		APIURL:       "https://dropbox-api.arkoselabs.com",
		CapiMode:     "lightbox",
		StyleTheme:   "default",
		BlobRequired: false,
		MobileKey:    false,
		Data: PresetData{
			WindowAncestorOrigins: []string{
				"https://dropboxcaptcha.com",
				"https://www.dropbox.com",
			},
			ClientConfigSitedataLocationHref: "https://dropboxcaptcha.com/",
			ClientConfigLanguage:             nil,
			ClientConfigTriggeredInline:      false,
			WindowTreeStructure:              "[[],[[]]]",
			WindowTreeIndex:                  []int{1, 0},
		},
	}, // ? NO BLOB (key gone)

	{
		Name:         "dropbox_login",
		WebsiteName:  "Dropbox L",
		SiteURL:      "https://dropboxcaptcha.com",
		SiteKey:      "419899FA-7FAF-5C1D-C027-BC34963E3A4F",
		APIURL:       "https://dropbox-api.arkoselabs.com",
		CapiMode:     "lightbox",
		StyleTheme:   "default",
		BlobRequired: true,
		MobileKey:    false,
		Data: PresetData{
			WindowAncestorOrigins:            []string{},
			ClientConfigSitedataLocationHref: "https://dropboxcaptcha.com/",
			ClientConfigLanguage:             nil,
			ClientConfigTriggeredInline:      false,
			WindowTreeStructure:              "[[[]],[],[[]]]",
			WindowTreeIndex:                  []int{2, 0},
		},
	}, // ? NO BLOB (key gone)

	// Max.Com
	{
		Name:         "max_login",
		WebsiteName:  "Max L",
		SiteURL:      "https://auth.max.com",
		SiteKey:      "B0217B00-2CA4-41CC-925D-1EEB57BFFC2F",
		APIURL:       "https://wbd-api.arkoselabs.com",
		CapiMode:     "lightbox",
		StyleTheme:   "max",
		BlobRequired: true,
		MobileKey:    false,
		ExtraArgs: map[string]interface{}{
			"language": "en-US",
		},
		Data: PresetData{
			WindowAncestorOrigins: []string{
				"https://auth.max.com",
				"https://auth.max.com",
			},
			ClientConfigSitedataLocationHref: "about:srcdoc",
			WindowTreeStructure:              "[[[]],[],[],[],[],[],[],[],[],[[]]]",
			ClientConfigLanguage:             "en-US",
			ClientConfigTriggeredInline:      false,
			WindowTreeIndex:                  []int{9, 0},
		},
	},

	// Twitter Web
	{
		Name:         "twitter_web_register",
		WebsiteName:  "Twitter Web R",
		SiteURL:      "https://iframe.arkoselabs.com",
		SiteKey:      "2CB16598-CB82-4CF7-B332-5990DB66F3AB",
		APIURL:       "https://client-api.arkoselabs.com",
		CapiMode:     "inline",
		StyleTheme:   "dark",
		BlobRequired: true,
		MobileKey:    false,
		Data: PresetData{
			WindowAncestorOrigins: []string{
				"https://iframe.arkoselabs.com",
				"https://x.com",
			},
			ClientConfigSitedataLocationHref: "https://iframe.arkoselabs.com/2CB16598-CB82-4CF7-B332-5990DB66F3AB/index.html",
			ClientConfigLanguage:             nil,
			ClientConfigTriggeredInline:      false,
			WindowTreeStructure:              "[[[]]]",
			WindowTreeIndex:                  []int{0, 0},
		},
	},
	{
		Name:         "twitter_web_unlock",
		WebsiteName:  "Twitter Custom UNL",
		SiteURL:      "https://iframe.arkoselabs.com",
		SiteKey:      "0152B4EB-D2DC-460A-89A1-629838B529C9",
		APIURL:       "https://client-api.arkoselabs.com",
		CapiMode:     "inline",
		StyleTheme:   "default",
		BlobRequired: true,
		MobileKey:    false,
		Data: PresetData{
			WindowAncestorOrigins: []string{
				"https://iframe.arkoselabs.com",
				"https://x.com",
			},
			ClientConfigSitedataLocationHref: "https://iframe.arkoselabs.com/0152B4EB-D2DC-460A-89A1-629838B529C9/index.html",
			ClientConfigLanguage:             "en",
			ClientConfigTriggeredInline:      false,
			WindowTreeStructure:              "[[[]],[[]],[]]",
			WindowTreeIndex:                  []int{0, 0},
		},
	},

	// Twitter Mobile
	{
		Name:         "twitter_mobile_register", // update someday ig idk
		WebsiteName:  "Twitter M-R",
		SiteURL:      "https://iframe.arkoselabs.com",
		SiteKey:      "867D55F2-24FD-4C56-AB6D-589EDAF5E7C5",
		APIURL:       "https://client-api.arkoselabs.com",
		CapiMode:     "inline",
		StyleTheme:   "dark",
		BlobRequired: true,
		MobileKey:    true,
		AppAgent:     "TwitterAndroid/10.65.2-release.0 (310652000-r-0)",
		AppPackage:   "com.twitter.android",
		Data: PresetData{
			WindowAncestorOrigins: []string{
				"https://iframe.arkoselabs.com",
				"https://twitter.com",
			},
			ClientConfigSitedataLocationHref: "https://iframe.arkoselabs.com/867D55F2-24FD-4C56-AB6D-589EDAF5E7C5/index.html",
			WindowTreeStructure:              "[[[]]]",
			WindowTreeIndex:                  []int{0, 0},
		},
	}, // BLOB USED

	// Zilch
	{
		Name:         "zilch_login",
		WebsiteName:  "Zilch L",
		SiteURL:      "https://customers.payzilch.com",
		SiteKey:      "284CE8B2-89E0-45B0-98B7-38594A810745",
		APIURL:       "https://client-api.arkoselabs.com",
		CapiMode:     "lightbox",
		StyleTheme:   "default",
		BlobRequired: true,
		MobileKey:    false,
		Data: PresetData{
			WindowAncestorOrigins: []string{
				"https://customers.payzilch.com",
			},
			ClientConfigSitedataLocationHref: "https://customers.payzilch.com/login",
			ClientConfigLanguage:             nil,
			ClientConfigTriggeredInline:      false,
			WindowTreeStructure:              "[[],[],[]]",
			WindowTreeIndex:                  []int{2},
			EmptyDocumentReferrer:            true,
		},
	},

	// Groupme
	{
		Name:         "groupme_register",
		WebsiteName:  "Groupme R",
		SiteURL:      "https://web.groupme.com",
		SiteKey:      "49D02870-26F8-42F2-8619-0157104B9DEE",
		APIURL:       "https://groupme-api.arkoselabs.com",
		CapiMode:     "lightbox",
		StyleTheme:   "default",
		BlobRequired: false,
		MobileKey:    false,
		Data: PresetData{
			WindowAncestorOrigins: []string{
				"https://web.groupme.com",
			},
			ClientConfigSitedataLocationHref: "https://web.groupme.com/signup",
			ClientConfigLanguage:             nil,
			ClientConfigTriggeredInline:      false,
			WindowTreeStructure:              "[[],[]]",
			WindowTreeIndex:                  []int{0},
		},
	},
}

func FindPresetBySiteKeyOrName(query string) (Preset, error) {
	for _, preset := range Presets {
		// Check by sitekey or siteurl
		if preset.SiteKey == query || preset.Name == query {
			return preset, nil
		}
	}
	return Preset{}, fmt.Errorf("preset not found for query: %s", query)
}
