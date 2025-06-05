package utils

// Initial Challenge Data
type ChallengeData struct {
	Token           string `json:"token"`
	ChallengeUrlCDN string `json:"challenge_url_cdn"`
	Tbio            bool   `json:"tbio "`
	Kbio            bool   `json:"kbio"`
	Mbio            bool   `json:"mbio"`
}

// Task Data
type GameData struct {
	Waves             int       `json:"waves"`
	InstructionString string    `json:"instruction_string"`
	GameVariant       string    `json:"game_variant"`
	GameType          int       `json:"gameType"`
	CustomGUI         CustomGUI `json:"customGUI"`
}

type CustomGUI struct {
	ChallengeImgs []string `json:"_challenge_imgs"`
	EncryptedMode int      `json:"encrypted_mode"`
}

type TaskData struct {
	ChallengeID  string            `json:"challengeId"`
	GameData     GameData          `json:"game_data"`
	DapibUrl     string            `json:"dapib_url"`
	StringTable  map[string]string `json:"string_table"`
	SessionToken string            `json:"session_token"`
}

// Solve Result
type AIResult struct {
	Result int `json:"result"`
}

type SolveResult struct {
	Response       string      `json:"response"`
	Solved         bool        `json:"solved"`
	DecryptionKey  string      `json:"decryption_key"`
	IncorrectGuess interface{} `json:"incorrect_guess"`
}

type Fingerprint struct {
	ID                          string   `bson:"_id"`
	WebglAliasedPointSizeRange  string   `bson:"webgl_aliased_point_size_range"`
	WebglAntialiasing           string   `bson:"webgl_antialiasing"`
	WebglVsiParams              string   `bson:"webgl_vsi_params"`
	WebglFsfParams              string   `bson:"webgl_fsf_params"`
	WebglFsiParams              string   `bson:"webgl_fsi_params"`
	WebglExtensions             []string `bson:"webgl_extensions"`
	WebglRenderer               string   `bson:"webgl_renderer"`
	WebglVendor                 string   `bson:"webgl_vendor"`
	WebglMaxViewportDims        string   `bson:"webgl_max_viewport_dims"`
	WebglUnmaskedRenderer       string   `bson:"webgl_unmasked_renderer"`
	WebglVsfParams              string   `bson:"webgl_vsf_params"`
	CFP                         int      `bson:"CFP"`
	UserAgent                   string   `bson:"user_agent"`
	WebglVersion                string   `bson:"webgl_version"`
	WebglAliasedLineWidthRange  string   `bson:"webgl_aliased_line_width_range"`
	WebglMaxParams              string   `bson:"webgl_max_params"`
	WebglShadingLanguageVersion string   `bson:"webgl_shading_language_version"`
	WebglUnmaskedVendor         string   `bson:"webgl_unmasked_vendor"`
	JSF                         string   `bson:"JSF"`
	WebglBits                   string   `bson:"webgl_bits"`
}
