package routes

import (
	"context"
	"fmt"
	"funcaptchaapi/core"
	utils "funcaptchaapi/utils"
	"log"
	"math"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/labstack/echo/v4"
)

type Request struct {
	TaskID    string `json:"task_id"`
	Proxy     string `json:"proxy"`
	Preset    string `json:"preset"`
	Blob      string `json:"blob"`
	Platform  string `json:"platform"`
	Hardcoded bool   `json:"hardcoded"`
}

var taskPool sync.Map

const (
	Service = "funcaptcha"

	// Colors
	Reset        = "\033[0m"
	Purple       = "\033[35m"
	DarkGray     = "\033[90m"
	Neutral      = "\033[37m" // Light gray
	LabelColor   = "\033[97m" // White
	SuccessColor = "\033[32m" // Green
	ErrorColor   = "\033[31m" // Red
)

func GetPlatformDetails(c echo.Context) error {
	platformDetails := make(map[string]string)

	for _, platform := range core.Platforms {
		userAgent := core.PlatformData["user_agent"][platform].(string)
		platformDetails[platform] = userAgent
	}

	// Return the platforms as JSON.
	return c.JSON(http.StatusOK, map[string]interface{}{
		"success":   true,
		"platforms": platformDetails,
	})
}

// Main Solver
func CreateTaskRoute(c echo.Context) error {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Recovered from panic: %v", r)
		}
	}()

	contentType := c.Request().Header.Get("Content-Type")
	if contentType != "application/json" {
		return c.JSON(http.StatusUnsupportedMediaType, map[string]interface{}{
			"success": false,
			"error":   "Unsupported Content-Type",
			"details": fmt.Sprintf("Expected 'Content-Type: application/json' but got '%s'", contentType),
		})
	}

	// Req
	var req Request
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]interface{}{"success": false, "error": "invalid request"})
	}

	// Proxy validation
	if !core.UseLocalHost && (req.Proxy == "" || !strings.HasPrefix(req.Proxy, "http://") ||
		!strings.Contains(req.Proxy, "@") || !strings.Contains(req.Proxy, ":") ||
		strings.Contains(req.Proxy, "localhost") || strings.Contains(req.Proxy, "127.0.0.1") ||
		strings.Contains(req.Proxy, "0.0.0.0")) {
		return c.JSON(http.StatusBadRequest, map[string]interface{}{
			"success": false,
			"error":   "invalid or missing proxy",
		})
	}

	if req.Preset != "" {
		// Find preset
		preset, err := utils.FindPresetBySiteKeyOrName(req.Preset)
		if err != nil {
			return c.JSON(http.StatusBadRequest, map[string]interface{}{"success": false, "error": "invalid preset"})
		}

		if preset.BlobRequired && (req.Blob == "" || strings.TrimSpace(req.Blob) == "") {
			return c.JSON(http.StatusBadRequest, map[string]interface{}{
				"success": false,
				"error":   "site requires blob - you forgot to send one",
			})
		}

		// Create Task
		task, err := core.NewFuncaptchaTask(req.Blob, req.Proxy, req.Platform, req.Hardcoded, preset)
		if err != nil {
			return c.JSON(http.StatusBadRequest, map[string]interface{}{"success": false, "error": "failed to create task"})
		}

		//  Store task in pool
		taskPool.Store(task.ID, task)

		// Solve Goroutine
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			start := time.Now()

			done := make(chan error)
			go func() {
				done <- task.Solve()
			}()

			var err error
			select {
			case err = <-done:
				if err != nil {
					errMsg := err.Error()

					// Check for proxy error
					if strings.Contains(errMsg, "proxy error") {
						task.Status = "error"
						task.ErrorReason = "bad proxy"
						return
					}

					if strings.Contains(errMsg, "invalid blob") {
						task.ErrorReason = "invalid blob"
					} else if strings.Contains(errMsg, "too many waves") {
						task.ErrorReason = "too many waves"
					} else if strings.Contains(errMsg, "failed to get image") {
						task.ErrorReason = "failed to fetch challenge image"
					} else if strings.Contains(errMsg, "407 Proxy") {
						task.ErrorReason = "407 proxy error - invalid proxy auth or you ran out of bandwidth"
					} else {
						task.ErrorReason = "internal error"
					}
					task.Status = "error"

				} else {
					task.Status = "completed"
				}

			case <-ctx.Done():
				task.Status = "error"
				task.ErrorReason = "timeout reached - proxy / funcaptcha network issue"
				err = fmt.Errorf("timeout reached")
			}

			duration := time.Since(start)
			task.ProcessTime = duration.Seconds()

			// Log
			logTaskCompletion(preset, task, err == nil, duration)
		}()

		return c.JSON(http.StatusOK, map[string]interface{}{"success": true, "task_id": task.ID})
	} else {
		return c.JSON(http.StatusBadRequest, map[string]interface{}{"success": false, "error": "preset wasn't provided"})
	}
}

func GetTaskRoute(c echo.Context) error {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Recovered from panic: %v", r)
		}
	}()

	var req Request
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]interface{}{"success": false, "error": "invalid request"})
	}

	// Retrieve task from taskPool
	val, exists := taskPool.Load(req.TaskID)
	if !exists {
		return c.JSON(http.StatusBadRequest, map[string]interface{}{"success": false, "error": "invalid task_id"})
	}
	task := val.(*core.FuncaptchaTask)

	// Task Response
	switch task.Status {
	case "completed":
		taskPool.Delete(req.TaskID)
		return c.JSON(http.StatusOK, map[string]interface{}{
			"success": true,
			"status":  task.Status,
			"token":   task.FinalToken,
			"time":    math.Round(task.ProcessTime*100) / 100,
		})

	case "error":
		taskPool.Delete(req.TaskID)
		return c.JSON(http.StatusOK, map[string]interface{}{
			"success": false,
			"status":  task.Status,
			"error":   task.ErrorReason,
		})

	case "processing":
		return c.JSON(http.StatusOK, map[string]interface{}{
			"success": false,
			"status":  task.Status,
		})

	default:
		return c.JSON(http.StatusInternalServerError, map[string]interface{}{
			"success": false,
			"error":   "unknown task status",
		})
	}
}

// Utilities
func logTaskCompletion(preset utils.Preset, task *core.FuncaptchaTask, success bool, duration time.Duration) {
	// Token Color
	tokenColor := SuccessColor
	if !success {
		tokenColor = ErrorColor
	}

	// All arguments
	websiteName := fmt.Sprintf("%s%s%s", Purple, preset.WebsiteName, Reset)
	gameLabel := fmt.Sprintf("%sGame:%s", LabelColor, Reset)
	gameValue := fmt.Sprintf("%s%s%s", Neutral, task.GameName, Reset)
	wavesLabel := fmt.Sprintf("%sWaves:%s", LabelColor, Reset)
	wavesValue := fmt.Sprintf("%s%d%s", Neutral, task.Waves, Reset)
	tokenLabel := fmt.Sprintf("%sToken:%s", LabelColor, Reset)
	tokenValue := fmt.Sprintf("%s%s%s", tokenColor, task.SessionToken, Reset)
	timeLabel := fmt.Sprintf("%sTime:%s", LabelColor, Reset)
	timeValue := fmt.Sprintf("%s%.2fs%s", Neutral, duration.Seconds(), Reset)
	separator := fmt.Sprintf("%s|%s", DarkGray, Reset)

	// Final message
	message := strings.Join([]string{
		websiteName,
		separator,
		gameLabel, gameValue,
		separator,
		wavesLabel, wavesValue,
		separator,
		timeLabel, timeValue,
		separator,
		tokenLabel, tokenValue,
	}, " ")

	log.Println(message)
}
