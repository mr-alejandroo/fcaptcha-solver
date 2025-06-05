package main

import (
	"fmt"
	utils "funcaptchaapi/utils"
	"testing"
)

func TestHelloBio(t *testing.T) {
	answerIndex := 2
	gameType := 4

	location := utils.LocationData{
		LeftArrow:    [2]int{40, 113},  // Left arrow at (100, 200)
		RightArrow:   [2]int{280, 113}, // Right arrow 50px to the right at (150, 200)
		SubmitButton: [2]int{175, 146}, // Submit button centered below at (125, 300)
	}

	startOffset := 20
	encodeBase64 := false

	bio := utils.GenerateBio(answerIndex, gameType, location, startOffset, encodeBase64)

	fmt.Println(bio)
}
