package utils

import (
	"encoding/base64"
	"fmt"
	"math"
	"math/rand"
)

type MouseEvent struct {
	Type string
	X    int
	Y    int
}

type SubEvent struct {
	Event         MouseEvent
	SincePrevious int
}

type LocationData struct {
	LeftArrow    [2]int
	RightArrow   [2]int
	SubmitButton [2]int
}

func (me MouseEvent) Format(timeElapsed int) string {
	codeMap := map[string]int{"Move": 0, "Down": 1, "Up": 2}
	return fmt.Sprintf("%d,%d,%d,%d;", timeElapsed, codeMap[me.Type], me.X, me.Y)
}

func GenerateMouseClickEvent(coords [2]int) []SubEvent {
	return []SubEvent{
		{Event: MouseEvent{"Down", coords[0], coords[1]}, SincePrevious: 0},
		{Event: MouseEvent{"Up", coords[0], coords[1]}, SincePrevious: rand.Intn(10)},
	}
}

func GenerateBezierPath(coords [][2]int, deviation, speed int) []SubEvent {
	var path []SubEvent
	for i := 0; i < len(coords)-1; i++ {
		start, end := coords[i], coords[i+1]
		tValues := make([]float64, speed+1)
		for t := 0; t <= speed; t++ {
			tValues[t] = float64(t) / float64(speed)
		}
		ctrl1 := randomControlPoint(start, end, deviation)
		ctrl2 := randomControlPoint(start, end, deviation)
		bezierPoints := makeBezier(start, ctrl1, ctrl2, end, tValues)
		for _, point := range bezierPoints {
			path = append(path, SubEvent{
				Event:         MouseEvent{"Move", point[0], point[1]},
				SincePrevious: rand.Intn(10) + 10, // point delay
			})
		}
	}
	return path
}

func randomControlPoint(p1, p2 [2]int, deviation int) [2]int {
	// Calculate midpoint between p1 and p2
	midX := (p1[0] + p2[0]) / 2
	midY := (p1[1] + p2[1]) / 2

	// Gen control point around midpoint with deviation
	return [2]int{
		midX + rand.Intn(deviation) - deviation/2,
		midY + rand.Intn(deviation) - deviation/2,
	}
}

func makeBezier(start, ctrl1, ctrl2, end [2]int, tValues []float64) [][2]int {
	var points [][2]int
	for _, t := range tValues {
		x := math.Pow(1-t, 3)*float64(start[0]) + 3*t*math.Pow(1-t, 2)*float64(ctrl1[0]) +
			3*(1-t)*t*t*float64(ctrl2[0]) + t*t*t*float64(end[0])
		y := math.Pow(1-t, 3)*float64(start[1]) + 3*t*math.Pow(1-t, 2)*float64(ctrl1[1]) +
			3*(1-t)*t*t*float64(ctrl2[1]) + t*t*t*float64(end[1])
		points = append(points, [2]int{int(x), int(y)})
	}
	return points
}

func EncodeEvents(events []SubEvent, startOffset int) []byte {
	var mbioContent string
	timeElapsed := startOffset

	for _, event := range events {
		mbioContent += event.Event.Format(timeElapsed)
		timeElapsed += event.SincePrevious
	}

	// manual format cause GO wont fucking match
	jsonString := fmt.Sprintf(`{"mbio":"%s","tbio":"","kbio":""}`, mbioContent)

	return []byte(jsonString)
}

func GenerateBio(answerIndex, gameType int, location LocationData, startOffset int, encodeBase64 bool) string {
	coords := [][2]int{
		{location.LeftArrow[0], location.LeftArrow[1]},
		{location.RightArrow[0], location.RightArrow[1]},
		{location.SubmitButton[0], location.SubmitButton[1]},
	}
	startingPoint := [2]int{rand.Intn(300), rand.Intn(250)}
	var events []SubEvent
	if gameType == 3 {
		tileCoord := coords[answerIndex%len(coords)]
		events = append(events, GenerateBezierPath([][2]int{startingPoint, tileCoord}, 20, 20)...)
		events = append(events, GenerateMouseClickEvent(tileCoord)...)
	} else if gameType == 4 {
		rightArrowPath := GenerateBezierPath([][2]int{startingPoint, coords[1]}, 20, 20)
		events = append(events, rightArrowPath...)
		for i := 0; i < answerIndex; i++ {
			events = append(events, GenerateMouseClickEvent(coords[1])...)
		}
		submitButtonPath := GenerateBezierPath([][2]int{coords[1], coords[2]}, 20, 20)
		events = append(events, submitButtonPath...)
		events = append(events, GenerateMouseClickEvent(coords[2])...)
	}

	if len(events) > 150 {
		events = events[:150]
	}

	eventData := EncodeEvents(events, startOffset)

	var finalEventData string
	if encodeBase64 {
		finalEventData = base64.StdEncoding.EncodeToString(eventData)
	} else {
		finalEventData = string(eventData)
	}

	return finalEventData
}
