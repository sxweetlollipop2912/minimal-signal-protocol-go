package main

import (
	"errors"
	"fmt"
	"github.com/sirupsen/logrus"
	"minimal-signal/client"
	"os"

	"github.com/jroimartin/gocui"
)

var logger = logrus.New()

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run main.go <userID>")
		return
	}
	userID := os.Args[1]

	chatApp := client.NewChatApp(userID)

	if err := chatApp.InitGui(); err != nil {
		logger.Fatalf("Error initializing gocui interface: %v", err)
	}

	if err := chatApp.PromptRecipientID(); err != nil {
		logger.Fatalf("Error prompting recipient ID: %v", err)
	}

	if err := chatApp.Gui.MainLoop(); err != nil && !errors.Is(err, gocui.ErrQuit) {
		logger.Fatalf("Error in gocui main loop: %v", err)
	}

	logger.Info("Application exited.")
}
