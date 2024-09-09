package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"minimal-signal/client"
	"minimal-signal/protocol/x3dh/bob"
	"os"

	"github.com/jroimartin/gocui"

	"github.com/joho/godotenv"
	"github.com/sirupsen/logrus"
)

var logger = logrus.New()

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run main.go <userID>")
		return
	}
	userID := os.Args[1]

	// TODO: Debug
	if userID == "alice" {
		godotenv.Load(".env.alice")
	} else if userID == "bob" {
		godotenv.Load(".env.bob")
	} else {
		godotenv.Load(".env")
	}

	identityKey, err := decodeHexTo32BytesArray(os.Getenv("IDENTITY_KEY"))
	if err != nil {
		fmt.Printf("Failed to decode IDENTITY_KEY: %v\n", err)
		return
	}

	prekey, err := decodeHexTo32BytesArray(os.Getenv("PREKEY"))
	if err != nil {
		fmt.Printf("Failed to decode PREKEY: %v\n", err)
		return
	}

	// oneTimePrekey, err := decodeHexTo32Byte(os.Getenv("ONE_TIME_PREKEY"))
	// if err != nil {
	// 	fmt.Printf("Failed to decode ONE_TIME_PREKEY: %v\n", err)
	// 	return
	// }

	chatApp := client.NewChatApp(userID, &bob.BobPrekeyBundle{
		IdentityKey: identityKey,
		Prekey:      prekey,
	})

	if err := chatApp.InitGui(); err != nil {
		logger.Fatalf("Error initializing gocui interface: %v", err)
	}

	if err := chatApp.PostKeys(); err != nil {
		logger.Fatalf("Error publishing keys: %v", err)
	}

	if err := chatApp.PromptRecipientID(); err != nil {
		logger.Fatalf("Error prompting recipient ID: %v", err)
	}

	if err := chatApp.Gui.MainLoop(); err != nil && !errors.Is(err, gocui.ErrQuit) {
		logger.Fatalf("Error in gocui main loop: %v", err)
	}

	logger.Info("Application exited.")
}

func decodeHexTo32BytesArray(hexStr string) ([32]byte, error) {
	if len(hexStr) == 0 {
		return [32]byte{}, fmt.Errorf("hex string is empty")
	}
	var byteArray [32]byte
	decodedBytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return byteArray, err
	}
	if len(decodedBytes) != 32 {
		return byteArray, fmt.Errorf("decoded byte array is not 32 bytes long")
	}
	copy(byteArray[:], decodedBytes)
	return byteArray, nil
}
