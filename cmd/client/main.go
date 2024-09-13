package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"minimal-signal/client"
	"minimal-signal/configs"
	"minimal-signal/crypto/key_ed25519"
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

	if err := createKeysIfNotExists(userID); err != nil {
		logger.Fatalf("Error creating keys: %v", err)
		return
	}
	if err := godotenv.Load(fmt.Sprintf("%s/.env.%s", configs.DebugSecretDir, userID)); err != nil {
		logger.Fatalf("Error loading .env file: %v", err)
		return
	}

	identityKey, err := decodeHexTo32BytesArray(os.Getenv("IDENTITY_KEY"))
	if err != nil {
		logger.Fatalf("Failed to decode IDENTITY_KEY: %v", err)
		return
	}

	prekey, err := decodeHexTo32BytesArray(os.Getenv("PREKEY"))
	if err != nil {
		logger.Fatalf("Failed to decode PREKEY: %v", err)
		return
	}

	// oneTimePrekey, err := decodeHexTo32Byte(os.Getenv("ONE_TIME_PREKEY"))
	// if err != nil {
	// 	logger.Fatalf("Failed to decode ONE_TIME_PREKEY: %v\n", err)
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

func createKeysIfNotExists(userId string) error {
	// Check if the .env.<userId> file already exists
	envFileName := fmt.Sprintf("%s/.env.%s", configs.DebugSecretDir, userId)
	if _, err := os.Stat(envFileName); err == nil {
		return nil
	}

	// Generate a new private key
	idkey, err := key_ed25519.New()
	if err != nil {
		return fmt.Errorf("failed to generate private key: %v", err)
	}
	prekey, err := key_ed25519.New()
	if err != nil {
		return fmt.Errorf("failed to generate private key: %v", err)
	}

	file, err := os.Create(envFileName)
	if err != nil {
		return fmt.Errorf("failed to create env file: %v", err)
	}
	defer file.Close()

	// Write the keys to the file
	_, err = file.WriteString(fmt.Sprintf("IDENTITY_KEY=%x\n", *idkey))
	if err != nil {
		return fmt.Errorf("failed to write identity key: %v", err)
	}
	_, err = file.WriteString(fmt.Sprintf("PREKEY=%x\n", *prekey))
	if err != nil {
		return fmt.Errorf("failed to write prekey: %v", err)
	}
	return nil
}
