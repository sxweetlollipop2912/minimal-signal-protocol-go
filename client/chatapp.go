package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"minimal-signal/common"
	"minimal-signal/configs"
	"minimal-signal/protocol/doubleratchet"
	"minimal-signal/protocol/x3dh/alice"
	"minimal-signal/protocol/x3dh/bob"
	"net/http"
	"sync"

	"github.com/gorilla/websocket"
	"github.com/jroimartin/gocui"
	"github.com/sirupsen/logrus"
)

var logger = logrus.New()

type ChatApp struct {
	Gui         *gocui.Gui
	recipientID string
	messages    []string
	wsConn      *websocket.Conn
	messageLock sync.Mutex
	userID      string
	wg          sync.WaitGroup

	// crypto stuff
	userPrivKeyBundle bob.BobPrekeyBundle
	otherIDKeyBundle  alice.BobPublicPrekeyBundle
	ratchet           doubleratchet.DoubleRatchet
	initHandshake     *common.X3DHHandshakeBundle
}

// NewChatApp initializes a new ChatApp
func NewChatApp(userID string, userKeyBundle *bob.BobPrekeyBundle) *ChatApp {
	return &ChatApp{userID: userID, userPrivKeyBundle: *userKeyBundle}
}

// connectToWebSocket connects to the WebSocket server.
// Already has recipientID set.
func (app *ChatApp) connectToWebSocket() error {
	serverUrl := fmt.Sprintf("ws://%s%s?userId=%s", configs.ServerAddress, configs.WebSocketPath, app.userID)
	conn, _, err := websocket.DefaultDialer.Dial(serverUrl, nil)
	if err != nil {
		return fmt.Errorf("failed to connect to WebSocket server: %w", err)
	}
	app.wsConn = conn

	// Get other's keys from server
	theirKeys, err := app.GetKeys(app.recipientID)
	if err != nil {
		logger.Fatalf("Error getting recipient keys: %v", err)
	}
	app.otherIDKeyBundle = *theirKeys

	app.wg.Add(1)
	go func() {
		defer app.wg.Done()
		app.listenForMessages()
	}()

	return nil
}

// listenForMessages listens for incoming WebSocket messages
func (app *ChatApp) listenForMessages() {
	for {
		_, msgBytes, err := app.wsConn.ReadMessage()
		if err != nil {
			logger.Errorf("Error reading message: %v", err)
			return
		}

		var msg common.MessageBundle
		if err := json.Unmarshal(msgBytes, &msg); err != nil {
			logger.Errorf("Error unmarshalling message: %v", err)
			continue
		}

		plaintext, err := app.decryptMessage(&msg)
		if err != nil {
			logger.Errorf("Error decrypting message: %v", err)
			continue
		}

		app.messageLock.Lock()
		app.messages = append(app.messages, fmt.Sprintf("[%s] %s", msg.From, plaintext))
		app.messageLock.Unlock()

		app.Gui.Update(func(g *gocui.Gui) error {
			return app.UpdateMessages(g)
		})
	}
}

// sendMessage sends a message to the WebSocket server in JSON format
func (app *ChatApp) sendMessage(message string) error {
	if app.wsConn == nil {
		return fmt.Errorf("WebSocket connection not established")
	}

	msg, err := app.encryptMessage(message)
	if err != nil {
		logger.Errorf("Error encrypting message: %v", err)
		return fmt.Errorf("failed to encrypt message: %w", err)
	}

	msgJSON, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal message to JSON: %w", err)
	}

	err = app.wsConn.WriteMessage(websocket.TextMessage, msgJSON)
	if err != nil {
		return fmt.Errorf("failed to send message: %w", err)
	}
	return nil
}

// quit handles quitting the application
func (app *ChatApp) quit(_ *gocui.Gui, _ *gocui.View) error {
	logger.Info("Shutting down gracefully...")
	if app.wsConn != nil {
		app.wsConn.Close()
	}
	app.wg.Wait()
	return gocui.ErrQuit
}

// PostKeys publishes Bob's keys to the server
func (app *ChatApp) PostKeys() error {
	serverURL := fmt.Sprintf("http://%s%s/%s", configs.ServerAddress, configs.PublishKeysPath, app.userID)

	payload, err := app.userPrivKeyBundle.ToPublicBundle()
	if err != nil {
		return fmt.Errorf("failed to convert keys to public bundle: %v", err)
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %v", err)
	}

	resp, err := http.Post(serverURL, "application/json", bytes.NewBuffer(payloadBytes))
	if err != nil {
		return fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned non-OK status: %v", resp.Status)
	}

	return nil
}

func (app *ChatApp) GetKeys(recipientID string) (*alice.BobPublicPrekeyBundle, error) {
	serverURL := fmt.Sprintf("http://%s%s/%s", configs.ServerAddress, configs.PublishKeysPath, recipientID)

	resp, err := http.Get(serverURL)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned non-OK status: %v", resp.Status)
	}

	var publicPrekeyBundle alice.BobPublicPrekeyBundle
	if err := json.NewDecoder(resp.Body).Decode(&publicPrekeyBundle); err != nil {
		return nil, fmt.Errorf("failed to decode response: %v", err)
	}

	return &publicPrekeyBundle, nil
}

func (app *ChatApp) getADBytes() ([64]byte, error) {
	var adBytes [64]byte
	userIDPub, err := app.userPrivKeyBundle.IdentityKey.Public()
	if err != nil {
		return adBytes, fmt.Errorf("failed to get public key: %v", err)
	}
	copy(adBytes[:32], userIDPub[:])
	copy(adBytes[32:], app.otherIDKeyBundle.IdentityKey[:])
	return adBytes, nil
}
