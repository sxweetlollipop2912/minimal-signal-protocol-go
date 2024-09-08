package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"minimal-signal/configs"
	"minimal-signal/protocol/x3dh/bob"
	"net/http"
	"sync"

	"github.com/gorilla/websocket"
	"github.com/jroimartin/gocui"
	"github.com/sirupsen/logrus"
)

var logger = logrus.New()

// Message struct for sending/receiving JSON
type Message struct {
	From    string `json:"from" validate:"required"`
	To      string `json:"to" validate:"required"`
	Message string `json:"message" validate:"required"`
}

type ChatApp struct {
	Gui           *gocui.Gui
	recipientID   string
	messages      []string
	wsConn        *websocket.Conn
	messageLock   sync.Mutex
	userID        string
	wg            sync.WaitGroup
	userKeyBundle bob.BobPrekeyBundle
}

// NewChatApp initializes a new ChatApp
func NewChatApp(userID string) *ChatApp {
	return &ChatApp{userID: userID}
}

// connectToWebSocket connects to the WebSocket server
func (app *ChatApp) connectToWebSocket() error {
	serverUrl := fmt.Sprintf("ws://%s%s?userId=%s", configs.ServerAddress, configs.WebSocketPath, app.userID)
	conn, _, err := websocket.DefaultDialer.Dial(serverUrl, nil)
	if err != nil {
		return fmt.Errorf("failed to connect to WebSocket server: %w", err)
	}
	app.wsConn = conn

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

		var msg Message
		if err := json.Unmarshal(msgBytes, &msg); err != nil {
			logger.Errorf("Error unmarshalling message: %v", err)
			continue
		}

		app.messageLock.Lock()
		app.messages = append(app.messages, fmt.Sprintf("[%s] %s", msg.From, msg.Message))
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

	msg := Message{
		From:    app.userID,
		To:      app.recipientID,
		Message: message,
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

// publishKeys publishes Bob's keys to the server
func (app *ChatApp) publishKeys() error {
	serverURL := fmt.Sprintf("http://%s%s?userId=%s", configs.ServerAddress, configs.PublishKeysPath, app.userID)

	payloadBytes, err := json.Marshal(app.userKeyBundle)
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
