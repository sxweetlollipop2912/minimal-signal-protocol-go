package client

import (
	"encoding/json"
	"fmt"
	"github.com/gorilla/websocket"
	"github.com/jroimartin/gocui"
	"github.com/sirupsen/logrus"
	"sync"
)

var logger = logrus.New()

// Message struct for sending/receiving JSON
type Message struct {
	From    string `json:"from" validate:"required"`
	To      string `json:"to" validate:"required"`
	Message string `json:"message" validate:"required"`
}

type ChatApp struct {
	Gui         *gocui.Gui
	recipientID string
	messages    []string
	wsConn      *websocket.Conn
	messageLock sync.Mutex
	userID      string
	wg          sync.WaitGroup
}

// NewChatApp initializes a new ChatApp
func NewChatApp(userID string) *ChatApp {
	return &ChatApp{userID: userID}
}

// connectToWebSocket connects to the WebSocket server
func (app *ChatApp) connectToWebSocket() error {
	u := fmt.Sprintf("ws://localhost:8080/ws?userId=%s", app.userID)
	conn, _, err := websocket.DefaultDialer.Dial(u, nil)
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
