package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
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
	gui         *gocui.Gui
	recipientID string
	messages    []string
	wsConn      *websocket.Conn
	messageLock sync.Mutex
	userID      string
}

// NewChatApp initializes a new ChatApp
func NewChatApp(userID string) *ChatApp {
	return &ChatApp{userID: userID}
}

// ConnectToWebSocket connects to the WebSocket server
func (app *ChatApp) ConnectToWebSocket() error {
	u := fmt.Sprintf("ws://localhost:8080/ws?userId=%s", app.userID)
	conn, _, err := websocket.DefaultDialer.Dial(u, nil)
	if err != nil {
		return fmt.Errorf("failed to connect to WebSocket server: %w", err)
	}
	app.wsConn = conn
	go app.ListenForMessages()
	return nil
}

// ListenForMessages listens for incoming WebSocket messages
func (app *ChatApp) ListenForMessages() {
	defer app.wsConn.Close()
	for {
		_, message, err := app.wsConn.ReadMessage()
		if err != nil {
			logger.Errorf("Error reading message: %v", err)
			return
		}

		app.messageLock.Lock()
		app.messages = append(app.messages, "[Other] "+string(message))
		app.messageLock.Unlock()

		app.gui.Update(func(g *gocui.Gui) error {
			return app.UpdateMessages(g)
		})
	}
}

// SendMessage sends a message to the WebSocket server in JSON format
func (app *ChatApp) SendMessage(message string) error {
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

// InitGui initializes the gocui screen
func (app *ChatApp) InitGui() error {
	g, err := gocui.NewGui(gocui.OutputNormal)
	if err != nil {
		return fmt.Errorf("failed to initialize gocui: %w", err)
	}
	app.gui = g
	g.SetManagerFunc(app.layout)

	return nil
}

// Layout function for the UI
func (app *ChatApp) layout(g *gocui.Gui) error {
	maxX, maxY := g.Size()

	if app.recipientID == "" {
		if v, err := g.SetView("prompt", maxX/4, maxY/4, 3*maxX/4, maxY/2); err != nil {
			if err != gocui.ErrUnknownView {
				return err
			}
			v.Title = "Enter recipient ID"
			v.Editable = true
			v.Wrap = true
			g.SetCurrentView("prompt")
		}
		return nil
	}

	if v, err := g.SetView("messages", 0, 0, maxX-1, maxY-5); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		v.Title = "Chat with " + app.recipientID
		v.Autoscroll = true
		v.Wrap = true
		app.UpdateMessages(g)
	}

	if v, err := g.SetView("input", 0, maxY-4, maxX-1, maxY-2); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		v.Title = "Type a message"
		v.Editable = true
		v.Wrap = true
		g.SetCurrentView("input")
	}

	if err := g.SetKeybinding("", gocui.KeyCtrlC, gocui.ModNone, app.Quit); err != nil {
		return err
	}

	return nil
}

// UpdateMessages updates the message view
func (app *ChatApp) UpdateMessages(g *gocui.Gui) error {
	v, err := g.View("messages")
	if err != nil {
		return err
	}
	v.Clear()
	for _, msg := range app.messages {
		fmt.Fprintln(v, msg)
	}
	return nil
}

// SendMessageHandler handles sending messages on Enter press
func (app *ChatApp) SendMessageHandler(g *gocui.Gui, v *gocui.View) error {
	message := strings.TrimSpace(v.Buffer())
	if message != "" {
		if err := app.SendMessage(message); err != nil {
			logger.Errorf("Error sending message: %v", err)
		}

		app.messages = append(app.messages, "[You] "+message)
		v.Clear()
		v.SetCursor(0, 0)
		app.UpdateMessages(g)
	}
	return nil
}

// PromptRecipientID prompts for recipient ID and sets the chat layout
func (app *ChatApp) PromptRecipientID() error {
	if err := app.gui.SetKeybinding("prompt", gocui.KeyEnter, gocui.ModNone, func(g *gocui.Gui, v *gocui.View) error {
		app.recipientID = strings.TrimSpace(v.Buffer())
		if app.recipientID == "" {
			return nil
		}
		g.DeleteView("prompt")
		g.SetManagerFunc(app.layout)
		g.SetCurrentView("input")

		if err := app.gui.SetKeybinding("input", gocui.KeyEnter, gocui.ModNone, app.SendMessageHandler); err != nil {
			logger.Fatalf("Error setting keybinding for input: %v", err)
		}

		if err := app.ConnectToWebSocket(); err != nil {
			logger.Fatalf("Error connecting to WebSocket server: %v", err)
		}

		return nil
	}); err != nil {
		return err
	}
	return nil
}

// Quit handles quitting the application
func (app *ChatApp) Quit(g *gocui.Gui, v *gocui.View) error {
	logger.Info("Shutting down gracefully...")
	if app.wsConn != nil {
		app.wsConn.Close()
	}
	return gocui.ErrQuit
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run main.go <userID>")
		return
	}
	userID := os.Args[1]

	chatApp := NewChatApp(userID)

	if err := chatApp.InitGui(); err != nil {
		logger.Fatalf("Error initializing gocui interface: %v", err)
	}

	if err := chatApp.PromptRecipientID(); err != nil {
		logger.Fatalf("Error prompting recipient ID: %v", err)
	}

	if err := chatApp.gui.MainLoop(); err != nil && err != gocui.ErrQuit {
		logger.Fatalf("Error in gocui main loop: %v", err)
	}

	logger.Info("Application exited.")
}
