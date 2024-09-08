package client

import (
	"errors"
	"fmt"
	"github.com/jroimartin/gocui"
	"strings"
)

// InitGui initializes the gocui screen
func (app *ChatApp) InitGui() error {
	g, err := gocui.NewGui(gocui.OutputNormal)
	if err != nil {
		return fmt.Errorf("failed to initialize gocui: %w", err)
	}
	app.Gui = g
	g.SetManagerFunc(app.layout)

	return nil
}

// PromptRecipientID prompts for recipient ID and sets the chat layout
func (app *ChatApp) PromptRecipientID() error {
	if err := app.Gui.SetKeybinding("prompt", gocui.KeyEnter, gocui.ModNone, func(g *gocui.Gui, v *gocui.View) error {
		app.recipientID = strings.TrimSpace(v.Buffer())
		if app.recipientID == "" {
			return nil
		}
		g.DeleteView("prompt")
		g.SetManagerFunc(app.layout)
		g.SetCurrentView("input")

		if err := app.Gui.SetKeybinding("input", gocui.KeyEnter, gocui.ModNone, app.SendMessageHandler); err != nil {
			logger.Fatalf("Error setting keybinding for input: %v", err)
		}

		if err := app.connectToWebSocket(); err != nil {
			logger.Fatalf("Error connecting to WebSocket server: %v", err)
		}

		return nil
	}); err != nil {
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
		if err := app.sendMessage(message); err != nil {
			logger.Errorf("Error sending message: %v", err)
		}

		app.messages = append(app.messages, "[You] "+message)
		v.Clear()
		v.SetCursor(0, 0)
		app.UpdateMessages(g)
	}
	return nil
}

// Layout function for the UI
func (app *ChatApp) layout(g *gocui.Gui) error {
	maxX, maxY := g.Size()

	if app.recipientID == "" {
		if v, err := g.SetView("prompt", maxX/4, maxY/4, 3*maxX/4, maxY/2); err != nil {
			if !errors.Is(err, gocui.ErrUnknownView) {
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
		if !errors.Is(err, gocui.ErrUnknownView) {
			return err
		}
		v.Title = "Chat with " + app.recipientID
		v.Autoscroll = true
		v.Wrap = true
		app.UpdateMessages(g)
	}

	if v, err := g.SetView("input", 0, maxY-4, maxX-1, maxY-2); err != nil {
		if !errors.Is(err, gocui.ErrUnknownView) {
			return err
		}
		v.Title = "Type a message"
		v.Editable = true
		v.Wrap = true
		g.SetCurrentView("input")
	}

	if err := g.SetKeybinding("", gocui.KeyCtrlC, gocui.ModNone, app.quit); err != nil {
		return err
	}

	return nil
}
