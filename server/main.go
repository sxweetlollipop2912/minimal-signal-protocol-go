package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
)

var (
	ctx            = context.Background()
	redisClient    = redis.NewClient(&redis.Options{Addr: "localhost:6379"})
	connectedUsers = make(map[string]*websocket.Conn)
	mutex          = &sync.Mutex{}
	logger         = logrus.New()
)

// Message struct for incoming/outgoing messages
type Message struct {
	From    string `json:"from" validate:"required"`
	To      string `json:"to" validate:"required"`
	Message string `json:"message" validate:"required"`
}

// WebSocket upgrader settings
var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

// Handle incoming WebSocket connections
func handleConnections(w http.ResponseWriter, r *http.Request) {
	// Upgrade HTTP request to WebSocket
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		logger.Errorf("Error upgrading to WebSocket: %v", err)
		return
	}
	defer ws.Close()

	// Extract userId from the URL query
	userID := r.URL.Query().Get("userId")
	if userID == "" {
		logger.Error("No userId provided in the query")
		return
	}

	// Add user to connectedUsers map
	mutex.Lock()
	connectedUsers[userID] = ws
	mutex.Unlock()
	logger.Infof("User %s connected", userID)

	// Check for queued messages
	retrieveQueuedMessages(userID, ws)

	// Listen for incoming messages
	for {
		_, message, err := ws.ReadMessage()
		if err != nil {
			logger.Errorf("Error reading message from user %s: %v", userID, err)
			break
		}

		var msgObj Message
		if err := json.Unmarshal(message, &msgObj); err != nil {
			logger.Errorf("Invalid message format from user %s: %v", userID, err)
			continue
		}

		// Add the sender's ID to the message
		msgObj.From = userID
		logger.Infof("Received message from user %s: %+v\n", userID, msgObj)

		handleMessage(msgObj)
	}

	// Remove user from connectedUsers map when they disconnect
	mutex.Lock()
	delete(connectedUsers, userID)
	mutex.Unlock()
	logger.Infof("User %s disconnected", userID)
}

// Handle sending messages and queuing for offline users
func handleMessage(msg Message) {
	mutex.Lock()
	recipientConn, online := connectedUsers[msg.To]
	mutex.Unlock()

	if online {
		// Send the message directly if the recipient is online
		messageJSON, _ := json.Marshal(msg)
		if err := recipientConn.WriteMessage(websocket.TextMessage, messageJSON); err != nil {
			logger.Errorf("Error sending message to user %s: %v", msg.To, err)
		}
	} else {
		// Queue the message in Redis if the recipient is offline
		queueMessage(msg.To, msg)
	}
}

// Queue a message in Redis
func queueMessage(userID string, msg Message) {
	messageJSON, err := json.Marshal(msg)
	if err != nil {
		logger.Errorf("Error marshalling message for user %s: %v", userID, err)
		return
	}
	if err := redisClient.RPush(ctx, fmt.Sprintf("messages:%s", userID), messageJSON).Err(); err != nil {
		logger.Errorf("Error queuing message for user %s: %v", userID, err)
	}
}

// Retrieve queued messages for a user when they reconnect
func retrieveQueuedMessages(userID string, ws *websocket.Conn) {
	messages, err := redisClient.LRange(ctx, fmt.Sprintf("messages:%s", userID), 0, -1).Result()
	if err != nil {
		logger.Errorf("Error retrieving queued messages for user %s: %v", userID, err)
		return
	}

	for _, message := range messages {
		if err := ws.WriteMessage(websocket.TextMessage, []byte(message)); err != nil {
			logger.Errorf("Error sending queued message to user %s: %v", userID, err)
			return
		}
	}

	// Clear the queue after sending
	redisClient.Del(ctx, fmt.Sprintf("messages:%s", userID))
}

// Main function to start the server
func main() {
	r := mux.NewRouter() // Using gorilla/mux for more flexible routing
	r.HandleFunc("/ws", handleConnections)

	logger.Info("WebSocket server running on ws://localhost:8080/ws")
	if err := http.ListenAndServe(":8080", r); err != nil {
		logger.Fatalf("Error starting server: %v", err)
	}
}
