package server

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/gorilla/websocket"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
	"net/http"
	"sync"
)

// Message struct for incoming/outgoing messages
type Message struct {
	From    string `json:"from" validate:"required"`
	To      string `json:"to" validate:"required"`
	Message string `json:"message" validate:"required"`
}

type Server struct {
	ctx       context.Context
	cancelCtx context.CancelFunc

	redisClient    *redis.Client
	connectedUsers map[string]*websocket.Conn
	mutex          *sync.Mutex
	logger         *logrus.Logger

	// WebSocket upgrader settings
	upgrader *websocket.Upgrader
}

func NewServer(ctx context.Context, redisClient *redis.Client, logger *logrus.Logger) *Server {
	ctx, cancelCtx := context.WithCancel(ctx)
	return &Server{
		ctx:            ctx,
		cancelCtx:      cancelCtx,
		redisClient:    redisClient,
		connectedUsers: make(map[string]*websocket.Conn),
		mutex:          &sync.Mutex{},
		logger:         logger,
		upgrader: &websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
		},
	}
}

// Handle incoming WebSocket connections
func (s *Server) HandleConnections(w http.ResponseWriter, r *http.Request) {
	// Upgrade HTTP request to WebSocket
	ws, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		s.logger.Errorf("Error upgrading to WebSocket: %v", err)
		return
	}
	defer ws.Close()

	// Extract userId from the URL query
	userID := r.URL.Query().Get("userId")
	if userID == "" {
		s.logger.Error("No userId provided in the query")
		return
	}

	// Add user to connectedUsers map
	s.mutex.Lock()
	s.connectedUsers[userID] = ws
	s.mutex.Unlock()
	s.logger.Infof("User %s connected", userID)

	// Check for queued messages
	s.retrieveQueuedMessages(userID, ws)

	// Listen for incoming messages
	for {
		_, message, err := ws.ReadMessage()
		if err != nil {
			s.logger.Errorf("Error reading message from user %s: %v", userID, err)
			break
		}

		var msgObj Message
		if err := json.Unmarshal(message, &msgObj); err != nil {
			s.logger.Errorf("Invalid message format from user %s: %v", userID, err)
			continue
		}

		// Add the sender's ID to the message
		msgObj.From = userID
		s.logger.Infof("Received message from user %s: %+v\n", userID, msgObj)

		s.handleMessage(&msgObj)
	}

	// Remove user from connectedUsers map when they disconnect
	s.mutex.Lock()
	delete(s.connectedUsers, userID)
	s.mutex.Unlock()
	s.logger.Infof("User %s disconnected", userID)
}

func (s *Server) Close() {
	s.cancelCtx()
	// Close all WebSocket connections
	s.mutex.Lock()
	for _, conn := range s.connectedUsers {
		conn.Close()
	}
	s.mutex.Unlock()
	s.redisClient.Close()
}

// Handle sending messages and queuing for offline users
func (s *Server) handleMessage(msg *Message) {
	s.mutex.Lock()
	recipientConn, online := s.connectedUsers[msg.To]
	s.mutex.Unlock()

	if online {
		// Send the message directly if the recipient is online
		messageJSON, _ := json.Marshal(msg)
		if err := recipientConn.WriteMessage(websocket.TextMessage, messageJSON); err != nil {
			s.logger.Errorf("Error sending message to user %s: %v", msg.To, err)
		}
	} else {
		// Queue the message in Redis if the recipient is offline
		s.queueMessage(msg.To, msg)
	}
}

// Queue a message in Redis
func (s *Server) queueMessage(userID string, msg *Message) {
	messageJSON, err := json.Marshal(msg)
	if err != nil {
		s.logger.Errorf("Error marshalling message for user %s: %v", userID, err)
		return
	}
	if err := s.redisClient.RPush(s.ctx, fmt.Sprintf("messages:%s", userID), messageJSON).Err(); err != nil {
		s.logger.Errorf("Error queuing message for user %s: %v", userID, err)
	}
}

// Retrieve queued messages for a user when they reconnect
func (s *Server) retrieveQueuedMessages(userID string, ws *websocket.Conn) {
	messages, err := s.redisClient.LRange(s.ctx, fmt.Sprintf("messages:%s", userID), 0, -1).Result()
	if err != nil {
		s.logger.Errorf("Error retrieving queued messages for user %s: %v", userID, err)
		return
	}

	for _, message := range messages {
		if err := ws.WriteMessage(websocket.TextMessage, []byte(message)); err != nil {
			s.logger.Errorf("Error sending queued message to user %s: %v", userID, err)
			return
		}
	}

	// Clear the queue after sending
	s.redisClient.Del(s.ctx, fmt.Sprintf("messages:%s", userID))
}
