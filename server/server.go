package server

import (
	"context"
	"encoding/json"
	"fmt"
	"minimal-signal/common"
	"minimal-signal/configs"
	"minimal-signal/protocol/x3dh/alice"
	"net/http"
	"sync"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
)

type Server struct {
	ctx       context.Context
	cancelCtx context.CancelFunc

	redisClient    *redis.Client
	connectedUsers map[connKey]*websocket.Conn
	mutex          *sync.Mutex
	logger         *logrus.Logger

	// WebSocket upgrader settings
	upgrader *websocket.Upgrader
}

type connKey struct {
	from string
	to   string
}

func NewServer(ctx context.Context, redisClient *redis.Client, logger *logrus.Logger) *Server {
	ctx, cancelCtx := context.WithCancel(ctx)
	return &Server{
		ctx:            ctx,
		cancelCtx:      cancelCtx,
		redisClient:    redisClient,
		connectedUsers: make(map[connKey]*websocket.Conn),
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
	fromID := r.URL.Query().Get("from")
	if fromID == "" {
		s.logger.Error("No fromID provided in the query")
		return
	}
	toID := r.URL.Query().Get("to")
	if toID == "" {
		s.logger.Error("No toID provided in the query")
		return
	}

	// Add user to connectedUsers map
	s.mutex.Lock()
	s.connectedUsers[connKey{from: fromID, to: toID}] = ws
	s.mutex.Unlock()
	s.logger.Infof("User %s connected, talking to %s", fromID, toID)

	// Check for queued messages
	s.retrieveQueuedMessages(toID, fromID, ws)

	// Listen for incoming messages
	for {
		_, message, err := ws.ReadMessage()
		if err != nil {
			s.logger.Errorf("Error reading message from user %s: %v", fromID, err)
			break
		}

		var msgObj common.MessageBundle
		if err := json.Unmarshal(message, &msgObj); err != nil {
			s.logger.Errorf("Invalid message format from user %s: %v", fromID, err)
			continue
		}

		// Add the sender's ID to the message
		msgObj.From = fromID
		s.logger.Infof("Received message from user %s: %+v\n", fromID, msgObj)

		s.handleMessage(&msgObj)
	}

	// Remove user from connectedUsers map when they disconnect
	s.mutex.Lock()
	delete(s.connectedUsers, connKey{from: fromID, to: toID})
	s.mutex.Unlock()
	s.logger.Infof("User %s disconnected", fromID)
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
func (s *Server) handleMessage(msg *common.MessageBundle) {
	s.mutex.Lock()
	recipientConn, online := s.connectedUsers[connKey{from: msg.To, to: msg.From}]
	s.mutex.Unlock()

	if online {
		// Send the message directly if the recipient is online
		messageJSON, _ := json.Marshal(msg)
		if err := recipientConn.WriteMessage(websocket.TextMessage, messageJSON); err != nil {
			s.logger.Errorf("Error sending message to user %s: %v", msg.To, err)
		}
	} else {
		// Queue the message in Redis if the recipient is offline
		s.queueMessage(msg)
	}
}

// Queue a message in Redis
func (s *Server) queueMessage(msg *common.MessageBundle) {
	messageJSON, err := json.Marshal(msg)
	if err != nil {
		s.logger.Errorf("Error marshalling message from %s to %s: %v", msg.From, msg.To, err)
		return
	}
	if err := s.redisClient.RPush(s.ctx, fmt.Sprintf(configs.ServerMessageQueueKey, msg.From, msg.To), messageJSON).Err(); err != nil {
		s.logger.Errorf("Error queuing message from %s to %s: %v", msg.From, msg.To, err)
	}
}

// Retrieve queued messages for a user when they reconnect
func (s *Server) retrieveQueuedMessages(from string, to string, ws *websocket.Conn) {
	messages, err := s.redisClient.LRange(s.ctx, fmt.Sprintf(configs.ServerMessageQueueKey, from, to), 0, -1).Result()
	if err != nil {
		s.logger.Errorf("Error retrieving queued messages from %s to %s: %v", from, to, err)
		return
	}

	for _, message := range messages {
		if err := ws.WriteMessage(websocket.TextMessage, []byte(message)); err != nil {
			s.logger.Errorf("Error sending queued message from %s to %s: %v", from, to, err)
			return
		}
	}

	// Clear the queue after sending
	s.redisClient.Del(s.ctx, fmt.Sprintf(configs.ServerMessageQueueKey, from, to))
}

func (s *Server) HandlePostKeys(w http.ResponseWriter, r *http.Request) {
	// Extract userId from the URL query
	vars := mux.Vars(r)
	userID, ok := vars["userID"]
	if !ok {
		s.logger.Error("No userID provided in the query")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Extract the public key from the request body
	var userPublicPrekeyBundle alice.BobPublicPrekeyBundle
	if err := json.NewDecoder(r.Body).Decode(&userPublicPrekeyBundle); err != nil {
		s.logger.Errorf("Error decoding keys for user %s: %v", userID, err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Serialize the struct to JSON before storing in Redis
	data, err := json.Marshal(userPublicPrekeyBundle)
	if err != nil {
		s.logger.Errorf("Error serializing keys for user %s: %v", userID, err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Publish the public key to Redis
	if err := s.redisClient.Set(s.ctx, fmt.Sprintf(configs.ServerUserPubKey, userID), data, 0).Err(); err != nil {
		s.logger.Errorf("Error publishing keys for user %s: %v", userID, err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	s.logger.Infof("Public key published for user %s", userID)
	w.WriteHeader(http.StatusOK)
}

func (s *Server) HandleGetKeys(w http.ResponseWriter, r *http.Request) {
	// Extract userId from the URL query
	vars := mux.Vars(r)
	userID, ok := vars["userID"]
	if !ok {
		s.logger.Error("No userID provided in the query")
		http.Error(w, "No userID provided", http.StatusBadRequest)
		return
	}

	// Get the public key from Redis as a string (JSON)
	data, err := s.redisClient.Get(s.ctx, fmt.Sprintf(configs.ServerUserPubKey, userID)).Result()
	if err != nil {
		s.logger.Errorf("Error retrieving keys for user %s: %v", userID, err)
		http.Error(w, "Error retrieving keys", http.StatusInternalServerError)
		return
	}

	// Deserialize the JSON string back into the struct
	var userPublicPrekeyBundle alice.BobPublicPrekeyBundle
	if err := json.Unmarshal([]byte(data), &userPublicPrekeyBundle); err != nil {
		s.logger.Errorf("Error decoding keys for user %s: %v", userID, err)
		http.Error(w, "Error decoding response", http.StatusInternalServerError)
		return
	}

	s.logger.Infof("Public key retrieved for user %s %+v", userID, userPublicPrekeyBundle)

	// Send the public key to the client
	w.Header().Set("Content-Type", "application/json") // Set JSON content type
	if err := json.NewEncoder(w).Encode(userPublicPrekeyBundle); err != nil {
		s.logger.Errorf("Error encoding keys for user %s: %v", userID, err)
		http.Error(w, "Error encoding response", http.StatusInternalServerError)
		return
	}

	s.logger.Infof("Public key retrieved for user %s", userID)
}
