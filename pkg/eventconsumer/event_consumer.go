package eventconsumer

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/fystack/mpcium/pkg/identity"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/fystack/mpcium/pkg/messaging"
	"github.com/fystack/mpcium/pkg/mpc"
	"github.com/fystack/mpcium/pkg/mpc/node"
	"github.com/fystack/mpcium/pkg/types"
	"github.com/nats-io/nats.go"
	"github.com/spf13/viper"
)

const (
	MPCGenerateEvent  = "mpc:generate" // keygen event
	MPCSignEvent      = "mpc:sign"
	MPCResharingEvent = "mpc:reshare"
)

const (
	cleanupInterval = 5 * time.Minute
	sessionTimeout  = 30 * time.Minute
)

type EventConsumer interface {
	Run()
	Close() error
}

type eventConsumer struct {
	node             *node.Node
	pubsub           messaging.PubSub
	defaultThreshold int

	keygenResultQueue    messaging.MessageQueue
	signingResultQueue   messaging.MessageQueue
	resharingResultQueue messaging.MessageQueue

	keygenSub    messaging.Subscription
	signingSub   messaging.Subscription
	resharingSub messaging.Subscription

	identityStore identity.Store

	// Track active sessions with timestamps for cleanup
	activeSessions  map[string]time.Time // Maps "walletID-txID" to creation time
	sessionsLock    sync.RWMutex
	cleanupInterval time.Duration // How often to run cleanup
	sessionTimeout  time.Duration // How long before a session is considered stale
	cleanupStopChan chan struct{} // Signal to stop cleanup goroutine
}

func NewEventConsumer(
	node *node.Node,
	pubsub messaging.PubSub,
	keygenResultQueue messaging.MessageQueue,
	signingResultQueue messaging.MessageQueue,
	resharingResultQueue messaging.MessageQueue,
	identityStore identity.Store,
) EventConsumer {
	ec := &eventConsumer{
		node:                 node,
		pubsub:               pubsub,
		keygenResultQueue:    keygenResultQueue,
		signingResultQueue:   signingResultQueue,
		resharingResultQueue: resharingResultQueue,
		activeSessions:       make(map[string]time.Time),
		cleanupInterval:      cleanupInterval,
		sessionTimeout:       sessionTimeout,
		cleanupStopChan:      make(chan struct{}),
		defaultThreshold:     viper.GetInt("mpc_threshold"),
		identityStore:        identityStore,
	}

	// Start background cleanup goroutine
	go ec.sessionCleanupRoutine()

	return ec
}

func (ec *eventConsumer) Run() {
	err := ec.consumeKeyGenerationEvent()
	if err != nil {
		log.Fatal("Failed to consume key generation event", err)
	}

	err = ec.consumeTxSigningEvent()
	if err != nil {
		log.Fatal("Failed to consume tx signing event", err)
	}

	err = ec.consumeResharingEvent()
	if err != nil {
		log.Fatal("Failed to consume resharing event", err)
	}

	logger.Info("MPC Event consumer started...!")
}

func (ec *eventConsumer) consumeKeyGenerationEvent() error {
	sub, err := ec.pubsub.Subscribe(MPCGenerateEvent, func(natMsg *nats.Msg) {
		if natMsg == nil || len(natMsg.Data) == 0 {
			logger.Warn("Received empty key generation message")
			return
		}

		var msg types.GenerateKeyMessage
		if err := json.Unmarshal(natMsg.Data, &msg); err != nil {
			logger.Error("Failed to unmarshal key generation message", err)
			return
		}
		logger.Info("Received key generation event", "walletID", msg.WalletID)

		if err := ec.identityStore.VerifyInitiatorMessage(&msg); err != nil {
			logger.Error("Failed to verify initiator message", err)
			return
		}

		// Create ECDSA and EDDSA keygen sessions
		fmt.Printf("About to create ECDSA session for wallet %s\n", msg.WalletID)
		ecdsaSession, err := ec.node.CreateSession(mpc.CurveECDSA, msg.WalletID, ec.defaultThreshold, ec.keygenResultQueue)
		if err != nil {
			logger.Error("Failed to create ECDSA keygen session", err)
			return
		}

		fmt.Printf("About to create EDDSA session for wallet %s\n", msg.WalletID)
		eddsaSession, err := ec.node.CreateSession(mpc.CurveEDDSA, msg.WalletID, ec.defaultThreshold, ec.keygenResultQueue)
		if err != nil {
			logger.Error("Failed to create EDDSA keygen session", err)
			return
		}

		// Create separate contexts for each session
		ecdsaCtx, ecdsaCancel := context.WithTimeout(context.Background(), 30*time.Second)
		eddsaCtx, eddsaCancel := context.WithTimeout(context.Background(), 30*time.Second)

		var wg sync.WaitGroup
		wg.Add(2)

		// Start ECDSA keygen
		go func() {
			defer wg.Done()
			defer ecdsaCancel()
			ecdsaSession.Keygen(ecdsaCtx, func(shareData []byte) {
				ecdsaSession.SetShareData(shareData)
				pubKey := ecdsaSession.GetPubKey()
				fmt.Printf("ECDSA public key: %x\n", pubKey)
				ec.node.SaveKeyData("keygen", mpc.CurveECDSA, msg.WalletID, pubKey, ec.defaultThreshold)
			})
		}()

		// Start EDDSA keygen
		go func() {
			defer wg.Done()
			defer eddsaCancel()
			eddsaSession.Keygen(eddsaCtx, func(shareData []byte) {
				eddsaSession.SetShareData(shareData)
				pubKey := eddsaSession.GetPubKey()
				fmt.Printf("EDDSA public key: %x\n", pubKey)
				ec.node.SaveKeyData("keygen", mpc.CurveEDDSA, msg.WalletID, pubKey, ec.defaultThreshold)
			})
		}()

		// Wait for both operations to complete
		wg.Wait()

	})

	if err != nil {
		return fmt.Errorf("failed to subscribe to key generation events: %w", err)
	}

	ec.keygenSub = sub
	return nil
}

func (ec *eventConsumer) consumeTxSigningEvent() error {
	sub, err := ec.pubsub.Subscribe(MPCSignEvent, func(natMsg *nats.Msg) {
		if natMsg == nil || len(natMsg.Data) == 0 {
			logger.Warn("Received empty signing message")
			return
		}

		var msg types.SignTxMessage
		if err := json.Unmarshal(natMsg.Data, &msg); err != nil {
			logger.Error("Failed to unmarshal signing message", err)
			return
		}

		if err := ec.identityStore.VerifyInitiatorMessage(&msg); err != nil {
			logger.Error("Failed to verify initiator message", err)
			return
		}

		// Check duplicate session
		// Create signing session
		// Start listening for messages
		// Start signing
		// Wait for session to complete
		// Publish result
		// Cleanup session
	})

	ec.signingSub = sub
	if err != nil {
		return err
	}

	return nil
}

func (ec *eventConsumer) consumeResharingEvent() error {
	sub, err := ec.pubsub.Subscribe(MPCResharingEvent, func(natMsg *nats.Msg) {
		if natMsg == nil || len(natMsg.Data) == 0 {
			logger.Warn("Received empty resharing message")
			return
		}

		var msg types.ResharingMessage
		if err := json.Unmarshal(natMsg.Data, &msg); err != nil {
			logger.Error("Failed to unmarshal resharing message", err)
			return
		}
		logger.Info("Received resharing event", "walletID", msg.WalletID, "newThreshold", msg.NewThreshold)

		if err := ec.identityStore.VerifyInitiatorMessage(&msg); err != nil {
			logger.Error("Failed to verify initiator message", err)
			return
		}

		// Check duplicate session
		// Create resharing session
		// Start listening for messages
		// Start resharing
		// Wait for session to complete
		// Publish result
		// Cleanup session
	})

	ec.resharingSub = sub
	if err != nil {
		return err
	}
	return nil
}

// Add a cleanup routine that runs periodically
func (ec *eventConsumer) sessionCleanupRoutine() {
	ticker := time.NewTicker(ec.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ec.cleanupStaleSessions()
		case <-ec.cleanupStopChan:
			return
		}
	}
}

// Cleanup stale sessions
func (ec *eventConsumer) cleanupStaleSessions() {
	now := time.Now()
	ec.sessionsLock.Lock()
	defer ec.sessionsLock.Unlock()

	for sessionID, creationTime := range ec.activeSessions {
		if now.Sub(creationTime) > ec.sessionTimeout {
			logger.Info("Cleaning up stale session", "sessionID", sessionID, "age", now.Sub(creationTime))
			delete(ec.activeSessions, sessionID)
		}
	}
}

// Close and clean up
func (ec *eventConsumer) Close() error {
	// Signal cleanup routine to stop
	close(ec.cleanupStopChan)

	err := ec.keygenSub.Unsubscribe()
	if err != nil {
		return err
	}
	err = ec.signingSub.Unsubscribe()
	if err != nil {
		return err
	}

	return nil
}
