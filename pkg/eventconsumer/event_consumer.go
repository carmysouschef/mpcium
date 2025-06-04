package eventconsumer

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/fystack/mpcium/pkg/event"
	"github.com/fystack/mpcium/pkg/identity"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/fystack/mpcium/pkg/messaging"
	"github.com/fystack/mpcium/pkg/mpc"
	"github.com/fystack/mpcium/pkg/mpc/node"
	"github.com/fystack/mpcium/pkg/mpc/session"
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

		if err := ec.handleKeygenMessage(&msg); err != nil {
			logger.Error("Failed to handle keygen message", err)
			return
		}
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

		logger.Info("Received signing event", "walletID", msg.WalletID, "keyType", msg.KeyType)

		if err := ec.handleSigningMessage(&msg, natMsg); err != nil {
			logger.Error("Failed to handle signing message", err)
			return
		}
	})

	if err != nil {
		return fmt.Errorf("failed to subscribe to signing events: %w", err)
	}

	ec.signingSub = sub
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

// handleKeygenMessage processes a single keygen message
func (ec *eventConsumer) handleKeygenMessage(msg *types.GenerateKeyMessage) error {
	// Create ECDSA and EDDSA keygen sessions
	ecdsaSession, err := ec.node.CreateSession(mpc.PurposeKeygen, mpc.CurveECDSA, msg.WalletID, ec.defaultThreshold, ec.keygenResultQueue)
	if err != nil {
		return fmt.Errorf("failed to create ECDSA keygen session: %w", err)
	}

	eddsaSession, err := ec.node.CreateSession(mpc.PurposeKeygen, mpc.CurveEDDSA, msg.WalletID, ec.defaultThreshold, ec.keygenResultQueue)
	if err != nil {
		return fmt.Errorf("failed to create EDDSA keygen session: %w", err)
	}

	// Create contexts for sessions
	ecdsaCtx, ecdsaCancel := context.WithTimeout(context.Background(), 30*time.Second)
	eddsaCtx, eddsaCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer ecdsaCancel()
	defer eddsaCancel()

	// Run keygen sessions concurrently
	if err := ec.runKeygenSessions(ecdsaSession, eddsaSession, ecdsaCtx, eddsaCtx, msg.WalletID); err != nil {
		return err
	}

	// Publish success event
	return ec.publishKeygenSuccess(ecdsaSession, eddsaSession, msg.WalletID)
}

// runKeygenSessions runs both ECDSA and EDDSA keygen sessions concurrently
func (ec *eventConsumer) runKeygenSessions(ecdsaSession, eddsaSession session.Session, ecdsaCtx, eddsaCtx context.Context, walletID string) error {
	var wg sync.WaitGroup
	errChan := make(chan error, 2)
	wg.Add(2)

	// Start ECDSA keygen
	go func() {
		defer wg.Done()
		ecdsaSession.Keygen(ecdsaCtx, func(shareData []byte) {
			ecdsaSession.SetShareData(shareData)
			pubKey := ecdsaSession.GetPubKey()
			logger.Debug("ECDSA public key", "key", pubKey)
			if err := ec.node.SaveKeyData("keygen", mpc.CurveECDSA, walletID, shareData, ec.defaultThreshold); err != nil {
				errChan <- fmt.Errorf("failed to save ECDSA key data: %w", err)
			}
		})
	}()

	// Start EDDSA keygen
	go func() {
		defer wg.Done()
		eddsaSession.Keygen(eddsaCtx, func(shareData []byte) {
			eddsaSession.SetShareData(shareData)
			pubKey := eddsaSession.GetPubKey()
			logger.Debug("EDDSA public key", "key", pubKey)
			if err := ec.node.SaveKeyData("keygen", mpc.CurveEDDSA, walletID, shareData, ec.defaultThreshold); err != nil {
				errChan <- fmt.Errorf("failed to save EDDSA key data: %w", err)
			}
		})
	}()

	// Monitor error channels
	go func() {
		for err := range ecdsaSession.Err() {
			logger.Error("ECDSA keygen error", err)
		}
		for err := range eddsaSession.Err() {
			logger.Error("EDDSA keygen error", err)
		}
	}()

	// Wait for completion
	wg.Wait()
	close(errChan)

	// Check for errors
	for err := range errChan {
		if err != nil {
			return err
		}
	}

	return nil
}

// publishKeygenSuccess publishes the keygen success event
func (ec *eventConsumer) publishKeygenSuccess(ecdsaSession, eddsaSession session.Session, walletID string) error {
	successEvent := mpc.KeygenSuccessEvent{
		WalletID:    walletID,
		ECDSAPubKey: ecdsaSession.GetPubKey(),
		EDDSAPubKey: eddsaSession.GetPubKey(),
	}

	successEventBytes, err := json.Marshal(successEvent)
	if err != nil {
		return fmt.Errorf("failed to marshal success event: %w", err)
	}

	err = ec.keygenResultQueue.Enqueue(
		fmt.Sprintf(mpc.TypeGenerateWalletSuccess, walletID),
		successEventBytes,
		&messaging.EnqueueOptions{
			IdempotententKey: fmt.Sprintf(mpc.TypeGenerateWalletSuccess, walletID),
		},
	)
	if err != nil {
		return fmt.Errorf("failed to publish key generation success message: %w", err)
	}

	return nil
}

// handleSigningMessage processes a single signing message
func (ec *eventConsumer) handleSigningMessage(msg *types.SignTxMessage, natMsg *nats.Msg) error {
	// Check for duplicate session
	if ec.checkDuplicateSession(msg.WalletID, msg.TxID) {
		natMsg.Term()
		return nil
	}

	// Create signing session
	session, err := ec.createSigningSession(msg)
	if err != nil {
		ec.handleSigningSessionError(
			msg.WalletID,
			msg.TxID,
			msg.NetworkInternalCode,
			err,
			"Failed to create signing session",
			natMsg,
		)
		return err
	}

	// Mark session as active
	ec.addSession(msg.WalletID, msg.TxID)

	// Start signing process
	return ec.startSigningProcess(session, msg, natMsg)
}

// createSigningSession creates a new signing session based on key type
func (ec *eventConsumer) createSigningSession(msg *types.SignTxMessage) (session.Session, error) {
	switch msg.KeyType {
	case types.KeyTypeSecp256k1:
		return ec.node.CreateSession(mpc.PurposeSign, mpc.CurveECDSA, msg.WalletID, ec.defaultThreshold, ec.keygenResultQueue)
	case types.KeyTypeEd25519:
		return ec.node.CreateSession(mpc.PurposeSign, mpc.CurveEDDSA, msg.WalletID, ec.defaultThreshold, ec.keygenResultQueue)
	default:
		return nil, fmt.Errorf("invalid key type: %s", msg.KeyType)
	}
}

// startSigningProcess starts the signing process and handles the result
func (ec *eventConsumer) startSigningProcess(session session.Session, msg *types.SignTxMessage, natMsg *nats.Msg) error {
	ctx, done := context.WithTimeout(context.Background(), 30*time.Second)

	// Start signing in background
	go session.Sign(ctx, msg.Tx, func(signature []byte) {
		done()
		logger.Info("Signing result", "signature", signature)

		// Handle reply if needed
		if natMsg.Reply != "" {
			if err := ec.pubsub.Publish(natMsg.Reply, signature); err != nil {
				logger.Error("Failed to publish reply", err)
			} else {
				logger.Info("Reply to the original message", "reply", natMsg.Reply)
			}
		}

		err := ec.signingResultQueue.Enqueue(event.SigningResultCompleteTopic, signature, &messaging.EnqueueOptions{
			IdempotententKey: msg.TxID,
		})
		if err != nil {
			session.Err() <- err
		}

		// Cleanup session
		ec.removeSession(msg.WalletID, msg.TxID)
	})

	// Monitor error channel
	go ec.monitorSigningErrors(session, msg, natMsg)

	return nil
}

// monitorSigningErrors monitors the session's error channel
func (ec *eventConsumer) monitorSigningErrors(session session.Session, msg *types.SignTxMessage, natMsg *nats.Msg) {
	for err := range session.Err() {
		if err != nil {
			ec.handleSigningSessionError(
				msg.WalletID,
				msg.TxID,
				msg.NetworkInternalCode,
				err,
				"Failed to sign tx",
				natMsg,
			)
			return
		}
	}
}

func (ec *eventConsumer) handleSigningSessionError(walletID, txID, NetworkInternalCode string, err error, errMsg string, natMsg *nats.Msg) {
	logger.Error("Signing session error", err, "walletID", walletID, "txID", txID, "error", errMsg)
	signingResult := event.SigningResultEvent{
		ResultType:          event.SigningResultTypeError,
		NetworkInternalCode: NetworkInternalCode,
		WalletID:            walletID,
		TxID:                txID,
		ErrorReason:         errMsg,
	}

	signingResultBytes, err := json.Marshal(signingResult)
	if err != nil {
		logger.Error("Failed to marshal signing result event", err)
		return
	}

	natMsg.Ack()
	err = ec.signingResultQueue.Enqueue(event.SigningResultCompleteTopic, signingResultBytes, &messaging.EnqueueOptions{
		IdempotententKey: txID,
	})
	if err != nil {
		logger.Error("Failed to publish signing result event", err)
		return
	}
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

// markSessionAsActive marks a session as active with the current timestamp
func (ec *eventConsumer) addSession(walletID, txID string) {
	sessionID := fmt.Sprintf("%s-%s", walletID, txID)
	ec.sessionsLock.Lock()
	ec.activeSessions[sessionID] = time.Now()
	ec.sessionsLock.Unlock()
}

// Remove a session from tracking
func (ec *eventConsumer) removeSession(walletID, txID string) {
	sessionID := fmt.Sprintf("%s-%s", walletID, txID)
	ec.sessionsLock.Lock()
	delete(ec.activeSessions, sessionID)
	ec.sessionsLock.Unlock()
}

// checkAndTrackSession checks if a session already exists and tracks it if new.
// Returns true if the session is a duplicate.
func (ec *eventConsumer) checkDuplicateSession(walletID, txID string) bool {
	sessionID := fmt.Sprintf("%s-%s", walletID, txID)

	// Check for duplicate
	ec.sessionsLock.RLock()
	_, isDuplicate := ec.activeSessions[sessionID]
	ec.sessionsLock.RUnlock()

	if isDuplicate {
		logger.Info("Duplicate signing request detected", "walletID", walletID, "txID", txID)
		return true
	}

	return false
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
