package node

import (
	"fmt"
	"sync"

	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/tss"
	"github.com/fystack/mpcium/pkg/identity"
	"github.com/fystack/mpcium/pkg/keyinfo"
	"github.com/fystack/mpcium/pkg/kvstore"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/fystack/mpcium/pkg/messaging"
	"github.com/fystack/mpcium/pkg/mpc"
	"github.com/fystack/mpcium/pkg/mpc/session"
	"github.com/fystack/mpcium/pkg/types"
	"github.com/nats-io/nats.go"
)

const (
	PurposeKeygen    = "keygen"
	PurposeSign      = "sign"
	PurposeResharing = "resharing"
	maxWorkers       = 5
)

type Node struct {
	nodeID         string
	peerIDs        []string
	pubSub         messaging.PubSub
	direct         messaging.DirectMessaging
	kvstore        kvstore.KVStore
	keyinfoStore   keyinfo.Store
	identityStore  identity.Store
	ecdsaPreParams *keygen.LocalPreParams
	peerRegistry   PeerRegistry
}

func NewNode(
	nodeID string,
	peerIDs []string,
	pubSub messaging.PubSub,
	direct messaging.DirectMessaging,
	kvstore kvstore.KVStore,
	keyinfoStore keyinfo.Store,
	peerRegistry PeerRegistry,
	identityStore identity.Store,
) *Node {
	ecdsaPreParams, err := loadPreParams()
	if err != nil {
		logger.Fatal("Generate pre params failed", err)
	}
	logger.Info("Starting new node, preparams is generated successfully!")

	go peerRegistry.WatchPeersReady()

	return &Node{
		nodeID:         nodeID,
		peerIDs:        peerIDs,
		pubSub:         pubSub,
		direct:         direct,
		kvstore:        kvstore,
		keyinfoStore:   keyinfoStore,
		peerRegistry:   peerRegistry,
		identityStore:  identityStore,
		ecdsaPreParams: ecdsaPreParams,
	}
}

// Create a keygen/sign session
func (n *Node) CreateSession(purpose string, curveType mpc.CurveType, walletID string, threshold int, successQueue messaging.MessageQueue) (session.Session, error) {
	// Validate peer count
	if err := n.validatePeerCount(purpose, threshold); err != nil {
		return nil, err
	}

	// Setup session parameters
	selfPartyID, allPartyIDs, topicComposer, sender := n.setupSessionParams(purpose, curveType, walletID)

	// Handle purpose-specific logic
	var keyData []byte
	var err error
	switch purpose {
	case PurposeKeygen:
		if err := n.handleKeygenPurpose(topicComposer, walletID); err != nil {
			return nil, err
		}
	case PurposeSign:
		if keyData, err = n.handleSignPurpose(topicComposer, walletID); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("invalid purpose: %s", purpose)
	}

	// Create and initialize party
	party, err := n.createParty(curveType, selfPartyID, allPartyIDs, threshold, sender, purpose, keyData)
	if err != nil {
		return nil, err
	}

	// Start message handling in background
	go n.receiveMessages(party, *topicComposer)

	logger.Info("Created new session",
		"purpose", purpose,
		"curveType", curveType,
		"walletID", walletID,
		"threshold", threshold,
		"partyID", selfPartyID.Id)

	return party, nil
}

// Create a resharing session
func (n *Node) CreateResharingSession(curveType mpc.CurveType, walletID string, oldThreshold, newThreshold int, successQueue messaging.MessageQueue) (session.Session, error) {
	// Validate peer count
	if err := n.validatePeerCount(PurposeResharing, newThreshold); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("resharing not yet implemented for curve type: %s", curveType)
}

func (n *Node) SaveKeyData(purpose string, curveType mpc.CurveType, walletID string, keyData []byte, threshold int) error {
	topicComposer := NewTopicComposer(purpose, string(curveType), walletID)

	err := n.kvstore.Put(topicComposer.ComposeKeyInfoTopic(), keyData)
	if err != nil {
		logger.Error("Failed to save key", err, "walletID", walletID)
		return err
	}

	keyInfo := keyinfo.KeyInfo{
		ParticipantPeerIDs: n.peerRegistry.GetReadyPeersIncludeSelf(),
		Threshold:          threshold,
	}

	err = n.keyinfoStore.Save(topicComposer.ComposeKeyInfoTopic(), &keyInfo)
	if err != nil {
		logger.Error("Failed to save keyinfo", err, "walletID", walletID)
		return err
	}
	logger.Info("Key data saved", "key", topicComposer.ComposeKeyInfoTopic())
	return nil
}

// Resign the node from the peer registry
func (n *Node) Close() {
	if err := n.peerRegistry.Resign(); err != nil {
		logger.Error("Resign failed", err)
	}
}

// validatePeerCount checks if there are enough peers for the session
func (n *Node) validatePeerCount(purpose string, threshold int) error {
	readyCount := n.peerRegistry.GetReadyPeersCount()
	if readyCount < int64(threshold+1) {
		return fmt.Errorf("not enough peers for %s session: need %d, have %d",
			purpose, threshold+1, readyCount)
	}
	return nil
}

// setupSessionParams initializes the basic session parameters
func (n *Node) setupSessionParams(purpose string, curveType mpc.CurveType, walletID string) (*tss.PartyID, tss.SortedPartyIDs, *TopicComposer, session.Sender) {
	readyPeerIDs := n.peerRegistry.GetReadyPeersIncludeSelf()
	selfPartyID, allPartyIDs := n.generatePartyIDs(purpose, readyPeerIDs)
	topicComposer := NewTopicComposer(purpose, string(curveType), walletID)
	sender := n.createSender(walletID, *topicComposer, allPartyIDs)
	return selfPartyID, allPartyIDs, topicComposer, sender
}

// handleKeygenPurpose handles keygen-specific logic
func (n *Node) handleKeygenPurpose(topicComposer *TopicComposer, walletID string) error {
	if keyInfo, _ := n.keyinfoStore.Get(topicComposer.ComposeKeyInfoTopic()); keyInfo != nil {
		return fmt.Errorf("key already exists for wallet %s", walletID)
	}
	return nil
}

// handleSignPurpose handles sign-specific logic
func (n *Node) handleSignPurpose(topicComposer *TopicComposer, walletID string) ([]byte, error) {
	keyData, err := n.kvstore.Get(topicComposer.ComposeKeyInfoTopic())
	if err != nil {
		return nil, fmt.Errorf("failed to get key data: %w", err)
	}
	if keyData == nil {
		return nil, fmt.Errorf("key data not found for wallet %s", walletID)
	}
	return keyData, nil
}

// createParty creates and initializes a party based on curve type
func (n *Node) createParty(curveType mpc.CurveType, selfPartyID *tss.PartyID, allPartyIDs tss.SortedPartyIDs, threshold int, sender session.Sender, purpose string, keyData []byte) (session.Session, error) {
	switch curveType {
	case mpc.CurveECDSA:
		party := session.NewECDSAParty(selfPartyID)
		party.Init(allPartyIDs, threshold, *n.ecdsaPreParams, sender)
		if purpose == PurposeSign {
			party.SetShareData(keyData)
		}
		return party, nil

	case mpc.CurveEDDSA:
		party := session.NewEDDSAParty(selfPartyID)
		party.Init(allPartyIDs, threshold, sender)
		if purpose == PurposeSign {
			party.SetShareData(keyData)
		}
		return party, nil

	default:
		return nil, fmt.Errorf("invalid curve type: %s", curveType)
	}
}

// Receive messages from other parties
func (n *Node) receiveMessages(party session.Session, topicComposer TopicComposer) {
	defer func() {
		if r := recover(); r != nil {
			logger.Error("Recovered from panic in receiveMessages", fmt.Errorf("%v", r))
		}
	}()

	subscribe := func() {
		if _, err := n.pubSub.Subscribe(topicComposer.ComposeBroadcastTopic(), func(msg *nats.Msg) {
			n.handleMessage(party, msg.Data)
		}); err != nil {
			logger.Error("Failed to subscribe to broadcast topic", err)
		}
	}

	listen := func() {
		if _, err := n.direct.Listen(topicComposer.ComposeDirectTopic(n.nodeID), func(data []byte) {
			n.handleMessage(party, data)
		}); err != nil {
			logger.Error("Failed to listen for direct messages", err)
		}
	}

	go subscribe()
	go listen()
}

// Handle the message from other parties
func (n *Node) handleMessage(party session.Session, data []byte) {
	tssMsg, err := n.unpackTssMessage(data)
	if err != nil {
		logger.Error("Failed to unpack tss message", err)
		return
	}
	// Push message to In channel of the party
	party.OnMsg(*tssMsg)
}

// Create a sender function that will be used to send messages to the party
func (n *Node) createSender(walletID string, topicComposer TopicComposer, allPartyIDs []*tss.PartyID) session.Sender {
	nodeToParty := make(map[string]*tss.PartyID, len(allPartyIDs))
	for _, partyID := range allPartyIDs {
		nodeToParty[partyToNodeID(partyID)] = partyID
	}

	return func(msg tss.Message) {
		data, routing, err := msg.WireBytes()
		if err != nil {
			logger.Error("Failed to get wire bytes", err)
			return
		}

		tssMsg := types.NewTssMessage(walletID, data, routing.IsBroadcast, routing.From, routing.To)
		tssMsg.Signature, err = n.identityStore.SignMessage(&tssMsg)
		if err != nil {
			logger.Error("Failed to sign message", err)
			return
		}

		packedMsg, err := types.MarshalTssMessage(&tssMsg)
		if err != nil {
			logger.Error("Failed to marshal tss message", err)
			return
		}

		if routing.IsBroadcast && len(routing.To) == 0 {
			if err := n.pubSub.Publish(topicComposer.ComposeBroadcastTopic(), packedMsg); err != nil {
				logger.Error("Failed to publish message", err)
			}
			return
		}

		var wg sync.WaitGroup
		sem := make(chan struct{}, maxWorkers)
		// Send messages to all parties in the routing table
		for _, to := range routing.To {
			wg.Add(1)
			sem <- struct{}{}
			go func(to *tss.PartyID) {
				defer wg.Done()
				defer func() { <-sem }()
				nodeID := partyToNodeID(to)
				if err := n.direct.Send(topicComposer.ComposeDirectTopic(nodeID), packedMsg); err != nil {
					logger.Error("Failed to send direct message", err)
				}
			}(to)
		}
		wg.Wait()
	}
}

// Generate party IDs for the purpose and ready peer IDs
func (n *Node) generatePartyIDs(purpose string, readyPeerIDs []string) (*tss.PartyID, []*tss.PartyID) {
	partyIDs := make([]*tss.PartyID, len(readyPeerIDs))
	var self *tss.PartyID

	for i, peerID := range readyPeerIDs {
		pid := createPartyID(peerID, purpose)
		partyIDs[i] = pid
		if peerID == n.nodeID {
			self = pid
		}
	}
	return self, tss.SortPartyIDs(partyIDs, 0)
}

// Unpack the tss message from the raw message
func (n *Node) unpackTssMessage(rawMsg []byte) (*types.TssMessage, error) {
	tssMsg, err := types.UnmarshalTssMessage(rawMsg)
	if err != nil {
		return nil, err
	}
	if err := n.identityStore.VerifyMessage(tssMsg); err != nil {
		return nil, err
	}
	return tssMsg, nil
}
