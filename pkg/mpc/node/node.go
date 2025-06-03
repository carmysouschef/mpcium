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
func (n *Node) CreateSession(curveType mpc.CurveType, walletID string, threshold int, successQueue messaging.MessageQueue) (session.Session, error) {
	if n.peerRegistry.GetReadyPeersCount() < int64(threshold+1) {
		return nil, fmt.Errorf("not enough peers to create gen session! Expected %d, got %d", threshold+1, n.peerRegistry.GetReadyPeersCount())
	}

	readyPeerIDs := n.peerRegistry.GetReadyPeersIncludeSelf()
	selfPartyID, allPartyIDs := n.generatePartyIDs(PurposeKeygen, readyPeerIDs)
	topicComposer := NewTopicComposer(PurposeKeygen, string(curveType), walletID)
	sender := n.createSender(walletID, *topicComposer, allPartyIDs)

	switch curveType {
	case mpc.CurveECDSA:
		ecdsaParty := session.NewECDSAParty(selfPartyID)
		ecdsaParty.Init(allPartyIDs, threshold, *n.ecdsaPreParams, sender)
		// Handle messages in a separate goroutine
		go n.receiveMessages(ecdsaParty, *topicComposer)
		return ecdsaParty, nil

	case mpc.CurveEDDSA:
		eddsaParty := session.NewEDDSAParty(selfPartyID)
		eddsaParty.Init(allPartyIDs, threshold, sender)
		// Handle messages in a separate goroutine
		go n.receiveMessages(eddsaParty, *topicComposer)
		return eddsaParty, nil
	default:
		return nil, fmt.Errorf("invalid curve type: %s", curveType)
	}

}

// Create a resharing session
func (n *Node) CreateResharingSession(curveType mpc.CurveType, walletID string, oldThreshold, newThreshold int, successQueue messaging.MessageQueue) (session.Session, error) {
	if n.peerRegistry.GetReadyPeersCount() < int64(newThreshold+1) {
		return nil, fmt.Errorf("not enough peers to create resharing session! Expected %d, got %d", newThreshold+1, n.peerRegistry.GetReadyPeersCount())
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

	return nil
}

// Resign the node from the peer registry
func (n *Node) Close() {
	if err := n.peerRegistry.Resign(); err != nil {
		logger.Error("Resign failed", err)
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
