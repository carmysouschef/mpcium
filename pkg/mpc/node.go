package mpc

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/tss"
	"github.com/fystack/mpcium/pkg/identity"
	"github.com/fystack/mpcium/pkg/keyinfo"
	"github.com/fystack/mpcium/pkg/kvstore"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/fystack/mpcium/pkg/messaging"
	"github.com/fystack/mpcium/pkg/mpc/implement/session"
	"github.com/google/uuid"
)

const (
	PurposeKeygen    string = "keygen"
	PurposeSign      string = "sign"
	PurposeResharing string = "resharing"
)

type Node struct {
	nodeID  string
	peerIDs []string

	pubSub         messaging.PubSub
	direct         messaging.DirectMessaging
	kvstore        kvstore.KVStore
	keyinfoStore   keyinfo.Store
	ecdsaPreParams *keygen.LocalPreParams
	identityStore  identity.Store

	peerRegistry PeerRegistry
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

	preParams, err := loadPreParams()
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
		ecdsaPreParams: preParams,
		peerRegistry:   peerRegistry,
		identityStore:  identityStore,
	}
}

func (n *Node) CreateKeyGenSession(curveType CurveType, walletID string, threshold int, successQueue messaging.MessageQueue) (session.Session, error) {
	if n.peerRegistry.GetReadyPeersCount() < int64(threshold+1) {
		return nil, fmt.Errorf("not enough peers to create gen session! Expected %d, got %d", threshold+1, n.peerRegistry.GetReadyPeersCount())
	}

	readyPeerIDs := n.peerRegistry.GetReadyPeersIncludeSelf()
	selfPartyID, allPartyIDs := n.generatePartyIDs(PurposeKeygen, readyPeerIDs)

	switch curveType {
	case CurveECDSA:
		return session.NewECDSASession(n.nodeID, walletID, readyPeerIDs, selfPartyID, allPartyIDs, threshold), nil
	case CurveEDDSA:
		return session.NewEDDASession(n.nodeID, walletID, readyPeerIDs, selfPartyID, allPartyIDs, threshold), nil
	default:
		return nil, fmt.Errorf("invalid curve type: %s", curveType)
	}
}

// func (n *Node) CreateSigningSession(curveType CurveType, walletID string, threshold int, successQueue messaging.MessageQueue) (ISigningSession, error) {
// 	if n.peerRegistry.GetReadyPeersCount() < int64(threshold+1) {
// 		return nil, fmt.Errorf("not enough peers to create signing session! Expected %d, got %d", threshold+1, n.peerRegistry.GetReadyPeersCount())
// 	}

// 	readyPeerIDs := n.peerRegistry.GetReadyPeersIncludeSelf()
// 	selfPartyID, allPartyIDs := n.generatePartyIDs(PurposeSign, readyPeerIDs)

// 	switch curveType {
// 	case CurveECDSA:
// 		return NewECDSSigningSession(walletID, n.pubSub, n.direct, readyPeerIDs, selfPartyID, allPartyIDs, threshold, n.ecdsaPreParams, n.kvstore, n.keyinfoStore, successQueue, n.identityStore)
// 	case CurveEDDSA:
// 		return NewEDDASigningSession(walletID, n.pubSub, n.direct, readyPeerIDs, selfPartyID, allPartyIDs, threshold, n.kvstore, n.keyinfoStore, successQueue, n.identityStore)
// 	default:
// 		return nil, fmt.Errorf("invalid curve type: %s", curveType)
// 	}
// }

// func (n *Node) CreateResharingSession(curveType CurveType, walletID string, oldThreshold int, newThreshold int, successQueue messaging.MessageQueue) (IResharingSession, error) {
// 	if n.peerRegistry.GetReadyPeersCount() < int64(newThreshold+1) {
// 		return nil, fmt.Errorf("not enough peers to create resharing session! Expected %d, got %d", newThreshold+1, n.peerRegistry.GetReadyPeersCount())
// 	}

// 	readyPeerIDs := n.peerRegistry.GetReadyPeersIncludeSelf()
// 	selfPartyID, allPartyIDs := n.generatePartyIDs(PurposeSign, readyPeerIDs)

// 	switch curveType {
// 	case CurveECDSA:
// 		return NewECDSAResharingSession(walletID, n.pubSub, n.direct, readyPeerIDs, selfPartyID, allPartyIDs, oldThreshold, newThreshold, n.ecdsaPreParams, n.kvstore, n.keyinfoStore, successQueue, n.identityStore)
// 	case CurveEDDSA:
// 		return NewEDDASResharingSession(walletID, n.pubSub, n.direct, readyPeerIDs, selfPartyID, allPartyIDs, oldThreshold, newThreshold, n.kvstore, n.keyinfoStore, successQueue, n.identityStore)
// 	default:
// 		return nil, fmt.Errorf("invalid curve type: %s", curveType)
// 	}
// }

func (n *Node) Close() {
	err := n.peerRegistry.Resign()
	if err != nil {
		logger.Error("Resign failed", err)
	}
}

func (n *Node) generatePartyIDs(purpose string, readyPeerIDs []string) (self *tss.PartyID, all []*tss.PartyID) {
	partyIDs := make([]*tss.PartyID, len(readyPeerIDs))

	for i, peerID := range readyPeerIDs {
		partyID := createPartyID(peerID, purpose)
		partyIDs[i] = partyID

		// Track self party ID when found
		if peerID == n.nodeID {
			self = partyID
		}
	}

	return self, tss.SortPartyIDs(partyIDs, 0)
}

func createPartyID(nodeID string, purpose string) *tss.PartyID {
	partyID := uuid.NewString()
	key := big.NewInt(0).SetBytes([]byte(nodeID + ":" + purpose))
	return tss.NewPartyID(partyID, purpose, key)
}

func loadPreParams() (*keygen.LocalPreParams, error) {
	const preParamsFile = "preparams.json"

	// Try to load from file first
	if data, err := os.ReadFile(preParamsFile); err == nil {
		preParams := new(keygen.LocalPreParams)
		if err := json.Unmarshal(data, preParams); err == nil {
			return preParams, nil
		}
	}

	// If file doesn't exist or is invalid, generate new pre-params
	preParams, err := keygen.GeneratePreParams(1*time.Minute, 8)
	if err != nil {
		return nil, fmt.Errorf("failed to generate pre-params: %w", err)
	}

	// Save to file for future use
	if data, err := json.Marshal(preParams); err == nil {
		if err := os.WriteFile(preParamsFile, data, 0644); err != nil {
			logger.Warn("Failed to save pre-params to file", "error", err)
		}
	}

	return preParams, nil
}
