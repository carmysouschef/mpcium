package mpc

import (
	"bytes"
	"fmt"
	"math/big"
	"time"

	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/tss"
	"github.com/cryptoniumX/mpcium/pkg/identity"
	"github.com/cryptoniumX/mpcium/pkg/keyinfo"
	"github.com/cryptoniumX/mpcium/pkg/kvstore"
	"github.com/cryptoniumX/mpcium/pkg/logger"
	"github.com/cryptoniumX/mpcium/pkg/messaging"
	"github.com/google/uuid"
)

const (
	PurposeKeygen string = "keygen"
	PurposeSign   string = "sign"
)

type ID string

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

func CreatePartyID(nodeID string, label string) *tss.PartyID {
	partyID := uuid.NewString()
	key := big.NewInt(0).SetBytes([]byte(nodeID))
	return tss.NewPartyID(partyID, label, key)
}

func PartyIDToNodeID(partyID *tss.PartyID) string {
	return string(partyID.KeyInt().Bytes())
}

func ComparePartyIDs(x, y *tss.PartyID) bool {
	return bytes.Equal(x.KeyInt().Bytes(), y.KeyInt().Bytes())
}

func ComposeReadyKey(nodeID string) string {
	return fmt.Sprintf("ready/%s", nodeID)
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
	preParams, err := keygen.GeneratePreParams(5 * time.Minute)
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

func (p *Node) ID() string {
	return p.nodeID
}

func composeReadyTopic(nodeID string) string {
	return fmt.Sprintf("%s-%s", nodeID, "ready")
}

func (p *Node) CreateKeyGenSession(walletID string, threshold int, successQueue messaging.MessageQueue) (*KeygenSession, error) {
	if p.peerRegistry.GetReadyPeersCount() < int64(threshold+1) {
		return nil, fmt.Errorf("Not enough peers to create gen session! Expected %d, got %d", threshold+1, p.peerRegistry.GetReadyPeersCount())
	}

	readyPeerIDs := p.peerRegistry.GetReadyPeersIncludeSelf()
	selfPartyID, allPartyIDs := p.generatePartyIDs(PurposeKeygen, readyPeerIDs)
	session := NewKeygenSession(
		walletID,
		p.pubSub,
		p.direct,
		readyPeerIDs,
		selfPartyID,
		allPartyIDs,
		threshold,
		p.ecdsaPreParams,
		p.kvstore,
		p.keyinfoStore,
		successQueue,
		p.identityStore,
	)
	return session, nil
}

func (p *Node) CreateEDDSAKeyGenSession(walletID string, threshold int, successQueue messaging.MessageQueue) (*EDDSAKeygenSession, error) {
	if p.peerRegistry.GetReadyPeersCount() < int64(threshold+1) {
		return nil, fmt.Errorf("Not enough peers to create gen session! Expected %d, got %d", threshold+1, p.peerRegistry.GetReadyPeersCount())
	}

	readyPeerIDs := p.peerRegistry.GetReadyPeersIncludeSelf()
	selfPartyID, allPartyIDs := p.generatePartyIDs(PurposeKeygen, readyPeerIDs)
	session := NewEDDSAKeygenSession(
		walletID,
		p.pubSub,
		p.direct,
		readyPeerIDs,
		selfPartyID,
		allPartyIDs,
		threshold,
		p.kvstore,
		p.keyinfoStore,
		successQueue,
		p.identityStore,
	)
	return session, nil
}

func (p *Node) CreateSigningSession(
	walletID string,
	txID string,
	networkInternalCode string,
	threshold int,
	resultQueue messaging.MessageQueue,
) (*SigningSession, error) {
	readyPeerIDs := p.peerRegistry.GetReadyPeersIncludeSelf()
	selfPartyID, allPartyIDs := p.generatePartyIDs(PurposeKeygen, readyPeerIDs)
	session := NewSigningSession(
		walletID,
		txID,
		networkInternalCode,
		p.pubSub,
		p.direct,
		readyPeerIDs,
		selfPartyID,
		allPartyIDs,
		threshold,
		p.ecdsaPreParams,
		p.kvstore,
		p.keyinfoStore,
		resultQueue,
		p.identityStore,
	)
	return session, nil
}

func (p *Node) CreateEDDSASigningSession(
	walletID string,
	txID string,
	networkInternalCode string,
	threshold int,
	resultQueue messaging.MessageQueue,
) (*EDDSASigningSession, error) {
	readyPeerIDs := p.peerRegistry.GetReadyPeersIncludeSelf()
	selfPartyID, allPartyIDs := p.generatePartyIDs(PurposeKeygen, readyPeerIDs)
	session := NewEDDSASigningSession(
		walletID,
		txID,
		networkInternalCode,
		p.pubSub,
		p.direct,
		readyPeerIDs,
		selfPartyID,
		allPartyIDs,
		threshold,
		p.kvstore,
		p.keyinfoStore,
		resultQueue,
		p.identityStore,
	)
	return session, nil
}

func (p *Node) generatePartyIDs(purpose string, readyPeerIDs []string) (self *tss.PartyID, all []*tss.PartyID) {
	var selfPartyID *tss.PartyID
	partyIDs := make([]*tss.PartyID, len(readyPeerIDs))
	for i, peerID := range readyPeerIDs {
		if peerID == p.nodeID {
			selfPartyID = CreatePartyID(peerID, purpose)
			partyIDs[i] = selfPartyID
		} else {
			partyIDs[i] = CreatePartyID(peerID, purpose)
		}
	}
	allPartyIDs := tss.SortPartyIDs(partyIDs, 0)
	return selfPartyID, allPartyIDs
}

func (p *Node) Close() {
	err := p.peerRegistry.Resign()
	if err != nil {
		logger.Error("Resign failed", err)
	}
}
