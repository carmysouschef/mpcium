package session

import (
	"github.com/bnb-chain/tss-lib/v2/tss"
	"github.com/fystack/mpcium/pkg/mpc/implement/ecdsa"
	"github.com/fystack/mpcium/pkg/mpc/implement/eddsa"
)

type Session interface {
	Send(msg tss.Message)
	Receive(msg tss.Message)
}

type session struct {
	walletID     string
	participants []string
	threshold    int

	selfPartyID *tss.PartyID
	allPartyIDs []*tss.PartyID
}

type ecdsaSession struct {
	session
	ecdsaParty *ecdsa.ECDSAParty
}

type eddsaSession struct {
	session
	eddsaParty *eddsa.EDDSAParty
}

func NewECDSASession(nodeID string, walletID string, participants []string, selfPartyID *tss.PartyID, allPartyIDs []*tss.PartyID, threshold int) Session {
	ecdsaParty := ecdsa.NewECDSAParty(nodeID)
	return &ecdsaSession{
		session:    session{walletID: walletID, participants: participants, threshold: threshold, selfPartyID: selfPartyID, allPartyIDs: allPartyIDs},
		ecdsaParty: ecdsaParty,
	}
}

func (s *ecdsaSession) Send(msg tss.Message) {
}

func (s *ecdsaSession) Receive(msg tss.Message) {
	if msg.IsBroadcast() {
		s.ecdsaParty.OnMsg(msg)
	} else {
		to := msg.GetTo()
		if to == nil {
			return
		}
		for _, dst := range to {
			if dst.Id != s.selfPartyID.Id {
				s.ecdsaParty.OnMsg(msg)
			}
		}
	}
}

func NewEDDASession(nodeID string, walletID string, participants []string, selfPartyID *tss.PartyID, allPartyIDs []*tss.PartyID, threshold int) Session {
	eddsaParty := eddsa.NewEDDSAParty(nodeID)
	return &eddsaSession{
		session:    session{walletID: walletID, participants: participants, threshold: threshold, selfPartyID: selfPartyID, allPartyIDs: allPartyIDs},
		eddsaParty: eddsaParty,
	}
}

func (s *eddsaSession) Send(msg tss.Message) {
}

func (s *eddsaSession) Receive(msg tss.Message) {
	if msg.IsBroadcast() {
		s.eddsaParty.OnMsg(msg)
	} else {
		to := msg.GetTo()
		if to == nil {
			return
		}
		for _, dst := range to {
			if dst.Id != s.selfPartyID.Id {
				s.eddsaParty.OnMsg(msg)
			}
		}
	}
}
