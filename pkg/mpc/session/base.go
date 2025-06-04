package session

import (
	"crypto/elliptic"
	"log"
	"math/big"

	"github.com/bnb-chain/tss-lib/v2/tss"
	"github.com/fystack/mpcium/pkg/types"
)

const (
	defaultChanSize = 1000
)

type Sender func(msg tss.Message)

type BaseParty struct {
	PartyID       *tss.PartyID
	Params        *tss.Parameters
	ReshareParams *tss.ReSharingParameters
	In            chan types.TssMessage
	Out           chan tss.Message
	ErrChan       chan error
	closeChan     chan struct{}
	sender        Sender
	curve         elliptic.Curve
}

func NewBaseParty(partyID *tss.PartyID) *BaseParty {
	return &BaseParty{
		PartyID:   partyID,
		In:        make(chan types.TssMessage, defaultChanSize),
		Out:       make(chan tss.Message, defaultChanSize),
		ErrChan:   make(chan error, defaultChanSize),
		closeChan: make(chan struct{}),
	}
}

// Init initializes the party with basic parameters
func (p *BaseParty) Init(sortedPartyIDs tss.SortedPartyIDs, threshold int, sender Sender) {
	// Update the partyID index
	ctx := tss.NewPeerContext(sortedPartyIDs)
	p.Params = tss.NewParameters(p.curve, ctx, p.PartyID, sortedPartyIDs.Len(), threshold)
	p.sender = sender
	go p.sendMessages()
}

// InitReshare initializes the party for resharing
func (p *BaseParty) InitReshare(oldParticipants tss.SortedPartyIDs, newParticipants tss.SortedPartyIDs, oldThreshold int, newThreshold int, sender Sender) {

	// Only update index for new parties
	// if p.PartyID.Index == -1 {
	// 	p.PartyID.Index = GetLocalPartyIndex(newSortedPartyIDs, p.PartyID.Id)
	// }

	p.ReshareParams = tss.NewReSharingParameters(
		p.curve,
		tss.NewPeerContext(oldParticipants),
		tss.NewPeerContext(newParticipants),
		p.PartyID,
		len(oldParticipants),
		oldThreshold,
		len(newParticipants),
		newThreshold,
	)
	p.sender = sender
	go p.sendMessages()
}

func (p *BaseParty) OnMsg(msg types.TssMessage) {
	select {
	case p.In <- msg:
	case <-p.closeChan:
	}
}

func (p *BaseParty) Err() chan error {
	return p.ErrChan
}

func (p *BaseParty) NotifyError() {
	for err := range p.ErrChan {
		log.Printf("Party %s received error: %v", p.PartyID.Id, err)
	}
}

func (p *BaseParty) Close() {
	close(p.closeChan)
	close(p.In)
	close(p.Out)
	close(p.ErrChan)
}

// processMsg handles message processing for any party implementation
func (p *BaseParty) processMsg(localParty tss.Party, msg types.TssMessage) error {
	ok, err := localParty.UpdateFromBytes(msg.MsgBytes, msg.From, msg.IsBroadcast)
	if !ok {
		return err
	}
	return nil
}

// hashToInt converts a hash to a big integer, respecting the curve's order
func (p *BaseParty) hashToInt(hash []byte) *big.Int {
	if p.curve == nil {
		return nil
	}
	orderBits := p.curve.Params().N.BitLen()
	orderBytes := (orderBits + 7) / 8
	if len(hash) > orderBytes {
		hash = hash[:orderBytes]
	}

	ret := new(big.Int).SetBytes(hash)
	excess := len(hash)*8 - orderBits
	if excess > 0 {
		ret.Rsh(ret, uint(excess))
	}
	return ret
}

func (p *BaseParty) sendMessages() {
	for {
		select {
		case <-p.closeChan:
			return
		case msg := <-p.Out:
			if p.sender != nil {
				p.sender(msg)
			}
		}
	}
}
