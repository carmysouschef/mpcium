package implement

import (
	"crypto/elliptic"
	"log"
	"math/big"

	"github.com/bnb-chain/tss-lib/v2/tss"
)

const (
	defaultChanSize = 1000
)

type Sender func(msg tss.Message)

type BaseParty struct {
	PartyID       *tss.PartyID
	Params        *tss.Parameters
	ReshareParams *tss.ReSharingParameters
	In            chan tss.Message
	Out           chan tss.Message
	ErrChan       chan error
	closeChan     chan struct{}
	sender        Sender
	curve         elliptic.Curve
}

func NewBaseParty(partyID string) *BaseParty {
	return &BaseParty{
		PartyID:   tss.NewPartyID(partyID, partyID, new(big.Int).SetBytes([]byte(partyID))),
		In:        make(chan tss.Message, defaultChanSize),
		Out:       make(chan tss.Message, defaultChanSize),
		ErrChan:   make(chan error, defaultChanSize),
		closeChan: make(chan struct{}),
	}
}

func (p *BaseParty) SetSender(sender Sender) {
	p.sender = sender
}

func (p *BaseParty) SetCurve(curve elliptic.Curve) {
	p.curve = curve
}

func (p *BaseParty) GetCurve() elliptic.Curve {
	return p.curve
}

func CreateSortedPartyIDs(participants []string) tss.SortedPartyIDs {
	partyIDs := make(tss.UnSortedPartyIDs, len(participants))
	for i, participant := range participants {
		partyIDs[i] = tss.NewPartyID(participant, participant, new(big.Int).SetBytes([]byte(participant)))
	}
	return tss.SortPartyIDs(partyIDs)
}

func GetLocalPartyIndex(partyIDs tss.SortedPartyIDs, partyID string) int {
	for i, pid := range partyIDs {
		if pid.Id == partyID {
			return i
		}
	}
	return -1
}

func (p *BaseParty) OnMsg(msg tss.Message) {
	select {
	case p.In <- msg:
	case <-p.closeChan:
	}
}

func (p *BaseParty) SendMessages() {
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

// Init initializes the party with basic parameters
func (p *BaseParty) Init(participants []string, threshold int, sender Sender) {
	sortedPartyIDs := CreateSortedPartyIDs(participants)
	// Update the partyID index
	p.PartyID.Index = GetLocalPartyIndex(sortedPartyIDs, p.PartyID.Id)
	ctx := tss.NewPeerContext(sortedPartyIDs)
	p.Params = tss.NewParameters(p.curve, ctx, p.PartyID, len(participants), threshold)
	p.SetSender(sender)
	go p.SendMessages()
}

// InitReshare initializes the party for resharing
func (p *BaseParty) InitReshare(oldParticipants []string, newParticipants []string, oldThreshold int, newThreshold int, sender Sender) {
	oldSortedPartyIDs := CreateSortedPartyIDs(oldParticipants)
	newSortedPartyIDs := CreateSortedPartyIDs(newParticipants)

	// Only update index for new parties
	if p.PartyID.Index == -1 {
		p.PartyID.Index = GetLocalPartyIndex(newSortedPartyIDs, p.PartyID.Id)
	}

	p.ReshareParams = tss.NewReSharingParameters(
		p.curve,
		tss.NewPeerContext(oldSortedPartyIDs),
		tss.NewPeerContext(newSortedPartyIDs),
		p.PartyID,
		len(oldParticipants),
		oldThreshold,
		len(newParticipants),
		newThreshold,
	)
	p.SetSender(sender)
	go p.SendMessages()
}

// ProcessMsg handles message processing for any party implementation
func (p *BaseParty) ProcessMsg(localParty tss.Party, msg tss.Message) error {
	bz, _, err := msg.WireBytes()
	if err != nil {
		return err
	}
	ok, err := localParty.UpdateFromBytes(bz, msg.GetFrom(), msg.IsBroadcast())
	if !ok {
		return err
	}
	return nil
}

// HashToInt converts a hash to a big integer, respecting the curve's order
func (p *BaseParty) HashToInt(hash []byte) *big.Int {
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
