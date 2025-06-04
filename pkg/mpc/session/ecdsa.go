package session

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"log"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/resharing"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/signing"
	"github.com/bnb-chain/tss-lib/v2/tss"
	"github.com/fystack/mpcium/pkg/encoding"
	"github.com/fystack/mpcium/pkg/logger"
)

type ECDSAParty struct {
	BaseParty
	preParams keygen.LocalPreParams
	shareData *keygen.LocalPartySaveData
}

func NewECDSAParty(partyID *tss.PartyID) *ECDSAParty {
	party := &ECDSAParty{
		BaseParty: *NewBaseParty(partyID),
	}
	party.curve = tss.S256()
	return party
}

func (p *ECDSAParty) Init(participants tss.SortedPartyIDs, threshold int, preParams keygen.LocalPreParams, sender Sender) {
	p.preParams = preParams
	p.BaseParty.Init(participants, threshold, sender)
}

func (p *ECDSAParty) InitSign(participants tss.SortedPartyIDs, threshold int, preParams keygen.LocalPreParams, sender Sender) {
	p.preParams = preParams
	p.BaseParty.Init(participants, threshold, sender)
}

func (p *ECDSAParty) InitReshare(oldParticipants tss.SortedPartyIDs, newParticipants tss.SortedPartyIDs, oldThreshold int, newThreshold int, preParams keygen.LocalPreParams, sender Sender) {
	p.preParams = preParams
	p.BaseParty.InitReshare(oldParticipants, newParticipants, oldThreshold, newThreshold, sender)
}

func (p *ECDSAParty) Keygen(ctx context.Context, done func([]byte)) {
	log.Printf("Party %s starting keygen\n", p.PartyID.String())
	defer log.Printf("Party %s ending keygen\n", p.PartyID.String())

	endCh := make(chan *keygen.LocalPartySaveData, 1)
	localParty := keygen.NewLocalParty(p.Params, p.Out, endCh, p.preParams)

	go func() {
		if err := localParty.Start(); err != nil {
			p.ErrChan <- err
		}
	}()

	for {
		select {
		case <-ctx.Done():
			log.Printf("Party %s keygen context done", p.PartyID.Id)
			return
		case share := <-endCh:
			if done != nil {
				bz, err := json.Marshal(share)
				if err != nil {
					p.ErrChan <- err
				}
				done(bz)
			}
			return
		case msg := <-p.In:
			if err := p.processMsg(localParty, msg); err != nil {
				p.ErrChan <- err
			}
		}
	}
}

func (p *ECDSAParty) Sign(ctx context.Context, msg []byte, done func([]byte)) {
	log.Printf("Party %s starting sign\n", p.PartyID.Id)
	defer log.Printf("Party %s ending sign\n", p.PartyID.Id)

	if p.shareData == nil {
		log.Printf("Party %s has no share data", p.PartyID.Id)
		return
	}

	endCh := make(chan *common.SignatureData, 1)
	msgToSign := p.hashToInt(msg)
	localParty := signing.NewLocalParty(msgToSign, p.Params, *p.shareData, p.Out, endCh)

	go func() {
		if err := localParty.Start(); err != nil {
			log.Printf("Party %s failed to start: %v\n", p.PartyID.Id, err)
			panic(err)
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case sig := <-endCh:
			if done != nil {
				bz, err := json.Marshal(sig)
				if err != nil {
					p.ErrChan <- err
				}
				done(bz)
			}
			return
		case msg := <-p.In:
			if err := p.processMsg(localParty, msg); err != nil {
				p.ErrChan <- err
			}
		}
	}
}

func (p *ECDSAParty) Reshare(ctx context.Context, done func([]byte)) {
	log.Printf("Party %s starting reshare\n", p.PartyID.Id)
	defer log.Printf("Party %s ending reshare\n", p.PartyID.Id)

	// Initialize share data for new participants
	if p.shareData == nil {
		data := keygen.NewLocalPartySaveData(p.ReshareParams.NewPartyCount())
		data.LocalPreParams = p.preParams
		p.shareData = &data
	}

	endCh := make(chan *keygen.LocalPartySaveData, 1)
	localParty := resharing.NewLocalParty(p.ReshareParams, *p.shareData, p.Out, endCh)

	go func() {
		if err := localParty.Start(); err != nil {
			p.ErrChan <- err
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case share := <-endCh:
			if done != nil {
				bz, err := json.Marshal(share)
				if err != nil {
					p.ErrChan <- err
				}
				done(bz)
			}
			return
		case msg := <-p.In:
			if err := p.processMsg(localParty, msg); err != nil {
				p.ErrChan <- err
			}
		}
	}
}

func (p *ECDSAParty) GetPubKey() []byte {
	publicKey := p.shareData.ECDSAPub
	pubKey := &ecdsa.PublicKey{
		Curve: p.curve,
		X:     publicKey.X(),
		Y:     publicKey.Y(),
	}

	pubKeyBytes, err := encoding.EncodeS256PubKey(pubKey)
	if err != nil {
		logger.Error("failed to encode public key", err)
		p.ErrChan <- fmt.Errorf("failed to encode public key: %w", err)
	}
	return pubKeyBytes
}

func (p *ECDSAParty) SetShareData(shareData []byte) {
	var localSaveData keygen.LocalPartySaveData
	err := json.Unmarshal(shareData, &localSaveData)
	if err != nil {
		p.ErrChan <- fmt.Errorf("failed deserializing shares: %w", err)
	}

	// Validate share data
	if localSaveData.ECDSAPub == nil {
		p.ErrChan <- fmt.Errorf("share data has nil public key")
	}
	if localSaveData.Xi == nil {
		p.ErrChan <- fmt.Errorf("share data has nil private share")
	}

	// Set curve for all points
	localSaveData.ECDSAPub.SetCurve(p.curve)
	for _, xj := range localSaveData.BigXj {
		if xj == nil {
			p.ErrChan <- fmt.Errorf("share data has nil public share")
		}
		xj.SetCurve(p.curve)
	}

	p.shareData = &localSaveData
}
