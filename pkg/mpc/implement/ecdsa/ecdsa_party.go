package ecdsa

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/resharing"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/signing"
	"github.com/bnb-chain/tss-lib/v2/tss"
	"github.com/fystack/mpcium/pkg/mpc/implement"
)

type ECDSAParty struct {
	implement.BaseParty
	preParams keygen.LocalPreParams
	shareData *keygen.LocalPartySaveData
}

func NewECDSAParty(partyID string) *ECDSAParty {
	party := &ECDSAParty{
		BaseParty: *implement.NewBaseParty(partyID),
	}
	party.SetCurve(tss.S256())
	return party
}

func (p *ECDSAParty) Init(participants []string, threshold int, preParams keygen.LocalPreParams, sender implement.Sender) {
	p.preParams = preParams
	p.BaseParty.Init(participants, threshold, sender)
}

func (p *ECDSAParty) InitReshare(oldParticipants []string, newParticipants []string, oldThreshold int, newThreshold int, preParams keygen.LocalPreParams, sender implement.Sender) {
	p.preParams = preParams
	p.BaseParty.InitReshare(oldParticipants, newParticipants, oldThreshold, newThreshold, sender)
}

func (p *ECDSAParty) Keygen(done func(*keygen.LocalPartySaveData)) {
	log.Printf("Party %s starting keygen\n", p.PartyID.Id)
	defer log.Printf("Party %s ending keygen\n", p.PartyID.Id)

	endCh := make(chan *keygen.LocalPartySaveData, 1)
	localParty := keygen.NewLocalParty(p.Params, p.Out, endCh, p.preParams)

	go func() {
		if err := localParty.Start(); err != nil {
			p.ErrChan <- err
		}
	}()

	for {
		select {
		case share := <-endCh:
			if done != nil {
				done(share)
			}
			return
		case msg := <-p.In:
			if err := p.ProcessMsg(localParty, msg); err != nil {
				p.ErrChan <- err
			}
		}
	}
}

func (p *ECDSAParty) Sign(msg []byte, done func(*common.SignatureData)) {
	log.Printf("Party %s starting sign\n", p.PartyID.Id)
	defer log.Printf("Party %s ending sign\n", p.PartyID.Id)

	if p.shareData == nil {
		log.Printf("Party %s has no share data", p.PartyID.Id)
		return
	}

	endCh := make(chan *common.SignatureData, 1)
	msgToSign := p.HashToInt(msg)
	localParty := signing.NewLocalParty(msgToSign, p.Params, *p.shareData, p.Out, endCh)

	go func() {
		if err := localParty.Start(); err != nil {
			log.Printf("Party %s failed to start: %v\n", p.PartyID.Id, err)
			panic(err)
		}
	}()

	for {
		select {
		case sig := <-endCh:
			if done != nil {
				done(sig)
			}
			return
		case msg := <-p.In:
			if err := p.ProcessMsg(localParty, msg); err != nil {
				p.ErrChan <- err
			}
		}
	}
}

func (p *ECDSAParty) Reshare(done func(*keygen.LocalPartySaveData)) {
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
		case share := <-endCh:
			if done != nil {
				done(share)
			}
			return
		case msg := <-p.In:
			if err := p.ProcessMsg(localParty, msg); err != nil {
				p.ErrChan <- err
			}
		}
	}
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
	localSaveData.ECDSAPub.SetCurve(p.GetCurve())
	for _, xj := range localSaveData.BigXj {
		if xj == nil {
			p.ErrChan <- fmt.Errorf("share data has nil public share")
		}
		xj.SetCurve(p.GetCurve())
	}

	p.shareData = &localSaveData
}
