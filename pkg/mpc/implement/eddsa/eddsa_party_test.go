package eddsa

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"testing"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/eddsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/tss"

	"github.com/fystack/mpcium/pkg/mpc/implement"
	"github.com/stretchr/testify/require"
)

// testConfig holds configuration for tests
type testConfig struct {
	threshold     int
	participants  []string
	messageToSign []byte
}

// defaultTestConfig returns default test configuration
func defaultTestConfig() testConfig {
	return testConfig{
		threshold:     2,
		participants:  []string{"party1", "party2", "party3"},
		messageToSign: []byte("test"),
	}
}

// setupTestParties creates and initializes test parties
func setupTestParties(t *testing.T, cfg testConfig) []*EDDSAParty {
	parties := make([]*EDDSAParty, len(cfg.participants))

	// Create parties and load pre-params
	for i, id := range cfg.participants {
		parties[i] = NewEDDSAParty(id)
	}

	// Initialize parties with senders
	senders := senders(parties)
	for i, party := range parties {
		party.Init(cfg.participants, cfg.threshold, senders[i])
		go party.NotifyError()
	}

	return parties
}

// cleanupTestParties ensures proper cleanup of test resources
func cleanupTestParties(parties []*EDDSAParty) {
	for _, party := range parties {
		party.Close()
	}
}

func TestEDDSAParty(t *testing.T) {
	cfg := defaultTestConfig()

	// Setup test parties
	parties := setupTestParties(t, cfg)
	// defer cleanupTestParties(parties)

	// Test key generation
	shares := keygenAll(parties)
	require.Equal(t, len(cfg.participants), len(shares), "Expected %d shares, got %d", len(cfg.participants), len(shares))
	t.Log("Key generation completed successfully")

	// Set share data for each party
	for _, party := range parties {
		party.SetShareData(shares[party.PartyID.Id])
	}

	// Test signing
	sigs := signAll(parties, cfg.messageToSign)
	require.Equal(t, len(cfg.participants), len(sigs), "Expected %d signatures, got %d", len(cfg.participants), len(sigs))
	t.Log("Signing completed successfully")

	// Test resharing
	_ = testResharing(t, parties, cfg)
	// defer cleanupTestParties(reshareParties)
}

func testResharing(t *testing.T, oldParties []*EDDSAParty, cfg testConfig) []*EDDSAParty {
	// Create new parties for resharing
	newParticipants := []string{"party1-reshare", "party2-reshare", "party3-reshare"}
	newParties := make([]*EDDSAParty, len(newParticipants))

	for i, id := range newParticipants {
		newParties[i] = NewEDDSAParty(id)
	}

	// Combine old and new parties for resharing
	allParties := append(oldParties, newParties...)
	reshareSenders := senderForReshare(allParties)

	// Initialize resharing for all parties
	for i, party := range allParties {
		party.InitReshare(
			cfg.participants,
			newParticipants,
			cfg.threshold,
			1, // new threshold
			reshareSenders[i],
		)
		go party.NotifyError()
	}

	// Perform resharing
	reshareShares := reshareAll(allParties)
	require.Equal(t, len(allParties), len(reshareShares), "Expected %d reshare shares, got %d", len(allParties), len(reshareShares))
	t.Log("Resharing completed successfully")

	// Remove last party of new parties
	newParties = newParties[:len(newParties)-1]
	newParticipants = newParticipants[:len(newParticipants)-1]
	// Initialize new parties for signing
	newSignSenders := senders(newParties)
	for i, party := range newParties {
		party.Init(newParticipants, 1, newSignSenders[i])
		party.SetShareData(reshareShares[party.PartyID.Id])
	}

	// Test signing with new parties
	sigs := signAll(newParties, cfg.messageToSign)
	require.Equal(t, len(newParticipants), len(sigs), "Expected %d signatures from new parties, got %d", len(newParticipants), len(sigs))
	t.Log("Signing with new parties completed successfully")

	return newParties
}

func keygenAll(parties []*EDDSAParty) map[string][]byte {
	wg := sync.WaitGroup{}
	wg.Add(len(parties))
	shares := make(map[string][]byte)
	var mu sync.Mutex

	for _, party := range parties {
		go func(p *EDDSAParty) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					log.Printf("Party %s panicked: %v", p.PartyID.Id, r)
				}
			}()

			p.Keygen(func(share *keygen.LocalPartySaveData) {
				bz, err := json.Marshal(share)
				if err != nil {
					log.Printf("Party %s failed to marshal share data: %v", p.PartyID.Id, err)
					return
				}
				mu.Lock()
				shares[p.PartyID.Id] = bz
				mu.Unlock()
			})
		}(party)
	}
	wg.Wait()
	return shares
}

func signAll(parties []*EDDSAParty, msg []byte) [][]byte {
	wg := sync.WaitGroup{}
	wg.Add(len(parties))
	sigs := make([][]byte, 0, len(parties))
	var mu sync.Mutex

	for _, party := range parties {
		go func(p *EDDSAParty) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					log.Printf("Party %s panicked: %v", p.PartyID.Id, r)
				}
			}()

			p.Sign(msg, func(sig *common.SignatureData) {
				bz, err := json.Marshal(sig)
				if err != nil {
					log.Printf("Party %s failed to marshal signature: %v", p.PartyID.Id, err)
					return
				}
				mu.Lock()
				sigs = append(sigs, bz)
				mu.Unlock()
			})
		}(party)
	}
	wg.Wait()
	return sigs
}

func reshareAll(parties []*EDDSAParty) map[string][]byte {
	wg := sync.WaitGroup{}
	wg.Add(len(parties))
	shares := make(map[string][]byte)
	var mu sync.Mutex

	for _, party := range parties {
		go func(p *EDDSAParty) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					log.Printf("Party %s panicked: %v", p.PartyID.Id, r)
				}
			}()

			p.Reshare(func(share *keygen.LocalPartySaveData) {
				bz, err := json.Marshal(share)
				if err != nil {
					log.Printf("Party %s failed to marshal share data: %v", p.PartyID.Id, err)
					return
				}
				mu.Lock()
				shares[p.PartyID.Id] = bz
				mu.Unlock()
			})
		}(party)
	}
	wg.Wait()
	return shares
}

func senders(parties []*EDDSAParty) []implement.Sender {
	senders := make([]implement.Sender, len(parties))
	for i, src := range parties {
		src := src
		senders[i] = func(msg tss.Message) {
			msgBytes, _, err := msg.WireBytes()
			if err != nil {
				log.Printf("Party %s failed to get wire bytes: %v", src.PartyID.Id, err)
				return
			}
			round, isBroadcast, err := ClassifyMsg(msgBytes)
			if err != nil {
				log.Printf("Party %s failed to classify message: %v", src.PartyID.Id, err)
				return
			}
			log.Printf("Party %s received message, round: %d, isBroadcast: %t", src.PartyID.Id, round, isBroadcast)
			if isBroadcast {
				for _, dst := range parties {
					if dst.PartyID.Id != src.PartyID.Id {
						dst.OnMsg(msg)
					}
				}
			} else {
				to := msg.GetTo()
				if to == nil {
					log.Printf("Warning: Party %s message has nil recipients", src.PartyID.Id)
					return
				}
				for _, recipient := range to {
					for _, dst := range parties {
						if recipient.Id == dst.PartyID.Id {
							dst.OnMsg(msg)
							break
						}
					}
				}
			}
		}
	}
	return senders
}

func senderForReshare(parties []*EDDSAParty) []implement.Sender {
	senders := make([]implement.Sender, len(parties))
	for i, src := range parties {
		src := src
		senders[i] = func(msg tss.Message) {
			msgBytes, _, err := msg.WireBytes()
			if err != nil {
				log.Printf("Party %s failed to get wire bytes: %v", src.PartyID.Id, err)
				return
			}
			round, isBroadcast, err := ClassifyMsg(msgBytes)
			if err != nil {
				log.Printf("Party %s failed to classify message: %v", src.PartyID.Id, err)
				return
			}
			if round != 7 {
				log.Printf("Party %s received message, round: %d, isBroadcast: %t", src.PartyID.Id, round, isBroadcast)
			}
			to := msg.GetTo()
			if to == nil {
				log.Printf("Warning: Party %s message has nil recipients", src.PartyID.Id)
				return
			}
			for _, recipient := range to {
				for _, dst := range parties {
					if recipient.Id == dst.PartyID.Id {
						dst.OnMsg(msg)
						break
					}
				}
			}
		}
	}
	return senders
}

func ThresholdPK(shareData *keygen.LocalPartySaveData) ([]byte, error) {
	if shareData == nil {
		return nil, fmt.Errorf("must call SetShareData() before attempting to sign")
	}

	pk := shareData.EDDSAPub
	ecdsaPK := &ecdsa.PublicKey{
		Curve: shareData.EDDSAPub.Curve(),
		X:     pk.X(),
		Y:     pk.Y(),
	}

	return encodeS256PubKey(ecdsaPK)
}

func encodeS256PubKey(pubKey *ecdsa.PublicKey) ([]byte, error) {
	publicKeyBytes := append(pubKey.X.Bytes(), pubKey.Y.Bytes()...)
	return publicKeyBytes, nil
}
