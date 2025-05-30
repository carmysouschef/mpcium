package ecdsa

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
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
func setupTestParties(t *testing.T, cfg testConfig) []*ECDSAParty {
	parties := make([]*ECDSAParty, len(cfg.participants))
	preParams := make([]*keygen.LocalPreParams, len(cfg.participants))

	// Create parties and load pre-params
	for i, id := range cfg.participants {
		parties[i] = NewECDSAParty(id)
		params, err := loadPreparams(id)
		require.NoError(t, err, "Failed to load pre-params for %s", id)
		preParams[i] = params
	}

	// Initialize parties with senders
	senders := senders(parties)
	for i, party := range parties {
		party.Init(cfg.participants, cfg.threshold, *preParams[i], senders[i])
		go party.NotifyError()
	}

	return parties
}

// cleanupTestParties ensures proper cleanup of test resources
func cleanupTestParties(parties []*ECDSAParty) {
	for _, party := range parties {
		party.Close()
	}
}

func TestECDSAParty(t *testing.T) {
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

func testResharing(t *testing.T, oldParties []*ECDSAParty, cfg testConfig) []*ECDSAParty {
	// Create new parties for resharing
	newParticipants := []string{"party1-reshare", "party2-reshare", "party3-reshare"}
	newParties := make([]*ECDSAParty, len(newParticipants))

	for i, id := range newParticipants {
		newParties[i] = NewECDSAParty(id)
	}

	// Combine old and new parties for resharing
	allParties := append(oldParties, newParties...)
	reshareSenders := senderForReshare(allParties)

	// Initialize resharing for all parties
	for i, party := range allParties {
		preParams, err := loadPreparams(party.PartyID.Id)
		require.NoError(t, err, "Failed to load pre-params for %s", party.PartyID.Id)

		party.InitReshare(
			cfg.participants,
			newParticipants,
			cfg.threshold,
			1, // new threshold
			*preParams,
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
		preParams, err := loadPreparams(party.PartyID.Id)
		require.NoError(t, err, "Failed to load pre-params for %s", party.PartyID.Id)

		party.Init(newParticipants, 1, *preParams, newSignSenders[i])
		party.SetShareData(reshareShares[party.PartyID.Id])
	}

	// Test signing with new parties
	sigs := signAll(newParties, cfg.messageToSign)
	require.Equal(t, len(newParticipants), len(sigs), "Expected %d signatures from new parties, got %d", len(newParticipants), len(sigs))
	t.Log("Signing with new parties completed successfully")

	return newParties
}

func keygenAll(parties []*ECDSAParty) map[string][]byte {
	wg := sync.WaitGroup{}
	wg.Add(len(parties))
	shares := make(map[string][]byte)
	var mu sync.Mutex

	for _, party := range parties {
		go func(p *ECDSAParty) {
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

func signAll(parties []*ECDSAParty, msg []byte) [][]byte {
	wg := sync.WaitGroup{}
	wg.Add(len(parties))
	sigs := make([][]byte, 0, len(parties))
	var mu sync.Mutex

	for _, party := range parties {
		go func(p *ECDSAParty) {
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

func reshareAll(parties []*ECDSAParty) map[string][]byte {
	wg := sync.WaitGroup{}
	wg.Add(len(parties))
	shares := make(map[string][]byte)
	var mu sync.Mutex

	for _, party := range parties {
		go func(p *ECDSAParty) {
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

func senders(parties []*ECDSAParty) []implement.Sender {
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

func senderForReshare(parties []*ECDSAParty) []implement.Sender {
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

func loadPreparams(partyID string) (*keygen.LocalPreParams, error) {
	// Try to read existing file
	data, err := os.ReadFile("preparams_" + partyID + ".json")
	if err == nil {
		var params *keygen.LocalPreParams
		if err := json.Unmarshal(data, &params); err == nil {
			return params, nil
		}
	}

	// Generate new parameters
	params, err := keygen.GeneratePreParams(1 * time.Minute)
	if err != nil {
		return nil, err
	}

	// Save the new parameters
	if data, err := json.Marshal(params); err == nil {
		os.WriteFile("preparams_"+partyID+".json", data, 0644)
	}

	return params, nil
}

func ThresholdPK(shareData *keygen.LocalPartySaveData) ([]byte, error) {
	if shareData == nil {
		return nil, fmt.Errorf("must call SetShareData() before attempting to sign")
	}

	pk := shareData.ECDSAPub
	ecdsaPK := &ecdsa.PublicKey{
		Curve: shareData.ECDSAPub.Curve(),
		X:     pk.X(),
		Y:     pk.Y(),
	}

	return encodeS256PubKey(ecdsaPK)
}

func encodeS256PubKey(pubKey *ecdsa.PublicKey) ([]byte, error) {
	publicKeyBytes := append(pubKey.X.Bytes(), pubKey.Y.Bytes()...)
	return publicKeyBytes, nil
}
