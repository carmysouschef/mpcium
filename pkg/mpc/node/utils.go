package node

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/tss"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/google/uuid"
)

func partyToNodeID(partyID *tss.PartyID) string {
	return string(partyID.KeyInt().Bytes())
}

func createPartyID(nodeID string, purpose string) *tss.PartyID {
	partyID := uuid.NewString()
	// Must use the same key for the same nodeID and purpose
	key := big.NewInt(0).SetBytes([]byte(nodeID))
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
