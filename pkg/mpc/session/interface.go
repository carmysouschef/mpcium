package session

import (
	"context"

	"github.com/fystack/mpcium/pkg/types"
)

// SessionID represents a unique identifier for a session
type SessionID string

// Session defines the interface for MPC sessions (keygen, signing, resharing)
type Session interface {
	// Keygen generates a new key pair for the session
	// ctx: context for cancellation
	// done: callback function that receives the generated key data
	Keygen(ctx context.Context, done func([]byte))

	// Sign signs a message using the session's key
	// ctx: context for cancellation
	// msg: message to sign
	// done: callback function that receives the signature
	Sign(ctx context.Context, msg []byte, done func([]byte))

	// Reshare redistributes the key shares among participants
	// ctx: context for cancellation
	// done: callback function that receives the new share data
	Reshare(ctx context.Context, done func([]byte))

	// SetShareData sets the key share data for the session
	// shareData: serialized key share data
	SetShareData(shareData []byte)

	// OnMsg processes an incoming message for this session
	// msg: the TSS message to process
	OnMsg(msg types.TssMessage)

	// Err returns the error channel for the session
	Err() chan error

	// Close terminates the session and releases resources
	Close()

	// GetPubKey returns the public key of the session
	GetPubKey() []byte
}
