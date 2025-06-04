package session

import (
	"context"

	"github.com/fystack/mpcium/pkg/types"
)

type SessionID string

type Session interface {
	// Init initializes the session
	Keygen(ctx context.Context, done func([]byte))
	Sign(ctx context.Context, msg []byte, done func([]byte))
	Reshare(ctx context.Context, done func([]byte))
	SetShareData(shareData []byte)

	// HandleMessage processes an incoming message for this session
	OnMsg(msg types.TssMessage)

	// Err returns the error channel
	Err() chan error

	// Close terminates the session and releases resources
	Close()

	// GetPubKey returns the public key of the session
	GetPubKey() []byte
}
