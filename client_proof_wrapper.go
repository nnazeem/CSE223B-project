// via VSCode Agent Chat

package raft

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"sync"
	"time"

	"github.com/golang/protobuf/proto"

	pb "go.etcd.io/raft/v3/raftpb"
)

const (
	clientProofMagic    = "raftclisig1"
	clientProofOverhead = len(clientProofMagic) + 8 + 8 + ed25519.SignatureSize + 4
)

var (
	ErrInvalidClientProof = errors.New("raft: invalid client proof")
	ErrUnknownClient      = errors.New("raft: unknown client")
	ErrClientReplay       = errors.New("raft: client message replay")
)

// ClientProofConfig configures the timestamp source for client proofs.
type ClientProofConfig struct {
	// Now returns the current time. Defaults to time.Now.
	Now func() time.Time
}

func (c *ClientProofConfig) now() time.Time {
	if c == nil || c.Now == nil {
		return time.Now()
	}
	return c.Now()
}

// ClientProofSigner signs client messages with a timestamp and client id.
// The proof is stored in Message.Context.
type ClientProofSigner struct {
	clientID uint64
	priv     ed25519.PrivateKey
	cfg      ClientProofConfig

	mu       sync.Mutex
	lastSent int64
}

// NewClientProofSigner returns a signer that adds client proofs.
func NewClientProofSigner(clientID uint64, priv ed25519.PrivateKey, cfg *ClientProofConfig) *ClientProofSigner {
	var c ClientProofConfig
	if cfg != nil {
		c = *cfg
	}
	return &ClientProofSigner{
		clientID: clientID,
		priv:     priv,
		cfg:      c,
	}
}

// AddClientProof signs the message and stores the proof in Message.Context.
func (s *ClientProofSigner) AddClientProof(m *pb.Message) error {
	if m == nil {
		return errors.New("raft: cannot sign nil message")
	}
	origCtx := normalizeClientProofContext(m.Context)
	ts := s.nextTimestamp()
	data, err := clientProofSignBytes(m, origCtx, ts, s.clientID)
	if err != nil {
		return err
	}
	sig := ed25519.Sign(s.priv, data)
	m.Context = packClientProof(sig, ts, s.clientID, origCtx)
	return nil
}

func (s *ClientProofSigner) nextTimestamp() int64 {
	ts := s.cfg.now().UnixNano()
	s.mu.Lock()
	defer s.mu.Unlock()
	if ts <= s.lastSent {
		ts = s.lastSent + 1
	}
	s.lastSent = ts
	return ts
}

// ClientProofVerifier verifies signed client messages and enforces replay checks.
type ClientProofVerifier struct {
	clientPubKeys map[uint64]ed25519.PublicKey

	mu       sync.Mutex
	lastSeen map[uint64]int64
}

// NewClientProofVerifier returns a verifier for the provided client keys.
func NewClientProofVerifier(clientPubKeys map[uint64]ed25519.PublicKey) *ClientProofVerifier {
	return &ClientProofVerifier{
		clientPubKeys: clientPubKeys,
		lastSeen:      make(map[uint64]int64),
	}
}

// VerifyClient checks the message proof and updates replay tracking on success.
func (v *ClientProofVerifier) VerifyClient(m *pb.Message) error {
	if m == nil {
		return errors.New("raft: cannot verify nil message")
	}
	sig, ts, clientID, origCtx, err := parseClientProof(m.Context)
	if err != nil {
		return err
	}
	pub, ok := v.clientPubKeys[clientID]
	if !ok {
		return ErrUnknownClient
	}
	data, err := clientProofSignBytes(m, origCtx, ts, clientID)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, data, sig) {
		return ErrInvalidClientProof
	}
	if err := v.checkReplay(clientID, ts); err != nil {
		return err
	}
	v.recordSeen(clientID, ts)
	m.Context = origCtx
	return nil
}

func (v *ClientProofVerifier) checkReplay(clientID uint64, ts int64) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if last, ok := v.lastSeen[clientID]; ok && ts <= last {
		return ErrClientReplay
	}
	return nil
}

func (v *ClientProofVerifier) recordSeen(clientID uint64, ts int64) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if ts > v.lastSeen[clientID] {
		v.lastSeen[clientID] = ts
	}
}

func clientProofSignBytes(m *pb.Message, context []byte, ts int64, clientID uint64) ([]byte, error) {
	mm := proto.Clone(m).(*pb.Message)
	mm.Context = normalizeClientProofContext(context)
	mm.Responses = nil
	payload, err := proto.Marshal(mm)
	if err != nil {
		return nil, err
	}
	return append(payload, clientProofMetadataBytes(ts, clientID)...), nil
}

func clientProofMetadataBytes(ts int64, clientID uint64) []byte {
	var b [16]byte
	binary.BigEndian.PutUint64(b[:8], uint64(ts))
	binary.BigEndian.PutUint64(b[8:], clientID)
	return b[:]
}

func normalizeClientProofContext(ctx []byte) []byte {
	if len(ctx) == 0 {
		return nil
	}
	return ctx
}

func packClientProof(sig []byte, ts int64, clientID uint64, origCtx []byte) []byte {
	out := make([]byte, clientProofOverhead+len(origCtx))
	copy(out, clientProofMagic)
	binary.BigEndian.PutUint64(out[len(clientProofMagic):], uint64(ts))
	binary.BigEndian.PutUint64(out[len(clientProofMagic)+8:], clientID)
	sigStart := len(clientProofMagic) + 16
	copy(out[sigStart:], sig)
	binary.BigEndian.PutUint32(out[sigStart+ed25519.SignatureSize:], uint32(len(origCtx)))
	copy(out[clientProofOverhead:], origCtx)
	return out
}

func parseClientProof(ctx []byte) (sig []byte, ts int64, clientID uint64, origCtx []byte, err error) {
	if len(ctx) < clientProofOverhead {
		return nil, 0, 0, nil, ErrInvalidClientProof
	}
	if string(ctx[:len(clientProofMagic)]) != clientProofMagic {
		return nil, 0, 0, nil, ErrInvalidClientProof
	}
	ts = int64(binary.BigEndian.Uint64(ctx[len(clientProofMagic):]))
	clientID = binary.BigEndian.Uint64(ctx[len(clientProofMagic)+8:])
	sigStart := len(clientProofMagic) + 16
	sigEnd := sigStart + ed25519.SignatureSize
	sig = ctx[sigStart:sigEnd]
	n := binary.BigEndian.Uint32(ctx[sigEnd : sigEnd+4])
	if uint64(clientProofOverhead)+uint64(n) != uint64(len(ctx)) {
		return nil, 0, 0, nil, ErrInvalidClientProof
	}
	origCtx = normalizeClientProofContext(ctx[clientProofOverhead:])
	return sig, ts, clientID, origCtx, nil
}
