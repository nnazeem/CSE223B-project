package raft

import (
	"bytes"
	"crypto/sha256"
	"encoding/gob"
	"errors"
	"time"

	pb "go.etcd.io/raft/v3/raftpb"
)

var (
	ErrInvalidBFTMessage     = errors.New("raft: invalid bft message")
	ErrInvalidBFTContext     = errors.New("raft: invalid bft context")
	ErrInvalidCheckpoint     = errors.New("raft: invalid checkpoint message")
	ErrInvalidViewChange     = errors.New("raft: invalid view-change message")
	ErrInvalidNewView        = errors.New("raft: invalid new-view message")
	ErrInvalidPreparedProof  = errors.New("raft: invalid prepared proof")
	ErrInvalidCheckpointCert = errors.New("raft: invalid checkpoint certificate")
)

// BFTPhase identifies the PBFT stage represented in BFTContext.
type BFTNodePhase uint8

const (
	Normal BFTNodePhase = iota
	ViewChange
)

// BFTPhase identifies the PBFT stage represented in BFTContext.
type BFTPhase uint8

const (
	PhaseUnknown BFTPhase = iota
	PhaseRequest
	PhasePrePrepare
	PhasePrepare
	PhaseCommit
	PhaseCheckpoint
	PhaseViewChange
	PhaseNewView
	PhaseReply
)

// BFTCheckpointProof captures one checkpoint proof.
type BFTCheckpointProof struct {
	SeqNum      uint64
	Digest      [32]byte // of state hash
	Checkpoints []pb.Message
}

// BFTPreparedProof captures one prepared request proof Pm in a view-change.
type BFTPreparedProof struct {
	View     uint64
	SeqNum   uint64
	Digest   [32]byte
	Prepares []pb.Message
}

// BFTContext carries PBFT metadata in the raft message context payload.
type BFTContext struct {
	Phase  BFTPhase
	View   uint64
	SeqNum uint64
	Digest [32]byte

	// Reply fields.
	RequestTimestamp int64
	ClientID         uint64
	ClientRequest    pb.Message
	Result           []byte

	// Checkpoint fields.
	CheckpointSeqNum uint64
	CheckpointDigest [32]byte

	// View-change/new-view evidence sets.
	CheckpointProofs BFTCheckpointProof
	PreparedProofs   []BFTPreparedProof
	ViewSet          []pb.Message
	PrePrepareSet    []pb.Message
}

// ClientProofConfig configures freshness checks for client-originated proofs.
type ClientProofConfig struct {
	MaxAge time.Duration
	Now    func() time.Time
}

func (c *ClientProofConfig) maxAge() time.Duration {
	if c == nil || c.MaxAge <= 0 {
		return DefaultMaxMessageAge
	}
	return c.MaxAge
}

func (c *ClientProofConfig) now() time.Time {
	if c == nil || c.Now == nil {
		return time.Now()
	}
	return c.Now()
}

func hashData(data []byte) [32]byte {
	return sha256.Sum256(data)
}

func encodeBFTContext(bctx BFTContext) ([]byte, error) {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(bctx); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func decodeBFTContext(data []byte) (BFTContext, error) {
	var bctx BFTContext
	if len(data) == 0 {
		return bctx, nil
	}
	err := gob.NewDecoder(bytes.NewReader(data)).Decode(&bctx)
	return bctx, err
}

func (p BFTPhase) IsBFTMessagePhase() bool {
	switch p {
	case PhasePrePrepare,
		PhasePrepare,
		PhaseCommit,
		PhaseCheckpoint,
		PhaseViewChange,
		PhaseNewView,
		PhaseReply:
		return true
	default:
		return false
	}
}

func zeroDigest(d [32]byte) bool {
	return d == [32]byte{}
}
