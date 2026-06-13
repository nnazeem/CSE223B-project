package raft

import (
	"bytes"
	"crypto/sha256"
	"encoding/gob"
	"time"
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
	PhaseFetchState
	PhaseStateResponse
)

// BFTPreparedProof captures one prepared request proof Pm in a view-change.
type BFTPreparedProof struct {
	View   uint64
	SeqNum uint64
	Digest [32]byte
}

// BFTPrePrepareMeta captures one pre-prepare metadata item in a new-view O set.
// It intentionally excludes the piggybacked request payload.
type BFTPrePrepareMeta struct {
	View   uint64
	SeqNum uint64
	Digest [32]byte
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
	Result           []byte

	// Checkpoint fields.
	CheckpointSeqNum uint64
	CheckpointDigest [32]byte

	// View-change/new-view evidence sets.
	CheckpointProofs []BFTPreparedProof
	PreparedProofs   []BFTPreparedProof
	ViewSet          [][]byte
	PrePrepareSet    []BFTPrePrepareMeta
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
