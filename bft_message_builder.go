package raft

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"sync"

	"google.golang.org/protobuf/proto"
	pb "go.etcd.io/raft/v3/raftpb"
)

// BFTMessageBuilder constructs and signs BFT client request messages.
//
// The resulting wire format corresponds to PBFT-style requests:
// <REQUEST, o, t, c>_sigma_c where:
// - o is operation (message entry data)
// - t is timestamp (embedded in signature envelope)
// - c is client ID (message From)
type BFTMessageBuilder struct {
	selfID uint64
	priv   ed25519.PrivateKey
	cfg    ClientProofConfig

	mu         sync.Mutex
	lastSentTS int64
}

// NewBFTMessageBuilder creates a new BFTMessageBuilder for the given node ID and signing key.
func NewBFTMessageBuilder(selfID uint64, priv ed25519.PrivateKey, cfg *ClientProofConfig) *BFTMessageBuilder {
	var c ClientProofConfig
	if cfg != nil {
		c = *cfg
	}
	return &BFTMessageBuilder{selfID: selfID, priv: priv, cfg: c}
}

// nextTimestamp generates a new timestamp for signing a message, ensuring that it is strictly greater than the last sent timestamp to prevent signature replay issues.
func (b *BFTMessageBuilder) nextTimestamp() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()

	ts := b.cfg.now().UnixNano()
	if ts <= b.lastSentTS {
		ts = b.lastSentTS + 1
	}
	b.lastSentTS = ts
	return ts
}

// signAt produces a signed message with the given timestamp, preserving the original context payload (if any).
func (b *BFTMessageBuilder) signAt(m pb.Message, ts int64) (pb.Message, error) {
	origCtx := normalizeContext(m.Context)
	dataSign, err := messageSignBytes(&m, origCtx, ts)
	if err != nil {
		return pb.Message{}, err
	}
	sig := ed25519.Sign(b.priv, dataSign)
	m.Context = packSignature(sig, ts, origCtx)
	return m, nil
}

func (b *BFTMessageBuilder) constructClientRequestAt(to uint64, operation []byte, ts int64) (pb.Message, error) {
	m := pb.Message{
		Type: pb.MsgProp.Enum(),
		From: u64Ptr(b.selfID),
		To:   u64Ptr(to),
		Entries: []*pb.Entry{{
			Data: operation,
		}},
	}
	return b.signAt(m, ts)
}

// ConstructClientRequest builds a signed PBFT-style client request directed to
// the given primary/target node.
func (b *BFTMessageBuilder) ConstructClientRequest(to uint64, operation []byte) (pb.Message, int64, error) {
	ts := b.nextTimestamp()
	m, err := b.constructClientRequestAt(to, operation, ts)
	if err != nil {
		return pb.Message{}, 0, err
	}
	return m, ts, nil
}

func (b *BFTMessageBuilder) constructPhaseMessageAt(to uint64, bctx BFTContext, entries []*pb.Entry, ts int64) (pb.Message, error) {
	encCtx, err := encodeBFTContext(bctx)
	if err != nil {
		return pb.Message{}, err
	}

	m := pb.Message{
		Type:    pb.MsgApp.Enum(),
		From:    u64Ptr(b.selfID),
		To:      u64Ptr(to),
		Context: encCtx,
		Entries: entries,
	}

	return b.signAt(m, ts)
}

// ConstructPrePrepare builds a signed PRE-PREPARE message:
// <PRE-PREPARE, v, n, d, m>_sigma_p.
func (b *BFTMessageBuilder) ConstructPrePrepare(to uint64, view uint64, seqNum uint64, request pb.Message) (BFTContext, pb.Message, int64, error) {
	entries := cloneEntries(request.GetEntries())
	digest, err := hashEntryBatch(entries)
	if err != nil {
		return BFTContext{}, pb.Message{}, 0, err
	}

	bctx := BFTContext{
		Phase:  PhasePrePrepare,
		View:   view,
		SeqNum: seqNum,
		Digest: digest,
	}

	ts := b.nextTimestamp()
	m, err := b.constructPhaseMessageAt(to, bctx, entries, ts)
	if err != nil {
		return BFTContext{}, pb.Message{}, 0, err
	}
	return bctx, m, ts, nil
}

// hashEntryBatch hashes the complete entry batch deterministically, preserving
// entry order and distinguishing nil entries from non-nil entries.
func hashEntryBatch(entries []*pb.Entry) ([32]byte, error) {
	h := sha256.New()
	mo := proto.MarshalOptions{Deterministic: true}

	var lenBuf [8]byte
	binary.BigEndian.PutUint64(lenBuf[:], uint64(len(entries)))
	if _, err := h.Write(lenBuf[:]); err != nil {
		return [32]byte{}, err
	}

	for _, e := range entries {
		if e == nil {
			if _, err := h.Write([]byte{0}); err != nil {
				return [32]byte{}, err
			}
			continue
		}
		if _, err := h.Write([]byte{1}); err != nil {
			return [32]byte{}, err
		}
		eb, err := mo.Marshal(e)
		if err != nil {
			return [32]byte{}, err
		}
		binary.BigEndian.PutUint64(lenBuf[:], uint64(len(eb)))
		if _, err := h.Write(lenBuf[:]); err != nil {
			return [32]byte{}, err
		}
		if _, err := h.Write(eb); err != nil {
			return [32]byte{}, err
		}
	}

	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out, nil
}

// ConstructPrepare builds a signed PREPARE message:
// <PREPARE, v, n, d, i>_sigma_i.
func (b *BFTMessageBuilder) ConstructPrepare(to uint64, view uint64, seqNum uint64, digest [32]byte) (pb.Message, int64, error) {
	bctx := BFTContext{
		Phase:  PhasePrepare,
		View:   view,
		SeqNum: seqNum,
		Digest: digest,
	}

	ts := b.nextTimestamp()
	m, err := b.constructPhaseMessageAt(to, bctx, nil, ts)
	if err != nil {
		return pb.Message{}, 0, err
	}
	return m, ts, nil
}

// ConstructCommit builds a signed COMMIT message:
// <COMMIT, v, n, D(m), i>_sigma_i.
func (b *BFTMessageBuilder) ConstructCommit(to uint64, view uint64, seqNum uint64, digest [32]byte) (pb.Message, int64, error) {
	bctx := BFTContext{
		Phase:  PhaseCommit,
		View:   view,
		SeqNum: seqNum,
		Digest: digest,
	}

	ts := b.nextTimestamp()
	m, err := b.constructPhaseMessageAt(to, bctx, nil, ts)
	if err != nil {
		return pb.Message{}, 0, err
	}
	return m, ts, nil
}

// ConstructCheckpoint builds a signed CHECKPOINT message:
// <CHECKPOINT, n, d, i>_sigma_i.
func (b *BFTMessageBuilder) ConstructCheckpoint(to uint64, checkpointSeq uint64, stateDigest [32]byte) (pb.Message, int64, error) {
	bctx := BFTContext{
		Phase:             PhaseCheckpoint,
		CheckpointSeqNum:  checkpointSeq,
		CheckpointDigest:  stateDigest,
		SeqNum:            checkpointSeq,
		Digest:            stateDigest,
	}

	ts := b.nextTimestamp()
	m, err := b.constructPhaseMessageAt(to, bctx, nil, ts)
	if err != nil {
		return pb.Message{}, 0, err
	}
	return m, ts, nil
}

// ConstructViewChange builds a signed VIEW-CHANGE message:
// <VIEW-CHANGE, v, n, C, P, i>_sigma_i.
func (b *BFTMessageBuilder) ConstructViewChange(
	to uint64,
	view uint64,
	lastStableSeq uint64,
	checkpointProofs []BFTCheckpointProof,
	preparedProofs []BFTPreparedProof,
) (pb.Message, int64, error) {
	bctx := BFTContext{
		Phase:            PhaseViewChange,
		View:             view,
		CheckpointSeqNum: lastStableSeq,
		SeqNum:           lastStableSeq,
		CheckpointProofs: append([]BFTCheckpointProof(nil), checkpointProofs...),
		PreparedProofs:   append([]BFTPreparedProof(nil), preparedProofs...),
	}

	ts := b.nextTimestamp()
	m, err := b.constructPhaseMessageAt(to, bctx, nil, ts)
	if err != nil {
		return pb.Message{}, 0, err
	}
	return m, ts, nil
}

// ConstructNewView builds a signed NEW-VIEW message:
// <NEW-VIEW, v, V, O>_sigma_p.
// v should be the new view number, V should be the set of view-change messages received from a quorum of replicas, and O should be the set of pre-prepare messages that the new primary is proposing for the new view.
func (b *BFTMessageBuilder) ConstructNewView(
	to uint64,
	view uint64,
	viewSet [][]byte,
	prePrepareSet []BFTPrePrepareMeta,
) (pb.Message, int64, error) {
	bctx := BFTContext{
		Phase:         PhaseNewView,
		View:          view,
		ViewSet:       append([][]byte(nil), viewSet...),
		PrePrepareSet: append([]BFTPrePrepareMeta(nil), prePrepareSet...),
	}

	ts := b.nextTimestamp()
	m, err := b.constructPhaseMessageAt(to, bctx, nil, ts)
	if err != nil {
		return pb.Message{}, 0, err
	}
	return m, ts, nil
}

// ConstructReply builds a signed REPLY message:
// <REPLY, v, t, c, i, r>_sigma_i.
func (b *BFTMessageBuilder) ConstructReply(
	to uint64,
	view uint64,
	requestTimestamp int64,
	clientID uint64,
	result []byte,
) (pb.Message, int64, error) {
	bctx := BFTContext{
		Phase:            PhaseReply,
		View:             view,
		RequestTimestamp: requestTimestamp,
		ClientID:         clientID,
		Result:           append([]byte(nil), result...),
	}

	ts := b.nextTimestamp()
	m, err := b.constructPhaseMessageAt(to, bctx, nil, ts)
	if err != nil {
		return pb.Message{}, 0, err
	}
	return m, ts, nil
}
