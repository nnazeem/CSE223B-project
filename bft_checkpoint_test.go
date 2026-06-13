package raft

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"testing"

	"github.com/golang/protobuf/proto"

	"github.com/stretchr/testify/require"
	pb "go.etcd.io/raft/v3/raftpb"
)

// checkpointTestFixture holds a 4-node cluster (f=1) wired for checkpoint tests.
type checkpointTestFixture struct {
	node      *BFTNode
	client    *BFTClient
	nodePrivs map[uint64]ed25519.PrivateKey
	ctx       context.Context
}

func newCheckpointTestFixture(t *testing.T) checkpointTestFixture {
	t.Helper()
	node, client, nodePrivs, _ := setupCluster(t)
	return checkpointTestFixture{
		node:      node,
		client:    client,
		nodePrivs: nodePrivs,
		ctx:       context.Background(),
	}
}

func (f checkpointTestFixture) signCheckpoint(from, seq uint64, digest [32]byte) *pb.Message {
	bctx := BFTContext{
		Phase:            PhaseCheckpoint,
		View:             0,
		SeqNum:           seq,
		Digest:           digest,
		CheckpointSeqNum: seq,
		CheckpointDigest: digest,
	}
	encCtx, err := encodeBFTContext(bctx)
	if err != nil {
		panic(err)
	}

	msg := &pb.Message{Type: pb.MsgApp.Enum(), From: u64p(from), Term: u64p(1), Context: encCtx}
	origCtx := normalizeContext(msg.Context)
	data, err := messageSignBytes(msg, origCtx, int64(from))
	if err != nil {
		panic(err)
	}
	msg.Context = packSignature(ed25519.Sign(f.nodePrivs[from], data), int64(from), origCtx)
	return msg
}

func (f checkpointTestFixture) stepCheckpoint(t *testing.T, from, seq uint64, digest [32]byte) {
	t.Helper()
	err := f.node.Step(f.ctx, f.signCheckpoint(from, seq, digest))
	require.NoError(t, err)
}

func (f checkpointTestFixture) signPrePrepare(from, seq uint64, payload []byte) *pb.Message {
	reqTS := int64(seq)
	clientReq := &pb.Message{
		Type:    pb.MsgProp.Enum(),
		From:    u64p(100),
		To:      u64p(1),
		Entries: []*pb.Entry{{Data: payload}},
	}
	reqData, err := messageSignBytes(clientReq, normalizeContext(clientReq.Context), reqTS)
	if err != nil {
		panic(err)
	}
	clientReq.Context = packSignature(ed25519.Sign(f.client.priv, reqData), reqTS, normalizeContext(clientReq.Context))

	digest, err := hashEntryBatch(clientReq.GetEntries())
	if err != nil {
		panic(err)
	}
	bctx := BFTContext{
		Phase:            PhasePrePrepare,
		View:             0,
		SeqNum:           seq,
		Digest:           digest,
		RequestTimestamp: reqTS,
		ClientID:         100,
		ClientRequest:    *proto.Clone(clientReq).(*pb.Message),
	}
	encCtx, err := encodeBFTContext(bctx)
	if err != nil {
		panic(err)
	}

	msg := &pb.Message{
		Type:    pb.MsgApp.Enum(),
		From:    u64p(from),
		Term:    u64p(1),
		Context: encCtx,
		Entries: cloneEntries(clientReq.GetEntries()),
	}
	origCtx := normalizeContext(msg.Context)
	data, err := messageSignBytes(msg, origCtx, int64(seq))
	if err != nil {
		panic(err)
	}
	msg.Context = packSignature(ed25519.Sign(f.nodePrivs[from], data), int64(seq), origCtx)
	return msg
}

func (f checkpointTestFixture) seedRequestDigests(t *testing.T, through uint64) {
	t.Helper()
	f.node.mu.Lock()
	defer f.node.mu.Unlock()
	for s := uint64(1); s <= through; s++ {
		payload := []byte(fmt.Sprintf("req-%d", s))
		msg := &pb.Message{
			Type:    pb.MsgApp.Enum(),
			From:    u64p(100),
			Term:    u64p(1),
			Entries: []*pb.Entry{{Data: payload}},
		}
		digest, err := hashEntryBatch(msg.GetEntries())
		require.NoError(t, err)
		key := bftSeqKey{view: 0, seq: s}
		f.node.pp[key] = digest
		f.node.log[s] = msg
	}
}

func (f checkpointTestFixture) drainOutbound(t *testing.T) []*pb.Message {
	t.Helper()
	f.node.mu.Lock()
	msgs := append([]*pb.Message(nil), f.node.bftMsgs...)
	f.node.bftMsgs = nil
	f.node.mu.Unlock()
	return msgs
}

func (f checkpointTestFixture) localDigest(t *testing.T, seq uint64) [32]byte {
	t.Helper()
	f.node.mu.Lock()
	defer f.node.mu.Unlock()
	dig, ok := f.node.localCheckpointDigest(seq)
	require.True(t, ok, "replica must have executed through seq %d", seq)
	return dig
}

func decodeOutboundBFTContext(t *testing.T, m *pb.Message) BFTContext {
	t.Helper()
	bctx, err := decodeBFTContext(m.Context)
	require.NoError(t, err)
	return bctx
}

func TestCheckpoint_QuorumStabilizes(t *testing.T) {
	f := newCheckpointTestFixture(t)
	seq := uint64(100)
	f.seedRequestDigests(t, seq)
	digest := f.localDigest(t, seq)

	f.stepCheckpoint(t, 2, seq, digest)
	f.stepCheckpoint(t, 3, seq, digest)
	require.Nil(t, f.node.stableCheckpoint)

	f.stepCheckpoint(t, 4, seq, digest)
	require.NotNil(t, f.node.stableCheckpoint)
	require.Equal(t, seq, f.node.stableCheckpoint.SeqNum)
	require.Equal(t, digest, f.node.stableCheckpoint.Digest)
	require.Len(t, f.node.stableCheckpoint.Proof.Checkpoints, 3)
	require.Equal(t, seq, f.node.lowW)
	require.Equal(t, seq+WatermarkWindow, f.node.highW)

	sc := f.node.StableCheckpoint()
	require.NotNil(t, sc)
	require.Len(t, sc.Proof.Checkpoints, 3)
	require.Equal(t, seq, sc.Proof.SeqNum)
	require.Equal(t, digest, sc.Proof.Digest)
}

func TestCheckpoint_ConflictingDigestsDoNotStabilize(t *testing.T) {
	f := newCheckpointTestFixture(t)
	seq := uint64(100)
	f.seedRequestDigests(t, seq)
	digestGood := f.localDigest(t, seq)
	digestBad := hashData([]byte("wrong-state"))

	f.stepCheckpoint(t, 2, seq, digestGood)
	f.stepCheckpoint(t, 3, seq, digestGood)
	f.stepCheckpoint(t, 4, seq, digestBad)

	require.Nil(t, f.node.stableCheckpoint)
	require.Len(t, f.node.checkpoints[seq][digestGood], 2)
	_, hasBad := f.node.checkpoints[seq][digestBad]
	require.False(t, hasBad)
}

func TestCheckpoint_StabilizeIgnoresOlderSequence(t *testing.T) {
	f := newCheckpointTestFixture(t)
	f.seedRequestDigests(t, 200)
	digest200 := f.localDigest(t, 200)
	digest100 := f.localDigest(t, 100)

	for _, from := range []uint64{2, 3, 4} {
		f.stepCheckpoint(t, from, 200, digest200)
	}
	require.Equal(t, uint64(200), f.node.stableCheckpoint.SeqNum)

	f.stepCheckpoint(t, 2, 100, digest100)
	f.stepCheckpoint(t, 3, 100, digest100)
	f.stepCheckpoint(t, 4, 100, digest100)

	require.Equal(t, uint64(200), f.node.stableCheckpoint.SeqNum)
	require.Equal(t, uint64(200), f.node.lowW)
}

func TestCheckpoint_StateDigestAt(t *testing.T) {
	f := newCheckpointTestFixture(t)
	f.seedRequestDigests(t, 3)

	f.node.mu.Lock()
	got := f.node.stateDigestAt(3)
	f.node.mu.Unlock()

	var wantMsgs []*pb.Message
	for s := uint64(1); s <= 3; s++ {
		wantMsgs = append(wantMsgs, f.node.log[s])
	}
	want, err := hashMessageBatch(wantMsgs)
	require.NoError(t, err)
	require.Equal(t, want, got)
}

func TestCheckpoint_constructCheckpointIfNeededSkipsNonInterval(t *testing.T) {
	f := newCheckpointTestFixture(t)
	f.seedRequestDigests(t, 99)

	f.node.mu.Lock()
	f.node.constructCheckpointIfNeeded(99)
	f.node.mu.Unlock()

	require.Empty(t, f.drainOutbound(t))
	require.Nil(t, f.node.stableCheckpoint)
}

func TestCheckpoint_constructCheckpointIfNeededBroadcastsAtInterval(t *testing.T) {
	f := newCheckpointTestFixture(t)
	f.seedRequestDigests(t, CheckpointInterval)

	f.node.mu.Lock()
	f.node.constructCheckpointIfNeeded(CheckpointInterval)
	f.node.mu.Unlock()

	out := f.drainOutbound(t)
	require.Len(t, out, 3, "should broadcast CHECKPOINT to the three peers")

	for _, m := range out {
		require.Equal(t, uint64(1), m.GetFrom())
		bctx := decodeOutboundBFTContext(t, m)
		require.Equal(t, PhaseCheckpoint, bctx.Phase)
		require.Equal(t, uint64(CheckpointInterval), bctx.CheckpointSeqNum)
		require.Equal(t, f.node.stateDigestAt(CheckpointInterval), bctx.CheckpointDigest)
	}
}

func TestCheckpoint_GarbageCollectPrunesOldState(t *testing.T) {
	f := newCheckpointTestFixture(t)
	f.seedRequestDigests(t, 150)
	dig := f.localDigest(t, 100)

	req := &pb.Message{
		Type:    pb.MsgApp.Enum(),
		From:    u64p(0),
		Term:    u64p(1),
		Entries: []*pb.Entry{{Data: []byte("x")}},
	}

	p := &pb.Message{
		Type:    pb.MsgApp.Enum(),
		From:    u64p(0),
		Term:    u64p(1),
		Entries: []*pb.Entry{{Data: []byte("y")}},
	}

	ch := &pb.Message{
		Type:    pb.MsgApp.Enum(),
		From:    u64p(0),
		Term:    u64p(1),
		Entries: []*pb.Entry{{Data: []byte("z")}},
	}

	f.node.mu.Lock()
	for _, seq := range []uint64{50, 100, 150} {
		key := bftSeqKey{view: 0, seq: seq}
		f.node.prepares[key] = map[uint64]*pb.Message{2: p}
		f.node.commits[key] = map[uint64]struct{}{2: {}}
		f.node.reqs[key] = req
	}
	for _, replica := range []uint64{1, 2, 3} {
		f.node.recordCheckpoint(100, dig, replica, ch)
	}
	f.node.stabilizeCheckpoint(100, dig)
	f.node.mu.Unlock()

	require.NotContains(t, f.node.pp, bftSeqKey{view: 0, seq: 50})
	require.NotContains(t, f.node.prepares, bftSeqKey{view: 0, seq: 50})
	require.NotContains(t, f.node.commits, bftSeqKey{view: 0, seq: 50})
	require.NotContains(t, f.node.reqs, bftSeqKey{view: 0, seq: 50})
	require.NotContains(t, f.node.pp, bftSeqKey{view: 0, seq: 100})

	require.Contains(t, f.node.pp, bftSeqKey{view: 0, seq: 150})
	require.Nil(t, f.node.checkpoints[50])
}

func TestCheckpoint_WatermarkBlocksStalePrePrepare(t *testing.T) {
	f := newCheckpointTestFixture(t)
	f.seedRequestDigests(t, 100)
	digest := f.localDigest(t, 100)

	for _, from := range []uint64{2, 3, 4} {
		f.stepCheckpoint(t, from, 100, digest)
	}

	err := f.node.Step(f.ctx, f.signPrePrepare(1, 100, []byte("late")))
	require.ErrorContains(t, err, "sequence number out of bounds")

	err = f.node.Step(f.ctx, f.signPrePrepare(1, 101, []byte("ok")))
	require.NoError(t, err)
}

func TestCheckpoint_ConstructCheckpointFields(t *testing.T) {
	f := newCheckpointTestFixture(t)
	seq := uint64(CheckpointInterval)
	digest := hashData([]byte("digest"))

	f.node.mu.Lock()
	msg, err := f.node.ConstructCheckpoint(seq, digest)
	f.node.mu.Unlock()
	require.NoError(t, err)

	bctx, err := decodeBFTContext(msg.Context)
	require.NoError(t, err)
	require.Equal(t, PhaseCheckpoint, bctx.Phase)
	require.Equal(t, seq, bctx.SeqNum)
	require.Equal(t, digest, bctx.Digest)
	require.Equal(t, seq, bctx.CheckpointSeqNum)
	require.Equal(t, digest, bctx.CheckpointDigest)
}

func TestCheckpoint_OnCommitQuorumTriggersAtInterval(t *testing.T) {
	f := newCheckpointTestFixture(t)
	seq := uint64(CheckpointInterval)
	payload := []byte("batch-at-checkpoint")

	msg := &pb.Message{
		Type:    pb.MsgApp.Enum(),
		From:    u64p(0),
		Term:    u64p(1),
		Entries: []*pb.Entry{{Data: payload}},
	}

	f.node.mu.Lock()
	key := bftSeqKey{view: 0, seq: seq}
	digest, err := hashEntryBatch(msg.GetEntries())
	require.NoError(t, err)
	f.node.pp[key] = digest
	f.node.reqs[key] = msg
	for s := uint64(1); s < seq; s++ {
		payload := []byte(fmt.Sprintf("req-%d", s))
		prev := &pb.Message{Type: pb.MsgApp.Enum(), From: u64p(100), Term: u64p(1), Entries: []*pb.Entry{{Data: payload}}}
		prevDigest, err := hashEntryBatch(prev.GetEntries())
		require.NoError(t, err)
		k := bftSeqKey{view: 0, seq: s}
		f.node.pp[k] = prevDigest
		f.node.log[s] = prev
	}
	f.node.onCommitQuorum(key)
	f.node.mu.Unlock()

	out := f.drainOutbound(t)
	require.Len(t, out, 3)
	for _, m := range out {
		bctx := decodeOutboundBFTContext(t, m)
		require.Equal(t, PhaseCheckpoint, bctx.Phase)
		require.Equal(t, seq, bctx.CheckpointSeqNum)
	}
}

func TestCheckpoint_DuplicateReplicaProofIsIdempotent(t *testing.T) {
	f := newCheckpointTestFixture(t)
	seq := uint64(100)
	f.seedRequestDigests(t, seq)
	digest := f.localDigest(t, seq)

	f.stepCheckpoint(t, 2, seq, digest)
	f.stepCheckpoint(t, 2, seq, digest)
	f.stepCheckpoint(t, 3, seq, digest)

	require.Len(t, f.node.checkpoints[seq][digest], 2)
	require.Nil(t, f.node.stableCheckpoint)
}

func TestCheckpoint_IgnoresMismatchedDigest(t *testing.T) {
	f := newCheckpointTestFixture(t)
	f.seedRequestDigests(t, 100)

	err := f.node.Step(f.ctx, f.signCheckpoint(2, 100, hashData([]byte("wrong"))))
	require.NoError(t, err)
	require.Empty(t, f.node.checkpoints)
}

func TestCheckpoint_IgnoresWhenNotExecutedThrough(t *testing.T) {
	f := newCheckpointTestFixture(t)
	f.seedRequestDigests(t, 50)

	err := f.node.Step(f.ctx, f.signCheckpoint(2, 100, hashData([]byte("any"))))
	require.NoError(t, err)
	require.Empty(t, f.node.checkpoints)
}

func TestCheckpoint_DoesNotDiscardBeforeStable(t *testing.T) {
	f := newCheckpointTestFixture(t)
	f.seedRequestDigests(t, 100)
	digest := f.localDigest(t, 100)

	f.stepCheckpoint(t, 2, 100, digest)
	f.stepCheckpoint(t, 3, 100, digest)

	require.Nil(t, f.node.stableCheckpoint)
	require.Contains(t, f.node.pp, bftSeqKey{view: 0, seq: 50})
}

func TestCheckpoint_InitialWatermarks(t *testing.T) {
	f := newCheckpointTestFixture(t)
	require.Equal(t, uint64(0), f.node.lowW)
	require.Equal(t, uint64(WatermarkWindow), f.node.highW)
	require.Greater(t, WatermarkWindow, CheckpointInterval)
}

func TestCheckpoint_InvalidSignatureRejected(t *testing.T) {
	f := newCheckpointTestFixture(t)
	msg := f.signCheckpoint(2, 100, hashData([]byte("state")))
	msg.Context[len(msg.Context)-1] ^= 0xff

	err := f.node.Step(f.ctx, msg)
	require.ErrorIs(t, err, ErrInvalidSignature)
}

func TestCheckpoint_UnknownSignerRejected(t *testing.T) {
	f := newCheckpointTestFixture(t)
	msg := f.signCheckpoint(2, 100, hashData([]byte("state")))
	msg.From = u64p(99)

	err := f.node.Step(f.ctx, msg)
	require.ErrorIs(t, err, ErrUnknownSigner)
}
