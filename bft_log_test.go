package raft

import (
	"context"
	"crypto/ed25519"
	"testing"

	"github.com/stretchr/testify/require"
	pb "go.etcd.io/raft/v3/raftpb"
)

func TestBFTLog_PrimaryAppendsPrePrepare(t *testing.T) {
	node, client, _, _ := setupCluster(t)
	ctx := context.Background()

	err := client.Propose(ctx, []byte("payload"))
	require.NoError(t, err)
	prop := <-client.Ready()

	err = node.Step(ctx, prop)
	require.NoError(t, err)

	node.mu.Lock()
	require.GreaterOrEqual(t, len(node.messageLog), 1)
	require.Equal(t, PhasePrePrepare, node.messageLog[0].phase)
	require.Equal(t, uint64(1), node.messageLog[0].seqNum)
	require.Contains(t, node.seqNumToLogIndex, bftSeqKey{view: 0, seq: 1})
	node.mu.Unlock()
}

func TestBFTLog_BackupAppendsPrePrepareAndPrepare(t *testing.T) {
	node, _, nodePrivs, _ := setupCluster(t)
	ctx := context.Background()

	bctx := BFTContext{Phase: PhasePrePrepare, View: 0, SeqNum: 1, Digest: hashData([]byte("test"))}
	encCtx, _ := encodeBFTContext(bctx)
	msg := &pb.Message{
		Type:    pb.MsgApp.Enum(),
		From:    u64p(2),
		Term:    u64p(1),
		Context: encCtx,
		Entries: []*pb.Entry{{Data: []byte("test")}},
	}
	origCtx := normalizeContext(msg.Context)
	data, _ := messageSignBytes(msg, origCtx, 100)
	msg.Context = packSignature(ed25519.Sign(nodePrivs[2], data), 100, origCtx)

	err := node.Step(ctx, msg)
	require.NoError(t, err)

	node.mu.Lock()
	defer node.mu.Unlock()
	require.GreaterOrEqual(t, len(node.messageLog), 2)
	require.Equal(t, PhasePrePrepare, node.messageLog[0].phase)
	require.Equal(t, uint64(2), node.messageLog[0].replica)
	require.Equal(t, PhasePrepare, node.messageLog[1].phase)
	require.Equal(t, uint64(1), node.messageLog[1].replica)
}

func TestBFTLog_CommitAppendedOnQuorum(t *testing.T) {
	node, _, nodePrivs, mock := setupCluster(t)
	ctx := context.Background()

	bctx := BFTContext{Phase: PhasePrePrepare, View: 0, SeqNum: 1, Digest: hashData([]byte("test"))}
	encCtx, _ := encodeBFTContext(bctx)
	msg := &pb.Message{Type: pb.MsgApp.Enum(), From: u64p(2), Term: u64p(1), Context: encCtx}
	origCtx := normalizeContext(msg.Context)
	data, _ := messageSignBytes(msg, origCtx, 100)
	msg.Context = packSignature(ed25519.Sign(nodePrivs[2], data), 100, origCtx)
	_ = node.Step(ctx, msg)
	<-node.Ready()
	node.Advance()
	mock.readyc <- Ready{}
	<-node.Ready()
	node.Advance()

	bctx.Phase = PhasePrepare
	encPCtx, _ := encodeBFTContext(bctx)
	pMsg := &pb.Message{Type: pb.MsgApp.Enum(), From: u64p(3), Term: u64p(1), Context: encPCtx}
	origPCtx := normalizeContext(pMsg.Context)
	pData, _ := messageSignBytes(pMsg, origPCtx, 200)
	pMsg.Context = packSignature(ed25519.Sign(nodePrivs[3], pData), 200, origPCtx)
	err := node.Step(ctx, pMsg)
	require.NoError(t, err)

	node.mu.Lock()
	hasCommit := false
	for _, rec := range node.messageLog {
		if rec.phase == PhaseCommit {
			hasCommit = true
		}
	}
	require.True(t, hasCommit)
	node.mu.Unlock()
}

func TestBFTLog_LastAppliedSeqNumOnCommitQuorum(t *testing.T) {
	node, _, nodePrivs, _ := setupCluster(t)
	ctx := context.Background()

	bctx := BFTContext{Phase: PhasePrePrepare, View: 0, SeqNum: 1, Digest: hashData([]byte("test"))}
	encCtx, _ := encodeBFTContext(bctx)
	msg := &pb.Message{Type: pb.MsgApp.Enum(), From: u64p(2), Term: u64p(1), Context: encCtx}
	origCtx := normalizeContext(msg.Context)
	data, _ := messageSignBytes(msg, origCtx, 100)
	msg.Context = packSignature(ed25519.Sign(nodePrivs[2], data), 100, origCtx)
	_ = node.Step(ctx, msg)

	bctx.Phase = PhasePrepare
	encPCtx, _ := encodeBFTContext(bctx)
	for _, from := range []uint64{3, 4} {
		pMsg := &pb.Message{Type: pb.MsgApp.Enum(), From: u64p(from), Term: u64p(1), Context: encPCtx}
		origPCtx := normalizeContext(pMsg.Context)
		pData, _ := messageSignBytes(pMsg, origPCtx, int64(from))
		pMsg.Context = packSignature(ed25519.Sign(nodePrivs[from], pData), int64(from), origPCtx)
		_ = node.Step(ctx, pMsg)
	}

	bctx.Phase = PhaseCommit
	encCCtx, _ := encodeBFTContext(bctx)
	for _, from := range []uint64{2, 3} {
		cMsg := &pb.Message{Type: pb.MsgApp.Enum(), From: u64p(from), Term: u64p(1), Context: encCCtx}
		origCCtx := normalizeContext(cMsg.Context)
		cData, _ := messageSignBytes(cMsg, origCCtx, int64(from+100))
		cMsg.Context = packSignature(ed25519.Sign(nodePrivs[from], cData), int64(from+100), origCCtx)
		_ = node.Step(ctx, cMsg)
	}

	node.mu.Lock()
	require.Equal(t, uint64(1), node.lastAppliedSeqNum)
	node.mu.Unlock()
}

func TestBFTLog_StableProofRetainedAfterCheckpoint(t *testing.T) {
	f := newCheckpointTestFixture(t)
	f.seedRequestDigests(t, 100)
	digest := f.localDigest(t, 100)

	for _, from := range []uint64{2, 3, 4} {
		f.stepCheckpoint(t, from, 100, digest)
	}

	f.node.mu.Lock()
	defer f.node.mu.Unlock()
	require.NotNil(t, f.node.stableCheckpoint)

	foundProof := false
	for _, rec := range f.node.messageLog {
		if rec.stableProof && rec.checkpointSeq == 100 {
			foundProof = true
			require.Len(t, rec.stableProofs, 3)
		}
		if rec.logSeq() <= 100 && !rec.stableProof {
			t.Fatalf("expected log records at or below stable seq to be truncated, found seq %d phase %v", rec.logSeq(), rec.phase)
		}
	}
	require.True(t, foundProof)
}

func TestBFTLog_NoDuplicatePrePrepare(t *testing.T) {
	node, _, nodePrivs, _ := setupCluster(t)
	ctx := context.Background()

	bctx := BFTContext{Phase: PhasePrePrepare, View: 0, SeqNum: 1, Digest: hashData([]byte("test"))}
	encCtx, _ := encodeBFTContext(bctx)
	msg := &pb.Message{Type: pb.MsgApp.Enum(), From: u64p(2), Term: u64p(1), Context: encCtx}
	origCtx := normalizeContext(msg.Context)
	data, _ := messageSignBytes(msg, origCtx, 100)
	msg.Context = packSignature(ed25519.Sign(nodePrivs[2], data), 100, origCtx)

	_ = node.Step(ctx, msg)
	before := node.MessageLogLen()
	_ = node.Step(ctx, msg)
	after := node.MessageLogLen()
	require.Equal(t, before, after)
}
