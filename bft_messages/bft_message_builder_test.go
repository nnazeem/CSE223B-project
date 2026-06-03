package raft

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	pb "go.etcd.io/raft/v3/raftpb"
)

func TestBFTMessageBuilder_ConstructClientRequest(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	now := time.Unix(1_700_000_000, 0)
	builder := NewBFTMessageBuilder(100, priv, &ClientProofConfig{Now: func() time.Time { return now }})

	msg, ts, err := builder.ConstructClientRequest(1, []byte("op:set x=1"))
	require.NoError(t, err)
	require.Equal(t, pb.MsgProp, msg.GetType())
	require.Equal(t, uint64(100), msg.GetFrom())
	require.Equal(t, uint64(1), msg.GetTo())
	require.Len(t, msg.GetEntries(), 1)
	require.Equal(t, []byte("op:set x=1"), msg.GetEntries()[0].GetData())

	verifyTS, origCtx, err := VerifyBFTMessageSignature(&msg, pub)
	require.NoError(t, err)
	require.Equal(t, ts, verifyTS)
	require.Empty(t, origCtx)
}

func TestBFTMessageBuilder_ConstructPrePrepare(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	now := time.Unix(1_700_000_000, 0)
	builder := NewBFTMessageBuilder(1, priv, &ClientProofConfig{Now: func() time.Time { return now }})

	request := pb.Message{
		Type: pb.MsgProp.Enum(),
		From: u64Ptr(100),
		Entries: []*pb.Entry{{
			Data: []byte("write:k=v"),
		}},
	}
	bctxPP, ppMsg, _, err := builder.ConstructPrePrepare(2, 7, 42, request)
	require.NoError(t, err)
	require.Equal(t, PhasePrePrepare, bctxPP.Phase)
	require.Equal(t, uint64(7), bctxPP.View)
	require.Equal(t, uint64(42), bctxPP.SeqNum)
	require.Equal(t, hashData([]byte("write:k=v")), bctxPP.Digest)
	require.Equal(t, pb.MsgApp, ppMsg.GetType())
	require.Equal(t, uint64(1), ppMsg.GetFrom())
	require.Equal(t, uint64(2), ppMsg.GetTo())
	require.Len(t, ppMsg.GetEntries(), 1)

	_, ppOrigCtx, err := VerifyBFTMessageSignature(&ppMsg, pub)
	require.NoError(t, err)
	decodedPP, err := decodeBFTContext(ppOrigCtx)
	require.NoError(t, err)
	require.Equal(t, PhasePrePrepare, decodedPP.Phase)
	require.Equal(t, uint64(7), decodedPP.View)
	require.Equal(t, uint64(42), decodedPP.SeqNum)
	require.Equal(t, bctxPP.Digest, decodedPP.Digest)
}

func TestBFTMessageBuilder_ConstructPrepare(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	now := time.Unix(1_700_000_000, 0)
	builder := NewBFTMessageBuilder(1, priv, &ClientProofConfig{Now: func() time.Time { return now }})

	digest := hashData([]byte("write:k=v"))
	pMsg, _, err := builder.ConstructPrepare(3, 7, 42, digest)
	require.NoError(t, err)
	require.Equal(t, pb.MsgApp, pMsg.GetType())
	require.Equal(t, uint64(1), pMsg.GetFrom())
	require.Equal(t, uint64(3), pMsg.GetTo())

	_, pOrigCtx, err := VerifyBFTMessageSignature(&pMsg, pub)
	require.NoError(t, err)
	decodedP, err := decodeBFTContext(pOrigCtx)
	require.NoError(t, err)
	require.Equal(t, PhasePrepare, decodedP.Phase)
	require.Equal(t, uint64(7), decodedP.View)
	require.Equal(t, uint64(42), decodedP.SeqNum)
	require.Equal(t, digest, decodedP.Digest)
}

func TestBFTMessageBuilder_ConstructCommit(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	now := time.Unix(1_700_000_001, 0)
	builder := NewBFTMessageBuilder(2, priv, &ClientProofConfig{Now: func() time.Time { return now }})

	digest := hashData([]byte("m"))
	commitMsg, _, err := builder.ConstructCommit(3, 9, 77, digest)
	require.NoError(t, err)
	_, commitCtxBytes, err := VerifyBFTMessageSignature(&commitMsg, pub)
	require.NoError(t, err)
	commitCtx, err := decodeBFTContext(commitCtxBytes)
	require.NoError(t, err)
	require.Equal(t, PhaseCommit, commitCtx.Phase)
	require.Equal(t, uint64(9), commitCtx.View)
	require.Equal(t, uint64(77), commitCtx.SeqNum)
	require.Equal(t, digest, commitCtx.Digest)
}

func TestBFTMessageBuilder_ConstructCheckpoint(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	now := time.Unix(1_700_000_001, 0)
	builder := NewBFTMessageBuilder(2, priv, &ClientProofConfig{Now: func() time.Time { return now }})

	stateDigest := hashData([]byte("state@77"))
	checkpointMsg, _, err := builder.ConstructCheckpoint(4, 77, stateDigest)
	require.NoError(t, err)
	_, checkpointCtxBytes, err := VerifyBFTMessageSignature(&checkpointMsg, pub)
	require.NoError(t, err)
	checkpointCtx, err := decodeBFTContext(checkpointCtxBytes)
	require.NoError(t, err)
	require.Equal(t, PhaseCheckpoint, checkpointCtx.Phase)
	require.Equal(t, uint64(77), checkpointCtx.CheckpointSeqNum)
	require.Equal(t, stateDigest, checkpointCtx.CheckpointDigest)
}

func TestBFTMessageBuilder_ConstructViewChange(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	now := time.Unix(1_700_000_001, 0)
	builder := NewBFTMessageBuilder(2, priv, &ClientProofConfig{Now: func() time.Time { return now }})

	digest := hashData([]byte("m"))
	checkpointProofs := []BFTPreparedProof{{View: 8, SeqNum: 70, Digest: hashData([]byte("cp"))}}
	preparedProofs := []BFTPreparedProof{{View: 9, SeqNum: 77, Digest: digest}}
	vcMsg, _, err := builder.ConstructViewChange(5, 10, 70, checkpointProofs, preparedProofs)
	require.NoError(t, err)
	_, vcCtxBytes, err := VerifyBFTMessageSignature(&vcMsg, pub)
	require.NoError(t, err)
	vcCtx, err := decodeBFTContext(vcCtxBytes)
	require.NoError(t, err)
	require.Equal(t, PhaseViewChange, vcCtx.Phase)
	require.Equal(t, uint64(10), vcCtx.View)
	require.Equal(t, uint64(70), vcCtx.CheckpointSeqNum)
	require.Equal(t, checkpointProofs, vcCtx.CheckpointProofs)
	require.Equal(t, preparedProofs, vcCtx.PreparedProofs)
}

func TestBFTMessageBuilder_ConstructNewView(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	now := time.Unix(1_700_000_001, 0)
	builder := NewBFTMessageBuilder(2, priv, &ClientProofConfig{Now: func() time.Time { return now }})

	viewSet := [][]byte{[]byte("vc1"), []byte("vc2")}
	prePrepareSet := []BFTPrePrepareMeta{{View: 10, SeqNum: 78, Digest: hashData([]byte("o1"))}}
	nvMsg, _, err := builder.ConstructNewView(6, 11, viewSet, prePrepareSet)
	require.NoError(t, err)
	_, nvCtxBytes, err := VerifyBFTMessageSignature(&nvMsg, pub)
	require.NoError(t, err)
	nvCtx, err := decodeBFTContext(nvCtxBytes)
	require.NoError(t, err)
	require.Equal(t, PhaseNewView, nvCtx.Phase)
	require.Equal(t, uint64(11), nvCtx.View)
	require.Equal(t, viewSet, nvCtx.ViewSet)
	require.Equal(t, prePrepareSet, nvCtx.PrePrepareSet)
}

func TestBFTMessageBuilder_ConstructReply(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	now := time.Unix(1_700_000_001, 0)
	builder := NewBFTMessageBuilder(2, priv, &ClientProofConfig{Now: func() time.Time { return now }})

	replyMsg, _, err := builder.ConstructReply(100, 11, 1_700_000_123, 100, []byte("ok"))
	require.NoError(t, err)
	_, replyCtxBytes, err := VerifyBFTMessageSignature(&replyMsg, pub)
	require.NoError(t, err)
	replyCtx, err := decodeBFTContext(replyCtxBytes)
	require.NoError(t, err)
	require.Equal(t, PhaseReply, replyCtx.Phase)
	require.Equal(t, uint64(11), replyCtx.View)
	require.Equal(t, int64(1_700_000_123), replyCtx.RequestTimestamp)
	require.Equal(t, uint64(100), replyCtx.ClientID)
	require.Equal(t, []byte("ok"), replyCtx.Result)
}
