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

	_, clientPriv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	requestTS := int64(1_700_000_000_123)
	request := pb.Message{
		Type: pb.MsgProp.Enum(),
		From: u64Ptr(100),
		To:   u64Ptr(1),
		Entries: []*pb.Entry{{
			Data: []byte("write:k=v"),
		}},
	}
	reqData, err := messageSignBytes(&request, normalizeContext(request.Context), requestTS)
	require.NoError(t, err)
	request.Context = packSignature(ed25519.Sign(clientPriv, reqData), requestTS, normalizeContext(request.Context))

	bctxPP, ppMsg, _, err := builder.ConstructPrePrepare(2, 7, 42, request)
	require.NoError(t, err)
	expectedDigest, err := hashEntryBatch(request.GetEntries())
	require.NoError(t, err)
	require.Equal(t, PhasePrePrepare, bctxPP.Phase)
	require.Equal(t, uint64(7), bctxPP.View)
	require.Equal(t, uint64(42), bctxPP.SeqNum)
	require.Equal(t, expectedDigest, bctxPP.Digest)
	require.Equal(t, uint64(100), bctxPP.ClientID)
	require.Equal(t, requestTS, bctxPP.RequestTimestamp)
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
	require.Equal(t, uint64(100), decodedPP.ClientID)
	require.Equal(t, requestTS, decodedPP.RequestTimestamp)
}

func TestBFTMessageBuilder_ConstructPrePrepare_MultiEntryDigestCoversFullBatch(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	now := time.Unix(1_700_000_003, 0)
	builder := NewBFTMessageBuilder(1, priv, &ClientProofConfig{Now: func() time.Time { return now }})

	requestA := pb.Message{
		Type: pb.MsgProp.Enum(),
		From: u64Ptr(100),
		Entries: []*pb.Entry{
			{Data: []byte("same-first")},
			{Data: []byte("second-a")},
		},
	}
	requestB := pb.Message{
		Type: pb.MsgProp.Enum(),
		From: u64Ptr(100),
		Entries: []*pb.Entry{
			{Data: []byte("same-first")},
			{Data: []byte("second-b")},
		},
	}

	_, clientPriv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	dataA, err := messageSignBytes(&requestA, normalizeContext(requestA.Context), int64(101))
	require.NoError(t, err)
	requestA.Context = packSignature(ed25519.Sign(clientPriv, dataA), int64(101), normalizeContext(requestA.Context))
	dataB, err := messageSignBytes(&requestB, normalizeContext(requestB.Context), int64(102))
	require.NoError(t, err)
	requestB.Context = packSignature(ed25519.Sign(clientPriv, dataB), int64(102), normalizeContext(requestB.Context))

	bctxA, _, _, err := builder.ConstructPrePrepare(2, 7, 42, requestA)
	require.NoError(t, err)
	bctxB, _, _, err := builder.ConstructPrePrepare(2, 7, 42, requestB)
	require.NoError(t, err)

	require.NotEqual(t, bctxA.Digest, bctxB.Digest)
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

	checkpointDigest := hashData([]byte("cp"))
	checkpointProof := BFTCheckpointProof{
		SeqNum:      70,
		Digest:      checkpointDigest,
		Checkpoints: nil,
	}

	digest := hashData([]byte("m"))
	preparedProofs := []BFTPreparedProof{
		{View: 9, SeqNum: 77, Digest: digest},
	}

	vcMsg, _, err := builder.ConstructViewChange(
		5,
		10,
		70,
		checkpointProof,
		preparedProofs,
	)
	require.NoError(t, err)

	_, vcCtxBytes, err := VerifyBFTMessageSignature(&vcMsg, pub)
	require.NoError(t, err)

	vcCtx, err := decodeBFTContext(vcCtxBytes)
	require.NoError(t, err)

	require.Equal(t, PhaseViewChange, vcCtx.Phase)
	require.Equal(t, uint64(10), vcCtx.View)
	require.Equal(t, uint64(70), vcCtx.SeqNum)
	require.Equal(t, uint64(70), vcCtx.CheckpointSeqNum)
	require.Equal(t, checkpointDigest, vcCtx.CheckpointDigest)
	require.Equal(t, checkpointProof, vcCtx.CheckpointProofs)
	require.Equal(t, preparedProofs, vcCtx.PreparedProofs)
}

func TestBFTMessageBuilder_ConstructNewView(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	now := time.Unix(1_700_000_001, 0)
	builder := NewBFTMessageBuilder(2, priv, &ClientProofConfig{Now: func() time.Time { return now }})

	viewSet := []pb.Message{
		{
			Type: pb.MsgApp.Enum(),
			From: u64Ptr(1),
			To:   u64Ptr(2),
		},
		{
			Type: pb.MsgApp.Enum(),
			From: u64Ptr(3),
			To:   u64Ptr(2),
		},
	}

	clientReq := &pb.Message{
		Type:    pb.MsgProp.Enum(),
		From:    u64Ptr(100),
		To:      u64Ptr(2),
		Entries: []*pb.Entry{{Data: []byte("o1")}},
	}
	_, clientPriv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	reqData, err := messageSignBytes(clientReq, normalizeContext(clientReq.Context), int64(123))
	require.NoError(t, err)
	clientReq.Context = packSignature(ed25519.Sign(clientPriv, reqData), int64(123), normalizeContext(clientReq.Context))

	digest, err := hashEntryBatch(clientReq.GetEntries())
	require.NoError(t, err)

	ppCtx := BFTContext{
		Phase:            PhasePrePrepare,
		View:             11,
		SeqNum:           78,
		Digest:           digest,
		RequestTimestamp: 123,
		ClientID:         100,
		ClientRequest:    *clientReq,
	}
	encCtx, err := encodeBFTContext(ppCtx)
	require.NoError(t, err)

	prePrepareSet := []pb.Message{
		{
			Type:    pb.MsgApp.Enum(),
			From:    u64Ptr(2),
			Context: encCtx,
			Entries: []*pb.Entry{{Data: []byte("o1")}},
		},
	}

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
