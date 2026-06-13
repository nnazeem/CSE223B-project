package raft

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/stretchr/testify/require"
	pb "go.etcd.io/raft/v3/raftpb"
)

func makeAdditionalSignedPrePrepare(
	t *testing.T,
	fx *bftNetworkFixture,
	from uint64,
	to uint64,
	view uint64,
	seq uint64,
	payload []byte,
	requestTS int64,
	clientID uint64,
	signTS int64,
) (*pb.Message, [32]byte) {
	t.Helper()

	entries := []*pb.Entry{{Data: payload}}
	digest, err := hashEntryBatch(entries)
	require.NoError(t, err)

	clientReq := signClientRequestForTest(t, clientID, fx.nodes[from].primaryForView(view), payload, fx.client.priv, requestTS)

	bctx := BFTContext{
		Phase:            PhasePrePrepare,
		View:             view,
		SeqNum:           seq,
		Digest:           digest,
		RequestTimestamp: requestTS,
		ClientID:         clientID,
		ClientRequest:    *proto.Clone(clientReq).(*pb.Message),
	}
	encCtx, err := encodeBFTContext(bctx)
	require.NoError(t, err)

	msg := &pb.Message{
		Type:    pb.MsgApp.Enum(),
		From:    u64p(from),
		To:      u64p(to),
		Context: encCtx,
		Entries: cloneEntries(entries),
	}
	signTestNodeMessage(t, msg, fx.nodePrivs[from], signTS)
	return msg, digest
}

func makeAdditionalSignedPhaseMessage(
	t *testing.T,
	fx *bftNetworkFixture,
	phase BFTPhase,
	from uint64,
	to uint64,
	view uint64,
	seq uint64,
	digest [32]byte,
	signTS int64,
) *pb.Message {
	t.Helper()

	bctx := BFTContext{Phase: phase, View: view, SeqNum: seq, Digest: digest}
	encCtx, err := encodeBFTContext(bctx)
	require.NoError(t, err)

	msg := &pb.Message{Type: pb.MsgApp.Enum(), From: u64p(from), To: u64p(to), Context: encCtx}
	signTestNodeMessage(t, msg, fx.nodePrivs[from], signTS)
	return msg
}

func makeAdditionalSignedCheckpoint(
	t *testing.T,
	fx *bftNetworkFixture,
	from uint64,
	seq uint64,
	digest [32]byte,
	signTS int64,
) pb.Message {
	t.Helper()

	bctx := BFTContext{
		Phase:            PhaseCheckpoint,
		SeqNum:           seq,
		Digest:           digest,
		CheckpointSeqNum: seq,
		CheckpointDigest: digest,
	}
	encCtx, err := encodeBFTContext(bctx)
	require.NoError(t, err)

	msg := &pb.Message{Type: pb.MsgApp.Enum(), From: u64p(from), Context: encCtx}
	signTestNodeMessage(t, msg, fx.nodePrivs[from], signTS)
	return *msg
}

func makeAdditionalSignedViewChange(
	t *testing.T,
	fx *bftNetworkFixture,
	from uint64,
	newView uint64,
	checkpointProof BFTCheckpointProof,
	preparedProofs []BFTPreparedProof,
	signTS int64,
) *pb.Message {
	t.Helper()

	bctx := BFTContext{
		Phase:            PhaseViewChange,
		View:             newView,
		SeqNum:           checkpointProof.SeqNum,
		CheckpointSeqNum: checkpointProof.SeqNum,
		CheckpointDigest: checkpointProof.Digest,
		CheckpointProofs: checkpointProof,
		PreparedProofs:   append([]BFTPreparedProof(nil), preparedProofs...),
	}
	encCtx, err := encodeBFTContext(bctx)
	require.NoError(t, err)

	msg := &pb.Message{Type: pb.MsgApp.Enum(), From: u64p(from), Context: encCtx}
	signTestNodeMessage(t, msg, fx.nodePrivs[from], signTS)
	return msg
}

func drainAdditionalReadyIfAny(t *testing.T, node *BFTNode) []*pb.Message {
	t.Helper()
	select {
	case rd := <-node.Ready():
		msgs := append([]*pb.Message(nil), rd.Messages...)
		node.Advance()
		return msgs
	case <-time.After(25 * time.Millisecond):
		return nil
	}
}

func TestBFTByzantine_PrepareBeforePrePrepareRejected(t *testing.T) {
	fx := newBFTNetworkFixture(t)
	target := fx.nodes[2]
	payload := []byte("prepare-without-preprepare")
	digest := entryDigest(t, payload)
	key := bftSeqKey{view: 0, seq: 1}

	prepare := makeAdditionalSignedPhaseMessage(t, fx, PhasePrepare, 3, 2, 0, 1, digest, 101)
	err := target.Step(fx.ctx, prepare)
	require.ErrorContains(t, err, "prepare does not match accepted pre-prepare")
	require.NotContains(t, target.pp, key)
	require.NotContains(t, target.prepares, key)
	require.NotContains(t, target.log, uint64(1))
}

func TestBFTByzantine_CommitBeforePrePrepareRejected(t *testing.T) {
	fx := newBFTNetworkFixture(t)
	target := fx.nodes[2]
	payload := []byte("commit-without-preprepare")
	digest := entryDigest(t, payload)
	key := bftSeqKey{view: 0, seq: 1}

	commit := makeAdditionalSignedPhaseMessage(t, fx, PhaseCommit, 3, 2, 0, 1, digest, 102)
	err := target.Step(fx.ctx, commit)
	require.ErrorContains(t, err, "commit does not match accepted pre-prepare")
	require.NotContains(t, target.pp, key)
	require.NotContains(t, target.commits, key)
	require.NotContains(t, target.log, uint64(1))
}

func TestBFTByzantine_DuplicateCommitFromOneReplicaDoesNotCommit(t *testing.T) {
	fx := newBFTNetworkFixture(t)
	target := fx.nodes[2]
	payload := []byte("duplicate-commit")
	seq := uint64(1)
	key := bftSeqKey{view: 0, seq: seq}

	pp, digest := makeAdditionalSignedPrePrepare(t, fx, 1, 2, 0, seq, payload, 1_001, 100, 201)
	require.NoError(t, target.Step(fx.ctx, pp))
	_ = drainNodeReadyMessages(t, target)

	prepare := makeAdditionalSignedPhaseMessage(t, fx, PhasePrepare, 3, 2, 0, seq, digest, 202)
	require.NoError(t, target.Step(fx.ctx, prepare))
	_ = drainNodeReadyMessages(t, target)

	commit := makeAdditionalSignedPhaseMessage(t, fx, PhaseCommit, 3, 2, 0, seq, digest, 203)
	require.NoError(t, target.Step(fx.ctx, proto.Clone(commit).(*pb.Message)))
	require.NoError(t, target.Step(fx.ctx, proto.Clone(commit).(*pb.Message)))

	require.Contains(t, target.commits, key)
	require.Len(t, target.commits[key], 2, "self commit plus one faulty replica must not become 2f+1")
	require.NotContains(t, target.log, seq)
}

func TestBFTByzantine_TamperedPrepareSignatureRejected(t *testing.T) {
	fx := newBFTNetworkFixture(t)
	target := fx.nodes[2]
	payload := []byte("tampered-prepare")
	digest := entryDigest(t, payload)

	prepare := makeAdditionalSignedPhaseMessage(t, fx, PhasePrepare, 3, 2, 0, 1, digest, 301)
	prepare.Context[len(prepare.Context)-1] ^= 0xff

	err := target.Step(fx.ctx, prepare)
	require.ErrorIs(t, err, ErrInvalidSignature)
	require.NotContains(t, target.log, uint64(1))
}

func TestBFTByzantine_UnknownReplicaCommitRejected(t *testing.T) {
	fx := newBFTNetworkFixture(t)
	target := fx.nodes[2]
	payload := []byte("unknown-replica-commit")
	digest := entryDigest(t, payload)

	bctx := BFTContext{Phase: PhaseCommit, View: 0, SeqNum: 1, Digest: digest}
	encCtx, err := encodeBFTContext(bctx)
	require.NoError(t, err)

	_, unknownPriv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	commit := &pb.Message{Type: pb.MsgApp.Enum(), From: u64p(99), To: u64p(2), Context: encCtx}
	signTestNodeMessage(t, commit, unknownPriv, 401)

	err = target.Step(fx.ctx, commit)
	require.ErrorIs(t, err, ErrUnknownSigner)
	require.NotContains(t, target.log, uint64(1))
}

func TestBFTByzantine_NewViewFromNonPrimaryRejected(t *testing.T) {
	fx := newBFTNetworkFixture(t)
	target := fx.nodes[3]
	view := uint64(1) // primary for view 1 is node 2.

	vc1 := makeSignedViewChangeForByzantineTest(t, fx, 1, view, 501)
	vc2 := makeSignedViewChangeForByzantineTest(t, fx, 2, view, 502)
	vc4 := makeSignedViewChangeForByzantineTest(t, fx, 4, view, 504)

	nv := makeSignedNewViewForByzantineTest(t, fx, 3, 3, view, []pb.Message{vc1, vc2, vc4}, nil, 505)
	err := target.Step(fx.ctx, nv)
	require.ErrorIs(t, err, ErrInvalidNewView)
	require.Equal(t, uint64(0), target.view)
	require.Equal(t, Normal, target.nodePhase)
}

func TestBFTByzantine_NewViewWithDuplicateViewChangesRejected(t *testing.T) {
	fx := newBFTNetworkFixture(t)
	target := fx.nodes[3]
	view := uint64(1)

	vc1 := makeSignedViewChangeForByzantineTest(t, fx, 1, view, 601)
	vc2 := makeSignedViewChangeForByzantineTest(t, fx, 2, view, 602)
	nv := makeSignedNewViewForByzantineTest(t, fx, 2, 3, view, []pb.Message{vc1, *proto.Clone(&vc1).(*pb.Message), vc2}, nil, 603)

	err := target.Step(fx.ctx, nv)
	require.ErrorIs(t, err, ErrInvalidNewView)
	require.Equal(t, uint64(0), target.view)
	require.Equal(t, Normal, target.nodePhase)
}

func TestBFTByzantine_NewViewWithUnexpectedPrePrepareSetRejected(t *testing.T) {
	fx := newBFTNetworkFixture(t)
	target := fx.nodes[3]
	view := uint64(1) // primary for view 1 is node 2.

	vc1 := makeSignedViewChangeForByzantineTest(t, fx, 1, view, 701)
	vc2 := makeSignedViewChangeForByzantineTest(t, fx, 2, view, 702)
	vc4 := makeSignedViewChangeForByzantineTest(t, fx, 4, view, 704)

	unexpectedPP, _ := makeAdditionalSignedPrePrepare(t, fx, 2, 3, view, 1, []byte("unexpected-o-entry"), 1_701, 100, 705)
	nv := makeSignedNewViewForByzantineTest(t, fx, 2, 3, view, []pb.Message{vc1, vc2, vc4}, []pb.Message{*unexpectedPP}, 706)

	err := target.Step(fx.ctx, nv)
	require.ErrorIs(t, err, ErrInvalidNewView)
	require.Equal(t, uint64(0), target.view)
	require.NotContains(t, target.log, uint64(1))
}

func TestBFTByzantine_ViewChangePreparedProofWithoutPrePrepareRejected(t *testing.T) {
	fx := newBFTNetworkFixture(t)
	target := fx.nodes[3]
	payload := []byte("prepared-proof-without-preprepare")
	digest := entryDigest(t, payload)

	p2 := makeAdditionalSignedPhaseMessage(t, fx, PhasePrepare, 2, 0, 0, 1, digest, 801)
	p4 := makeAdditionalSignedPhaseMessage(t, fx, PhasePrepare, 4, 0, 0, 1, digest, 804)
	proof := BFTPreparedProof{View: 0, SeqNum: 1, Digest: digest, Prepares: []pb.Message{*p2, *p4}}
	vc := makeAdditionalSignedViewChange(t, fx, 2, 1, BFTCheckpointProof{}, []BFTPreparedProof{proof}, 805)

	err := target.Step(fx.ctx, vc)
	require.ErrorIs(t, err, ErrInvalidPreparedProof)
	require.Equal(t, uint64(0), target.view)
}

func TestBFTByzantine_ClientDoesNotAcceptConflictingReplies(t *testing.T) {
	fx := newBFTNetworkFixture(t)
	require.NoError(t, fx.client.Propose(fx.ctx, []byte("conflicting-replies")))

	var reqTS int64
	for ts := range fx.client.pending {
		reqTS = ts
	}
	require.NotZero(t, reqTS)

	makeReply := func(from uint64, result []byte, signTS int64) *pb.Message {
		bctx := BFTContext{Phase: PhaseReply, View: 0, RequestTimestamp: reqTS, ClientID: fx.client.selfID, Result: append([]byte(nil), result...)}
		encCtx, err := encodeBFTContext(bctx)
		require.NoError(t, err)
		msg := &pb.Message{Type: pb.MsgApp.Enum(), From: u64p(from), To: u64p(fx.client.selfID), Context: encCtx}
		signTestNodeMessage(t, msg, fx.nodePrivs[from], signTS)
		return msg
	}

	require.NoError(t, fx.client.Step(fx.ctx, makeReply(2, []byte("OK"), 901)))
	require.NoError(t, fx.client.Step(fx.ctx, makeReply(3, []byte("BAD"), 902)))

	select {
	case result := <-fx.client.ConsensusC:
		t.Fatalf("client accepted conflicting replies without f+1 matching results: %q", string(result))
	case <-time.After(50 * time.Millisecond):
	}

	require.Len(t, fx.client.pending, 1)
}
