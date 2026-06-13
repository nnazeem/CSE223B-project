package raft

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/stretchr/testify/require"
	pb "go.etcd.io/raft/v3/raftpb"
)

type bftNetworkFixture struct {
	ctx       context.Context
	nodes     map[uint64]*BFTNode
	mocks     map[uint64]*mockNode
	nodePrivs map[uint64]ed25519.PrivateKey
	nodePubs  map[uint64]ed25519.PublicKey
	client    *BFTClient
	clientPub ed25519.PublicKey
}

func newBFTNetworkFixture(t *testing.T) *bftNetworkFixture {
	t.Helper()

	clientPub, clientPriv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	nodePubs := make(map[uint64]ed25519.PublicKey)
	nodePrivs := make(map[uint64]ed25519.PrivateKey)
	for id := uint64(1); id <= 4; id++ {
		pub, priv, err := ed25519.GenerateKey(nil)
		require.NoError(t, err)
		nodePubs[id] = pub
		nodePrivs[id] = priv
	}

	cfg := &ClientProofConfig{MaxAge: 30 * time.Second, Now: time.Now}
	clientIDs := []uint64{100}

	fx := &bftNetworkFixture{
		ctx:       context.Background(),
		nodes:     make(map[uint64]*BFTNode),
		mocks:     make(map[uint64]*mockNode),
		nodePrivs: nodePrivs,
		nodePubs:  nodePubs,
		client:    NewBFTClient(100, 4, clientPriv, nodePubs, clientIDs, clientPub, cfg),
		clientPub: clientPub,
	}

	for id := uint64(1); id <= 4; id++ {
		mn := &mockNode{readyc: make(chan Ready, 32)}
		fx.mocks[id] = mn
		fx.nodes[id] = WrapBFTNode(mn, id, 4, nodePrivs[id], nodePubs, clientIDs, clientPub, cfg)
	}

	return fx
}

func signedBFTContext(t *testing.T, m *pb.Message, pub ed25519.PublicKey) BFTContext {
	t.Helper()
	_, origCtx, err := VerifyBFTMessageSignature(m, pub)
	require.NoError(t, err)
	bctx, err := decodeBFTContext(origCtx)
	require.NoError(t, err)
	return bctx
}

func makePrePrepareForNetworkTest(t *testing.T, fx *bftNetworkFixture, from uint64, seq uint64, payload []byte, requestTS int64, clientID uint64) (*pb.Message, [32]byte) {
	t.Helper()
	clientReq := signClientRequestForTest(t, clientID, 1, payload, fx.client.priv, requestTS)
	digest, err := hashEntryBatch(clientReq.GetEntries())
	require.NoError(t, err)
	bctx := BFTContext{
		Phase:            PhasePrePrepare,
		View:             0,
		SeqNum:           seq,
		Digest:           digest,
		RequestTimestamp: requestTS,
		ClientID:         clientID,
		ClientRequest:    *proto.Clone(clientReq).(*pb.Message),
	}
	encCtx, err := encodeBFTContext(bctx)
	require.NoError(t, err)
	return &pb.Message{
		Type:    pb.MsgApp.Enum(),
		From:    u64p(from),
		Context: encCtx,
		Entries: cloneEntries(clientReq.GetEntries()),
	}, digest
}

func makePhaseMessageForNetworkTest(t *testing.T, phase BFTPhase, from uint64, seq uint64, digest [32]byte) *pb.Message {
	t.Helper()
	bctx := BFTContext{Phase: phase, View: 0, SeqNum: seq, Digest: digest}
	encCtx, err := encodeBFTContext(bctx)
	require.NoError(t, err)
	return &pb.Message{Type: pb.MsgApp.Enum(), From: u64p(from), Context: encCtx}
}

func drainNodeReadyMessages(t *testing.T, node *BFTNode) []*pb.Message {
	t.Helper()
	select {
	case rd := <-node.Ready():
		msgs := append([]*pb.Message(nil), rd.Messages...)
		node.Advance()
		return msgs
	case <-time.After(250 * time.Millisecond):
		t.Fatal("timed out waiting for node Ready")
		return nil
	}
}

func drainNodeReadyIfAny(t *testing.T, node *BFTNode) []*pb.Message {
	t.Helper()
	select {
	case rd := <-node.Ready():
		msgs := append([]*pb.Message(nil), rd.Messages...)
		node.Advance()
		return msgs
	case <-time.After(20 * time.Millisecond):
		return nil
	}
}

func partitionMessagesByPhase(t *testing.T, msgs []*pb.Message, pubs map[uint64]ed25519.PublicKey) map[BFTPhase][]*pb.Message {
	t.Helper()
	out := make(map[BFTPhase][]*pb.Message)
	for _, msg := range msgs {
		pub, ok := pubs[msg.GetFrom()]
		require.True(t, ok, "unknown sender %d", msg.GetFrom())
		bctx := signedBFTContext(t, msg, pub)
		out[bctx.Phase] = append(out[bctx.Phase], msg)
	}
	return out
}

func stepNetworkMessage(t *testing.T, fx *bftNetworkFixture, msg *pb.Message) []*pb.Message {
	t.Helper()
	msg = proto.Clone(msg).(*pb.Message)
	if msg.GetTo() == fx.client.selfID {
		require.NoError(t, fx.client.Step(fx.ctx, msg))
		return nil
	}
	node := fx.nodes[msg.GetTo()]
	require.NotNil(t, node, "message has unknown target %d", msg.GetTo())
	require.NoError(t, node.Step(fx.ctx, msg))
	return drainNodeReadyIfAny(t, node)
}

func TestBFTNetwork_NormalCaseCommitsAndRepliesOK(t *testing.T) {
	fx := newBFTNetworkFixture(t)

	require.NoError(t, fx.client.Propose(fx.ctx, []byte("set x=1")))
	clientToPrimary := <-fx.client.Ready()
	require.Equal(t, uint64(1), clientToPrimary.GetTo())

	require.NoError(t, fx.nodes[1].Step(fx.ctx, clientToPrimary))
	primaryOut := drainNodeReadyMessages(t, fx.nodes[1])
	byPhase := partitionMessagesByPhase(t, primaryOut, fx.nodePubs)
	require.Len(t, byPhase[PhasePrePrepare], 3)

	var prepares []*pb.Message
	for _, pp := range byPhase[PhasePrePrepare] {
		out := stepNetworkMessage(t, fx, pp)
		prepares = append(prepares, partitionMessagesByPhase(t, out, fx.nodePubs)[PhasePrepare]...)
	}
	require.NotEmpty(t, prepares)

	var commits []*pb.Message
	for _, prepare := range prepares {
		out := stepNetworkMessage(t, fx, prepare)
		commits = append(commits, partitionMessagesByPhase(t, out, fx.nodePubs)[PhaseCommit]...)
	}
	require.NotEmpty(t, commits)

	var replies []*pb.Message
	for _, commit := range commits {
		out := stepNetworkMessage(t, fx, commit)
		for _, msg := range out {
			if msg.GetTo() == fx.client.selfID {
				replies = append(replies, msg)
				continue
			}
			bctx := signedBFTContext(t, msg, fx.nodePubs[msg.GetFrom()])
			if bctx.Phase == PhaseCommit {
				commits = append(commits, msg)
			}
		}
		if len(replies) >= int(fx.client.f+1) {
			break
		}
	}
	require.GreaterOrEqual(t, len(replies), int(fx.client.f+1))

	for _, reply := range replies[:fx.client.f+1] {
		require.NoError(t, fx.client.Step(fx.ctx, proto.Clone(reply).(*pb.Message)))
	}

	select {
	case result := <-fx.client.ConsensusC:
		require.Equal(t, []byte("OK"), result)
	case <-time.After(250 * time.Millisecond):
		t.Fatal("client did not observe f+1 matching replies")
	}
}

func TestBFTNetwork_BackupForwardsClientRequestWithoutChangingClientSignature(t *testing.T) {
	fx := newBFTNetworkFixture(t)

	require.NoError(t, fx.client.Propose(fx.ctx, []byte("forward me")))
	var clientToBackup *pb.Message
	for i := 0; i < 4; i++ {
		msg := <-fx.client.Ready()
		if msg.GetTo() == 2 {
			clientToBackup = msg
		}
	}
	require.NotNil(t, clientToBackup)

	require.NoError(t, fx.nodes[2].Step(fx.ctx, clientToBackup))
	out := drainNodeReadyMessages(t, fx.nodes[2])
	require.Len(t, out, 1)

	forwarded := out[0]
	require.Equal(t, pb.MsgProp, forwarded.GetType())
	require.Equal(t, uint64(100), forwarded.GetFrom())
	require.Equal(t, uint64(1), forwarded.GetTo())
	_, _, err := VerifyBFTMessageSignature(forwarded, fx.clientPub)
	require.NoError(t, err, "forwarded client request must preserve the client signature")
}

func TestBFTNetwork_RejectsPrePrepareFromNonPrimary(t *testing.T) {
	fx := newBFTNetworkFixture(t)
	pp, _ := makePrePrepareForNetworkTest(t, fx, 3, 1, []byte("bad primary"), 100, 100)
	signTestNodeMessage(t, pp, fx.nodePrivs[3], 100)

	err := fx.nodes[2].Step(fx.ctx, pp)
	require.ErrorContains(t, err, "pre-prepare from non-primary")
}

func TestBFTNetwork_RejectsPrepareWithMismatchedDigest(t *testing.T) {
	fx := newBFTNetworkFixture(t)
	pp, _ := makePrePrepareForNetworkTest(t, fx, 1, 1, []byte("good"), 100, 100)
	signTestNodeMessage(t, pp, fx.nodePrivs[1], 100)
	require.NoError(t, fx.nodes[2].Step(fx.ctx, pp))
	_ = drainNodeReadyMessages(t, fx.nodes[2])

	badDigest := entryDigest(t, []byte("different"))
	prepare := makePhaseMessageForNetworkTest(t, PhasePrepare, 3, 1, badDigest)
	signTestNodeMessage(t, prepare, fx.nodePrivs[3], 200)

	err := fx.nodes[2].Step(fx.ctx, prepare)
	require.ErrorContains(t, err, "prepare does not match accepted pre-prepare")
}

func TestBFTNetwork_RejectsCommitBeforePreparedCertificate(t *testing.T) {
	fx := newBFTNetworkFixture(t)
	pp, digest := makePrePrepareForNetworkTest(t, fx, 1, 1, []byte("commit too early"), 100, 100)
	signTestNodeMessage(t, pp, fx.nodePrivs[1], 100)
	require.NoError(t, fx.nodes[2].Step(fx.ctx, pp))
	_ = drainNodeReadyMessages(t, fx.nodes[2])

	commit := makePhaseMessageForNetworkTest(t, PhaseCommit, 3, 1, digest)
	signTestNodeMessage(t, commit, fx.nodePrivs[3], 200)

	err := fx.nodes[2].Step(fx.ctx, commit)
	require.ErrorContains(t, err, "commit before prepared certificate")
}

func TestBFTNetwork_DuplicateClientReplyDoesNotCountTwice(t *testing.T) {
	fx := newBFTNetworkFixture(t)
	require.NoError(t, fx.client.Propose(fx.ctx, []byte("reply quorum")))

	var reqTS int64
	for ts := range fx.client.pending {
		reqTS = ts
	}
	require.NotZero(t, reqTS)

	bctx := BFTContext{Phase: PhaseReply, View: 0, RequestTimestamp: reqTS, ClientID: 100, Result: []byte("OK")}
	encCtx, err := encodeBFTContext(bctx)
	require.NoError(t, err)

	reply := &pb.Message{Type: pb.MsgApp.Enum(), From: u64p(2), To: u64p(100), Context: encCtx}
	signTestNodeMessage(t, reply, fx.nodePrivs[2], 500)
	require.NoError(t, fx.client.Step(fx.ctx, proto.Clone(reply).(*pb.Message)))
	require.NoError(t, fx.client.Step(fx.ctx, proto.Clone(reply).(*pb.Message)))

	select {
	case <-fx.client.ConsensusC:
		t.Fatal("duplicate reply from one replica should not satisfy f+1 reply quorum")
	case <-time.After(50 * time.Millisecond):
	}

	reply3 := &pb.Message{Type: pb.MsgApp.Enum(), From: u64p(3), To: u64p(100), Context: encCtx}
	signTestNodeMessage(t, reply3, fx.nodePrivs[3], 501)
	require.NoError(t, fx.client.Step(fx.ctx, reply3))

	select {
	case result := <-fx.client.ConsensusC:
		require.Equal(t, []byte("OK"), result)
	case <-time.After(250 * time.Millisecond):
		t.Fatal("client did not accept f+1 matching replies")
	}
}
