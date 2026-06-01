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

type mockNode struct {
	Node
	readyc chan Ready
}

func (m *mockNode) Step(ctx context.Context, msg pb.Message) error { return nil }
func (m *mockNode) Propose(ctx context.Context, data []byte) error { return nil }
func (m *mockNode) Ready() <-chan Ready                            { return m.readyc }
func (m *mockNode) Tick()                                          {}
func (m *mockNode) Advance()                                       {}

func setupCluster(t *testing.T) (*BFTNode, *BFTClient, map[uint64]ed25519.PrivateKey, *mockNode) {
	pubC, privC, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	nodePubs := make(map[uint64]ed25519.PublicKey)
	nodePrivs := make(map[uint64]ed25519.PrivateKey)

	for i := uint64(1); i <= 4; i++ {
		pub, priv, _ := ed25519.GenerateKey(nil)
		nodePubs[i] = pub
		nodePrivs[i] = priv
	}

	clientIDs := []uint64{100}
	cfg := &ClientProofConfig{MaxAge: 30 * time.Second, Now: time.Now}

	mn := &mockNode{readyc: make(chan Ready, 10)}
	bftNode := WrapBFTNode(mn, 1, 4, nodePrivs[1], nodePubs, clientIDs, pubC, cfg)
	bftClient := NewBFTClient(100, 4, privC, nodePubs, clientIDs, pubC, cfg)

	return bftNode, bftClient, nodePrivs, mn
}

func TestBFT_VerifyMessageSignature_Utility(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	m := &pb.Message{Type: pb.MsgApp, From: 1, To: 2}

	ts := time.Now().UnixNano()
	data, _ := messageSignBytes(m, nil, ts)
	sig := ed25519.Sign(priv, data)
	m.Context = packSignature(sig, ts, nil)

	extractedTs, origCtx, err := VerifyBFTMessageSignature(m, pub)
	require.NoError(t, err)
	require.Equal(t, ts, extractedTs)
	require.Empty(t, origCtx)

	mTampered := *m
	mTampered.To = 99
	_, _, err = VerifyBFTMessageSignature(&mTampered, pub)
	require.ErrorIs(t, err, ErrInvalidSignature)

	badPub, _, _ := ed25519.GenerateKey(nil)
	_, _, err = VerifyBFTMessageSignature(m, badPub)
	require.ErrorIs(t, err, ErrInvalidSignature)
}

func TestBFT_Client_ReplayAttack(t *testing.T) {
	node, client, _, _ := setupCluster(t)
	ctx := context.Background()

	// Intercept a valid client proposal
	err := client.Propose(ctx, []byte("data"))
	require.NoError(t, err)
	propMsg := <-client.Ready()

	// 1. Process it once (Pass a Clone so the original is untouched)
	msg1 := proto.Clone(&propMsg).(*pb.Message)
	err = node.Step(ctx, msg1)
	require.NoError(t, err)

	// 2. Process exact same payload again (Should Fail due to timestamp tracking)
	msg2 := proto.Clone(&propMsg).(*pb.Message)
	err = node.Step(ctx, msg2)
	require.ErrorIs(t, err, ErrStaleMessage)
}

func TestBFT_Node_PrepareQuorum(t *testing.T) {
	node, _, nodePrivs, mock := setupCluster(t)
	ctx := context.Background()

	bctx := BFTContext{Phase: PhasePrePrepare, View: 0, SeqNum: 1, Digest: hashData([]byte("test"))}
	encCtx, _ := encodeBFTContext(bctx)

	msg := &pb.Message{Type: pb.MsgApp, From: 2, Term: 1, Context: encCtx}
	origCtx := normalizeContext(msg.Context)
	data, _ := messageSignBytes(msg, origCtx, 100)
	msg.Context = packSignature(ed25519.Sign(nodePrivs[2], data), 100, origCtx)

	_ = node.Step(ctx, msg)
	node.Advance()

	bctx.Phase = PhasePrepare
	encPCtx, _ := encodeBFTContext(bctx)

	// Since f=1, 2f+1 requires 3. Node processed 1 PrePrepare and self-voted (count=2).
	// We inject just ONE more peer Prepare to hit threshold 3.
	pMsg := &pb.Message{Type: pb.MsgApp, From: 3, Term: 1, Context: encPCtx}
	origPCtx := normalizeContext(pMsg.Context)
	pData, _ := messageSignBytes(pMsg, origPCtx, 200)
	pMsg.Context = packSignature(ed25519.Sign(nodePrivs[3], pData), 200, origPCtx)

	err := node.Step(ctx, pMsg)
	require.NoError(t, err)

	mock.readyc <- Ready{}
	rd := <-node.Ready()
	require.NotEmpty(t, rd.Messages)

	cCtx, _ := decodeBFTContext(rd.Messages[0].Context)
	require.Equal(t, PhaseCommit, cCtx.Phase)
}

// -------------------------------------------------------------
// Adversarial / Edge Case Tests
// -------------------------------------------------------------

func TestBFT_Node_EquivocatingLeader(t *testing.T) {
	node, _, nodePrivs, _ := setupCluster(t)
	ctx := context.Background()

	// Leader sends PrePrepare with Digest A
	bctxA := BFTContext{Phase: PhasePrePrepare, View: 0, SeqNum: 1, Digest: hashData([]byte("A"))}
	encA, _ := encodeBFTContext(bctxA)
	msgA := &pb.Message{Type: pb.MsgApp, From: 2, Term: 1, Context: encA}

	dataA, _ := messageSignBytes(msgA, encA, 100)
	msgA.Context = packSignature(ed25519.Sign(nodePrivs[2], dataA), 100, encA)
	err := node.Step(ctx, msgA)
	require.NoError(t, err)

	// Malicious Leader tries to equivocate with Digest B for the same Sequence Number
	bctxB := BFTContext{Phase: PhasePrePrepare, View: 0, SeqNum: 1, Digest: hashData([]byte("B"))}
	encB, _ := encodeBFTContext(bctxB)
	msgB := &pb.Message{Type: pb.MsgApp, From: 2, Term: 1, Context: encB}

	dataB, _ := messageSignBytes(msgB, encB, 101)
	msgB.Context = packSignature(ed25519.Sign(nodePrivs[2], dataB), 101, encB)

	err = node.Step(ctx, msgB)
	require.ErrorContains(t, err, "conflicting pre-prepare digest")
}

func TestBFT_Node_OutOfBoundsSequence(t *testing.T) {
	node, _, nodePrivs, _ := setupCluster(t)
	ctx := context.Background()

	// Sequence Number 9999 is far above highW (2000)
	bctx := BFTContext{Phase: PhasePrePrepare, View: 0, SeqNum: 9999, Digest: hashData([]byte("data"))}
	enc, _ := encodeBFTContext(bctx)
	msg := &pb.Message{Type: pb.MsgApp, From: 2, Term: 1, Context: enc}

	data, _ := messageSignBytes(msg, enc, 100)
	msg.Context = packSignature(ed25519.Sign(nodePrivs[2], data), 100, enc)

	err := node.Step(ctx, msg)
	require.ErrorContains(t, err, "sequence number out of bounds")
}

func TestBFT_Node_ImpossibleQuorum(t *testing.T) {
	node, _, nodePrivs, mock := setupCluster(t)
	ctx := context.Background()

	bctx := BFTContext{Phase: PhasePrePrepare, View: 0, SeqNum: 1, Digest: hashData([]byte("test"))}
	encCtx, _ := encodeBFTContext(bctx)
	msg := &pb.Message{Type: pb.MsgApp, From: 2, Term: 1, Context: encCtx}

	data, _ := messageSignBytes(msg, encCtx, 100)
	msg.Context = packSignature(ed25519.Sign(nodePrivs[2], data), 100, encCtx)

	// Leader and Self Vote -> 2 Votes total (Needs 3 for Quorum)
	_ = node.Step(ctx, msg)
	node.Advance()

	// Send an empty ready to unblock the channel
	mock.readyc <- Ready{}

	select {
	case rd := <-node.Ready():
		if len(rd.Messages) > 0 {
			cCtx, _ := decodeBFTContext(rd.Messages[0].Context)
			require.NotEqual(t, PhaseCommit, cCtx.Phase, "Node emitted Commit without reaching Quorum!")
		}
	case <-time.After(50 * time.Millisecond):
		// Test Passed: Expected deadlock/halt behavior due to insufficient peers for 2f+1
	}
}
