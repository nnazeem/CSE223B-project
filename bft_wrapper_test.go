package raft

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	pb "go.etcd.io/raft/v3/raftpb"
)

// mockNode provides a stub for the wrapped Raft interface.
type mockNode struct{ Node }

func (m *mockNode) Step(ctx context.Context, msg pb.Message) error { return nil }
func (m *mockNode) Propose(ctx context.Context, data []byte) error { return nil }
func (m *mockNode) Ready() <-chan Ready {
	ch := make(chan Ready, 1)
	ch <- Ready{}
	return ch
}
func (m *mockNode) Tick()    {}
func (m *mockNode) Advance() {}

func setupCluster(t *testing.T) (*BFTNode, *BFTClient, map[uint64]ed25519.PrivateKey) {
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

	bftNode := WrapBFTNode(&mockNode{}, 1, 4, nodePrivs[1], nodePubs, clientIDs, pubC, cfg)
	bftClient := NewBFTClient(100, 4, privC, nodePubs, clientIDs, pubC, cfg)

	return bftNode, bftClient, nodePrivs
}

// Test the Shared Cryptographic Utility directly
func TestVerifyBFTMessageSignature_Utility(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	m := &pb.Message{
		Type: pb.MsgApp,
		From: 1,
		To:   2,
	}

	ts := time.Now().UnixNano()
	data, _ := messageSignBytes(m, nil, ts)
	sig := ed25519.Sign(priv, data)
	m.Context = packSignature(sig, ts, nil)

	// 1. Valid Signature
	extractedTs, origCtx, err := VerifyBFTMessageSignature(m, pub)
	require.NoError(t, err)
	require.Equal(t, ts, extractedTs)
	require.Empty(t, origCtx)

	// 2. Tampered Payload (e.g., Changing the recipient)
	mTampered := *m
	mTampered.To = 99
	_, _, err = VerifyBFTMessageSignature(&mTampered, pub)
	require.ErrorIs(t, err, ErrInvalidSignature)

	// 3. Unknown Public Key
	badPub, _, _ := ed25519.GenerateKey(nil)
	_, _, err = VerifyBFTMessageSignature(m, badPub)
	require.ErrorIs(t, err, ErrInvalidSignature)
}

func TestBFTClient_ConsensusQuorum(t *testing.T) {
	_, client, nodePrivs := setupCluster(t)
	ctx := context.Background()

	err := client.Propose(ctx, []byte("payload"))
	require.NoError(t, err)

	var reqTs int64
	for ts := range client.pending {
		reqTs = ts
	}
	require.NotZero(t, reqTs, "Request timestamp should be captured")

	bctx := BFTContext{Phase: PhaseReply, Result: []byte("success")}
	encCtx, _ := encodeBFTContext(bctx)

	generateReply := func(nodeID uint64) *pb.Message {
		// Supplying a deterministic Term avoids protobuf zero-value slice discrepancies
		m := &pb.Message{Type: pb.MsgApp, From: nodeID, Term: 1, Context: encCtx}

		// Normalize explicitly as the actual production signing flow would
		origCtx := normalizeContext(m.Context)

		data, err := messageSignBytes(m, origCtx, reqTs)
		require.NoError(t, err, "messageSignBytes failed")

		sig := ed25519.Sign(nodePrivs[nodeID], data)
		m.Context = packSignature(sig, reqTs, origCtx)
		return m
	}

	// 1/2 Replies (Quorum is f+1 where f=1, so we need 2 total)
	err = client.Step(ctx, generateReply(2))
	require.NoError(t, err, "First reply failed signature verification")
	require.Len(t, client.pending, 1)

	// 2/2 Replies (f+1 consensus met)
	err = client.Step(ctx, generateReply(3))
	require.NoError(t, err, "Second reply failed signature verification")
	require.Empty(t, client.pending)

	result := <-client.ConsensusC
	require.Equal(t, []byte("success"), result)
}

func TestBFTNode_PrepareQuorum(t *testing.T) {
	node, _, nodePrivs := setupCluster(t)
	ctx := context.Background()

	bctx := BFTContext{
		Phase:  PhasePrePrepare,
		View:   0,
		SeqNum: 1,
		Digest: hashData([]byte("test")),
	}
	encCtx, _ := encodeBFTContext(bctx)

	msg := &pb.Message{Type: pb.MsgApp, From: 2, Term: 1, Context: encCtx}

	// Sign the Pre-Prepare from Leader identically to how the standard system would
	origCtx := normalizeContext(msg.Context)
	data, _ := messageSignBytes(msg, origCtx, 100)
	msg.Context = packSignature(ed25519.Sign(nodePrivs[2], data), 100, origCtx)

	_ = node.Step(ctx, msg)
	node.Advance() // clear the broadcast queue

	bctx.Phase = PhasePrepare
	encPCtx, _ := encodeBFTContext(bctx)

	// Quorum is 2f+1 (f=1, requiring 3 out of 4).
	// The Node processed 1 Pre-Prepare natively and voted for itself, keeping count at 1.
	// We inject 2 more Prepares from peers to hit the magic number of 3.
	for i := uint64(2); i <= 3; i++ {
		pMsg := &pb.Message{Type: pb.MsgApp, From: i, Term: 1, Context: encPCtx}

		origPCtx := normalizeContext(pMsg.Context)
		pData, _ := messageSignBytes(pMsg, origPCtx, 200)
		pMsg.Context = packSignature(ed25519.Sign(nodePrivs[i], pData), 200, origPCtx)

		err := node.Step(ctx, pMsg)
		require.NoError(t, err)
	}

	// Node correctly processed 3 votes and generated its outbound PhaseCommit
	rd := <-node.Ready()
	require.NotEmpty(t, rd.Messages)

	cCtx, _ := decodeBFTContext(rd.Messages[0].Context)
	require.Equal(t, PhaseCommit, cCtx.Phase)
}

func TestBFTClient_Tick_ResendsPending(t *testing.T) {
	_, client, _ := setupCluster(t)
	ctx := context.Background()

	err := client.Propose(ctx, []byte("data"))
	require.NoError(t, err)

	// Drain the initial proposals broadcast out over the network
	for i := 0; i < 4; i++ {
		<-client.Ready()
	}

	// Push ticks manually past timeout configuration (10 ticks)
	for i := 0; i < 11; i++ {
		client.Tick()
	}

	// Expect all proposals to be re-broadcasted in the readyc due to the retry loop
	require.Len(t, client.readyc, 4)
}
