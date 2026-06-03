// with VSCode Agent Chat
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
	node, _, nodePrivs, _ := setupCluster(t)
	ctx := context.Background()

	bctx := BFTContext{Phase: PhasePrePrepare, View: 0, SeqNum: 1, Digest: hashData([]byte("test"))}
	encCtx, _ := encodeBFTContext(bctx)

	msg := &pb.Message{Type: pb.MsgApp, From: 2, Term: 1, Context: encCtx}
	origCtx := normalizeContext(msg.Context)
	data, _ := messageSignBytes(msg, origCtx, 100)
	msg.Context = packSignature(ed25519.Sign(nodePrivs[2], data), 100, origCtx)

	_ = node.Step(ctx, msg)

	// FIX: Must catch the PhasePrepare broadcast before calling Advance!
	<-node.Ready()
	node.Advance()

	bctx.Phase = PhasePrepare
	encPCtx, _ := encodeBFTContext(bctx)

	// Since f=1, 2f+1 requires 3. Node processed 1 PrePrepare and self-voted (count=2).
	// We inject ONE more peer Prepare to hit threshold 3.
	pMsg := &pb.Message{Type: pb.MsgApp, From: 3, Term: 1, Context: encPCtx}
	origPCtx := normalizeContext(pMsg.Context)
	pData, _ := messageSignBytes(pMsg, origPCtx, 200)
	pMsg.Context = packSignature(ed25519.Sign(nodePrivs[3], pData), 200, origPCtx)

	err := node.Step(ctx, pMsg)
	require.NoError(t, err)

	// FIX: The triggerc multiplexer automatically flushes the Commit message!
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
	node, _, nodePrivs, _ := setupCluster(t)
	ctx := context.Background()

	bctx := BFTContext{Phase: PhasePrePrepare, View: 0, SeqNum: 1, Digest: hashData([]byte("test"))}
	encCtx, _ := encodeBFTContext(bctx)
	msg := &pb.Message{Type: pb.MsgApp, From: 2, Term: 1, Context: encCtx}

	data, _ := messageSignBytes(msg, encCtx, 100)
	msg.Context = packSignature(ed25519.Sign(nodePrivs[2], data), 100, encCtx)

	// Leader and Self Vote -> 2 Votes total (Needs 3 for Quorum)
	_ = node.Step(ctx, msg)

	// FIX: Catch the PhasePrepare broadcast before calling Advance!
	<-node.Ready()
	node.Advance()

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

func TestBFT_Client_Tick_ResendsPending(t *testing.T) {
	_, client, _, _ := setupCluster(t)
	ctx := context.Background()

	err := client.Propose(ctx, []byte("data"))
	require.NoError(t, err)

	for i := 0; i < 4; i++ {
		<-client.Ready()
	}

	for i := 0; i < 11; i++ {
		client.Tick()
	}

	require.Len(t, client.readyc, 4)
}

func TestBFT_Client_ConsensusQuorum(t *testing.T) {
	_, client, nodePrivs, _ := setupCluster(t)
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
		m := &pb.Message{Type: pb.MsgApp, From: nodeID, Term: 1, Context: encCtx}
		origCtx := normalizeContext(m.Context)

		data, err := messageSignBytes(m, origCtx, reqTs)
		require.NoError(t, err, "messageSignBytes failed")

		sig := ed25519.Sign(nodePrivs[nodeID], data)
		m.Context = packSignature(sig, reqTs, origCtx)
		return m
	}

	err = client.Step(ctx, generateReply(2))
	require.NoError(t, err, "First reply failed signature verification")
	require.Len(t, client.pending, 1)

	err = client.Step(ctx, generateReply(3))
	require.NoError(t, err, "Second reply failed signature verification")
	require.Empty(t, client.pending)

	result := <-client.ConsensusC
	require.Equal(t, []byte("success"), result)
}

// Integration Test w/ etcd Raft Node
func TestBFT_Integration_RealRaftNode(t *testing.T) {
	ctx := context.Background()

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

	storage := NewMemoryStorage()
	raftCfg := &Config{
		ID:              1,
		ElectionTick:    10,
		HeartbeatTick:   1,
		Storage:         storage,
		MaxSizePerMsg:   4096,
		MaxInflightMsgs: 256,
	}

	// Single node cluster bypasses "pending config change" limits
	peers := []Peer{{ID: 1}}

	realNode := StartNode(raftCfg, peers)
	defer realNode.Stop()

	bftNode := WrapBFTNode(realNode, 1, 4, nodePrivs[1], nodePubs, clientIDs, pubC, cfg)
	bftClient := NewBFTClient(100, 4, privC, nodePubs, clientIDs, pubC, cfg)

	signPeerMsg := func(m *pb.Message, priv ed25519.PrivateKey) {
		ts := time.Now().UnixNano()
		origCtx := normalizeContext(m.Context)
		data, _ := messageSignBytes(m, origCtx, ts)
		m.Context = packSignature(ed25519.Sign(priv, data), ts, origCtx)
	}

	// Drain initial setup and ConfChange
	rd := <-bftNode.Ready()
	storage.Append(rd.Entries)
	for _, ent := range rd.CommittedEntries {
		if ent.Type == pb.EntryConfChange {
			var cc pb.ConfChange
			cc.Unmarshal(ent.Data)
			bftNode.ApplyConfChange(cc)
		}
	}
	bftNode.Advance()

	// Become Raft Leader
	err = bftNode.Campaign(ctx)
	require.NoError(t, err)

	// Drain Campaign Success payload
	rd = <-bftNode.Ready()
	storage.Append(rd.Entries)
	bftNode.Advance()

	// ==============================================================
	// STAGE 2: BFT Client Proposal & Consensus
	// ==============================================================
	payloadData := []byte("integration-test-data")
	err = bftClient.Propose(ctx, payloadData)
	require.NoError(t, err)

	clientMsg := <-bftClient.Ready()

	err = bftNode.Step(ctx, &clientMsg)
	require.NoError(t, err)

	// Pull BFT PrePrepare Broadcast
	rd = <-bftNode.Ready()
	require.NotEmpty(t, rd.Messages)

	ppMsg := rd.Messages[0]
	bctx, err := decodeBFTContext(ppMsg.Context)
	require.NoError(t, err)
	require.Equal(t, PhasePrePrepare, bctx.Phase)

	bftNode.Advance()

	// Inject Peer Prepares
	bctx.Phase = PhasePrepare
	encPCtx, _ := encodeBFTContext(bctx)

	for i := uint64(2); i <= 3; i++ {
		pMsg := &pb.Message{Type: pb.MsgApp, From: i, Term: 1, Context: encPCtx}
		signPeerMsg(pMsg, nodePrivs[i])
		err = bftNode.Step(ctx, pMsg)
		require.NoError(t, err)
	}

	// Pull BFT Commit Broadcast
	rd = <-bftNode.Ready()
	require.NotEmpty(t, rd.Messages)
	cCtx, _ := decodeBFTContext(rd.Messages[0].Context)
	require.Equal(t, PhaseCommit, cCtx.Phase)
	bftNode.Advance()

	// Inject Peer Commits
	bctx.Phase = PhaseCommit
	encCCtx, _ := encodeBFTContext(bctx)

	for i := uint64(2); i <= 3; i++ {
		cMsg := &pb.Message{Type: pb.MsgApp, From: i, Term: 1, Context: encCCtx}
		signPeerMsg(cMsg, nodePrivs[i])
		err = bftNode.Step(ctx, cMsg)
		require.NoError(t, err)
	}

	// Validate BFTNode called realNode.Propose
	rd = <-bftNode.Ready()
	require.NotEmpty(t, rd.Entries, "Real Raft node should have appended the entry to its log")
	require.Equal(t, payloadData, rd.Entries[0].Data, "The client payload should match the internal Raft entry data")

	storage.Append(rd.Entries)
	bftNode.Advance()
}
