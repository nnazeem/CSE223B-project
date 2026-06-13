// bft_wrapper_test.go
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

func (m *mockNode) Step(ctx context.Context, msg *pb.Message) error { return nil }
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

	m := &pb.Message{Type: pb.MsgApp.Enum(), From: u64p(1), To: u64p(2)}

	ts := time.Now().UnixNano()
	data, _ := messageSignBytes(m, nil, ts)
	sig := ed25519.Sign(priv, data)
	m.Context = packSignature(sig, ts, nil)

	extractedTs, origCtx, err := VerifyBFTMessageSignature(m, pub)
	require.NoError(t, err)
	require.Equal(t, ts, extractedTs)
	require.Empty(t, origCtx)

	mTampered := proto.Clone(m).(*pb.Message)
	mTampered.To = u64p(99)
	_, _, err = VerifyBFTMessageSignature(mTampered, pub)
	require.ErrorIs(t, err, ErrInvalidSignature)

	badPub, _, _ := ed25519.GenerateKey(nil)
	_, _, err = VerifyBFTMessageSignature(m, badPub)
	require.ErrorIs(t, err, ErrInvalidSignature)
}

func TestBFT_Client_ReplayAttack(t *testing.T) {
	node, client, _, _ := setupCluster(t)
	ctx := context.Background()

	err := client.Propose(ctx, []byte("data"))
	require.NoError(t, err)
	propMsg := <-client.Ready()

	msg1 := proto.Clone(propMsg).(*pb.Message)
	err = node.Step(ctx, msg1)
	require.NoError(t, err)

	msg2 := proto.Clone(propMsg).(*pb.Message)
	err = node.Step(ctx, msg2)
	require.ErrorIs(t, err, ErrStaleMessage)
}

func TestBFT_Node_PrepareQuorum(t *testing.T) {
	node, _, nodePrivs, mock := setupCluster(t)
	ctx := context.Background()

	node.view = 1 // Advance view so Node 2 is the legitimate Primary

	bctx := BFTContext{Phase: PhasePrePrepare, View: 1, SeqNum: 1, Digest: hashData([]byte("test"))}
	encCtx, _ := encodeBFTContext(bctx)

	msg := &pb.Message{Type: pb.MsgApp.Enum(), From: u64p(2), Term: u64p(1), Context: encCtx}
	origCtx := normalizeContext(msg.Context)
	data, _ := messageSignBytes(msg, origCtx, 100)
	msg.Context = packSignature(ed25519.Sign(nodePrivs[2], data), 100, origCtx)

	_ = node.Step(ctx, msg)

	rd := <-node.Ready()
	require.NotEmpty(t, rd.Messages)
	node.Advance()

	bctx.Phase = PhasePrepare
	encPCtx, _ := encodeBFTContext(bctx)

	pMsg := &pb.Message{Type: pb.MsgApp.Enum(), From: u64p(3), Term: u64p(1), Context: encPCtx}
	origPCtx := normalizeContext(pMsg.Context)
	pData, _ := messageSignBytes(pMsg, origPCtx, 200)
	pMsg.Context = packSignature(ed25519.Sign(nodePrivs[3], pData), 200, origPCtx)

	err := node.Step(ctx, pMsg)
	require.NoError(t, err)

	mock.readyc <- Ready{}
	rd2 := <-node.Ready()
	require.NotEmpty(t, rd2.Messages)
	node.Advance()

	// Strip the outbound signature to verify inner contents
	_, cOrigCtx, err := VerifyBFTMessageSignature(rd2.Messages[0], node.nodePubKeys[1])
	require.NoError(t, err)

	cCtx, _ := decodeBFTContext(cOrigCtx)
	require.Equal(t, PhaseCommit, cCtx.Phase)
}

// -------------------------------------------------------------
// Adversarial / Edge Case Tests
// -------------------------------------------------------------

func TestBFT_Node_EquivocatingLeader(t *testing.T) {
	node, _, nodePrivs, _ := setupCluster(t)
	ctx := context.Background()

	node.view = 1 // Advance view

	bctxA := BFTContext{Phase: PhasePrePrepare, View: 1, SeqNum: 1, Digest: hashData([]byte("A"))}
	encA, _ := encodeBFTContext(bctxA)
	msgA := &pb.Message{Type: pb.MsgApp.Enum(), From: u64p(2), Term: u64p(1), Context: encA}

	dataA, _ := messageSignBytes(msgA, encA, 100)
	msgA.Context = packSignature(ed25519.Sign(nodePrivs[2], dataA), 100, encA)
	err := node.Step(ctx, msgA)
	require.NoError(t, err)

	bctxB := BFTContext{Phase: PhasePrePrepare, View: 1, SeqNum: 1, Digest: hashData([]byte("B"))}
	encB, _ := encodeBFTContext(bctxB)
	msgB := &pb.Message{Type: pb.MsgApp.Enum(), From: u64p(2), Term: u64p(1), Context: encB}

	dataB, _ := messageSignBytes(msgB, encB, 101)
	msgB.Context = packSignature(ed25519.Sign(nodePrivs[2], dataB), 101, encB)

	err = node.Step(ctx, msgB)
	require.ErrorContains(t, err, "conflicting pre-prepare digest")
}

func TestBFT_Node_OutOfBoundsSequence(t *testing.T) {
	node, _, nodePrivs, _ := setupCluster(t)
	ctx := context.Background()

	node.view = 1 // Advance view

	bctx := BFTContext{Phase: PhasePrePrepare, View: 1, SeqNum: 9999, Digest: hashData([]byte("data"))}
	enc, _ := encodeBFTContext(bctx)
	msg := &pb.Message{Type: pb.MsgApp.Enum(), From: u64p(2), Term: u64p(1), Context: enc}

	data, _ := messageSignBytes(msg, enc, 100)
	msg.Context = packSignature(ed25519.Sign(nodePrivs[2], data), 100, enc)

	err := node.Step(ctx, msg)
	require.ErrorContains(t, err, "sequence number out of bounds")
}

func TestBFT_Node_ImpossibleQuorum(t *testing.T) {
	node, _, nodePrivs, mock := setupCluster(t)
	ctx := context.Background()

	node.view = 1 // Advance view

	bctx := BFTContext{Phase: PhasePrePrepare, View: 1, SeqNum: 1, Digest: hashData([]byte("test"))}
	encCtx, _ := encodeBFTContext(bctx)
	msg := &pb.Message{Type: pb.MsgApp.Enum(), From: u64p(2), Term: u64p(1), Context: encCtx}

	data, _ := messageSignBytes(msg, encCtx, 100)
	msg.Context = packSignature(ed25519.Sign(nodePrivs[2], data), 100, encCtx)

	_ = node.Step(ctx, msg)
	<-node.Ready()
	node.Advance()

	mock.readyc <- Ready{}

	select {
	case rd := <-node.Ready():
		if len(rd.Messages) > 0 {
			_, origCtx, _ := VerifyBFTMessageSignature(rd.Messages[0], node.nodePubKeys[1])
			cCtx, _ := decodeBFTContext(origCtx)
			require.NotEqual(t, PhaseCommit, cCtx.Phase, "Node emitted Commit without reaching Quorum!")
		}
	case <-time.After(50 * time.Millisecond):
		// Test Passed: Expected halt due to insufficient peers
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
		m := &pb.Message{Type: pb.MsgApp.Enum(), From: u64p(nodeID), Term: u64p(1), Context: encCtx}
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


func TestBFT_LogReplication_SequentialExecution(t *testing.T) {
    node, _, nodePrivs, _ := setupCluster(t)
    ctx := context.Background()

    // Simulate Commits for Sequence 2 BEFORE Sequence 1
    // It should NOT execute Sequence 2 yet.
    bctx2 := BFTContext{Phase: PhaseCommit, View: 0, SeqNum: 2, Digest: hashData([]byte("seq2"))}
    encCtx2, _ := encodeBFTContext(bctx2)
    node.mu.Lock()
    node.reqs[bftSeqKey{view: 0, seq: 2}] = []*pb.Entry{{Data: []byte("seq2")}}
    node.mu.Unlock()

    for i := uint64(1); i <= 3; i++ {
        msg := &pb.Message{Type: pb.MsgApp.Enum(), From: u64p(i), Context: encCtx2}
        signPeerMsgForTest(msg, nodePrivs[i], 100)
        _ = node.Step(ctx, msg)
    }

    require.Equal(t, uint64(0), node.lastExecuted, "Should buffer Sequence 2, lastExecuted remains 0")

    // Now send Commits for Sequence 1
    bctx1 := BFTContext{Phase: PhaseCommit, View: 0, SeqNum: 1, Digest: hashData([]byte("seq1"))}
    encCtx1, _ := encodeBFTContext(bctx1)
    node.mu.Lock()
    node.reqs[bftSeqKey{view: 0, seq: 1}] = []*pb.Entry{{Data: []byte("seq1")}}
    node.mu.Unlock()

    for i := uint64(1); i <= 3; i++ {
        msg := &pb.Message{Type: pb.MsgApp.Enum(), From: u64p(i), Context: encCtx1}
        signPeerMsgForTest(msg, nodePrivs[i], 101)
        _ = node.Step(ctx, msg)
    }

    // Since Sequence 1 completed, it should unblock Sequence 2.
    require.Equal(t, uint64(2), node.lastExecuted, "Both Sequence 1 and 2 should execute in order")
}

func TestBFT_Checkpointing_GarbageCollection(t *testing.T) {
    node, _, nodePrivs, _ := setupCluster(t)
    ctx := context.Background()

    // Populate fake state history
    key := bftSeqKey{view: 0, seq: 50}
    node.mu.Lock()
    node.pp[key] = hashData([]byte("old"))
    node.lowW = 0
    node.highW = 200
    node.mu.Unlock()

    cpDigest := hashData([]byte("state_at_100"))
    bctx := BFTContext{Phase: PhaseCheckpoint, SeqNum: 100, CheckpointDigest: cpDigest}
    encCtx, _ := encodeBFTContext(bctx)

    // Receive checkpoints from 2f+1 nodes
    for i := uint64(1); i <= 3; i++ {
        msg := &pb.Message{Type: pb.MsgApp.Enum(), From: u64p(i), Context: encCtx}
        signPeerMsgForTest(msg, nodePrivs[i], 200)
        _ = node.Step(ctx, msg)
    }

    node.mu.Lock()
    defer node.mu.Unlock()
    
    require.Equal(t, uint64(100), node.lowW, "Low watermark should advance to stable checkpoint seq")
    require.Equal(t, uint64(300), node.highW, "High watermark should advance relative to lowW")
    _, exists := node.pp[key]
    require.False(t, exists, "Garbage collection should have deleted seq 50")
}

func TestBFT_ViewChange_NewViewGeneration(t *testing.T) {
    /// Test that a node designated as the primary for v+1 broadcasts a NEW-VIEW upon receiving 2f+1 VIEW-CHANGEs
	node, _, nodePrivs, _ := setupCluster(t)
	ctx := context.Background()

	// Make node 2 the leader for view 1 (since 1 mod 4 + 1 = 2)
	node.selfID = 2 
	node.priv = nodePrivs[2] // Ensure node signs with node 2's key

    vcCtx := BFTContext{Phase: PhaseViewChange, View: 1, CheckpointSeqNum: 100}
	encCtx, _ := encodeBFTContext(vcCtx)

	// Simulate receiving VIEW-CHANGE from 3 nodes (including self)
	for i := uint64(1); i <= 3; i++ {
		msg := &pb.Message{Type: pb.MsgApp.Enum(), From: u64p(i), Context: encCtx}
		signPeerMsgForTest(msg, nodePrivs[i], 300)
		_ = node.Step(ctx, msg)
	}

	rd := <-node.Ready()
	node.Advance()

	require.NotEmpty(t, rd.Messages, "Node 2 should have generated outbound messages")
	
	// Verify outbound message is NEW-VIEW
	_, origCtx, _ := VerifyBFTMessageSignature(rd.Messages[0], node.nodePubKeys[2])
	nvCtx, _ := decodeBFTContext(origCtx)
	require.Equal(t, PhaseNewView, nvCtx.Phase, "Primary for v+1 should construct NEW-VIEW")
	require.Equal(t, uint64(1), node.view, "Node should officially transition to view 1")
}

func TestBFT_Client_ReplyGeneration(t *testing.T) {
	node, client, _, _ := setupCluster(t)
	ctx := context.Background()

	// Simulate Client Proposal
	client.Propose(ctx, []byte("reply_test"))
	msg := <-client.Ready()
	
	_ = node.Step(ctx, msg) // Generates PrePrepare

	// Drain the PrePrepare message before triggering PhaseReply
	rd1 := <-node.Ready()
	node.Advance()
	require.NotEmpty(t, rd1.Messages)

	// Force consensus manually
	key := bftSeqKey{view: 0, seq: 1}
	
	// Keep the mutex locked while executing pending requests
	node.mu.Lock()
	node.committedLocal[key] = true
	node.reqs[key] = []*pb.Entry{{Data: []byte("reply_test")}}

	// Trigger Execution (Requires bn.mu to be locked)
	node.executePending()
	node.mu.Unlock() // <--- Moved unlock to here!

	// Drain Ready channel to catch the outbound reply
	rd2 := <-node.Ready()
	require.NotEmpty(t, rd2.Messages)
	
	_, origCtx, _ := VerifyBFTMessageSignature(rd2.Messages[0], node.nodePubKeys[1])
	replyCtx, _ := decodeBFTContext(origCtx)
	
	require.Equal(t, PhaseReply, replyCtx.Phase, "Node should generate a PhaseReply after execution")
	require.Equal(t, uint64(100), replyCtx.ClientID, "Reply should be addressed to the correct client")
}

func TestBFT_StateTransfer_CatchUp(t *testing.T) {
	node, _, nodePrivs, _ := setupCluster(t)
	ctx := context.Background()

	node.view = 1 // Advance view

	// Simulate receiving a message far ahead of highW
	bctx := BFTContext{Phase: PhasePrePrepare, View: 1, SeqNum: 3000, Digest: hashData([]byte("future"))}
	encCtx, _ := encodeBFTContext(bctx)
	msg := &pb.Message{Type: pb.MsgApp.Enum(), From: u64Ptr(2), Context: encCtx}
	signPeerMsgForTest(msg, nodePrivs[2], 100)

	_ = node.Step(ctx, msg)

	// Verify Node generates a PhaseFetchState
	rd := <-node.Ready()
	node.Advance()
	
	_, origCtx, _ := VerifyBFTMessageSignature(rd.Messages[0], node.nodePubKeys[1])
	reqCtx, _ := decodeBFTContext(origCtx)
	require.Equal(t, PhaseFetchState, reqCtx.Phase, "Node should request state when lagging")

	// Provide State Responses
	respCtx := BFTContext{Phase: PhaseStateResponse, CheckpointSeqNum: 2500}
	encResp, _ := encodeBFTContext(respCtx)
	for i := uint64(2); i <= 3; i++ {
		rMsg := &pb.Message{Type: pb.MsgApp.Enum(), From: u64Ptr(i), Context: encResp}
		signPeerMsgForTest(rMsg, nodePrivs[i], 200)
		_ = node.Step(ctx, rMsg)
	}

	require.Equal(t, uint64(2500), node.lowW, "Node should update its low water mark via state transfer")
	require.Equal(t, uint64(2700), node.highW, "Node should update its high water mark")
}

// Utility for tests
func signPeerMsgForTest(m *pb.Message, priv ed25519.PrivateKey, ts int64) {
    origCtx := normalizeContext(m.Context)
    data, _ := messageSignBytes(m, origCtx, ts)
    m.Context = packSignature(ed25519.Sign(priv, data), ts, origCtx)
}

// Integration Test w/ Real etcd Raft Node and Asynchronous Consumer
func TestBFT_Integration_RealRaftNode(t *testing.T) {
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

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	outboundMsgs := make(chan *pb.Message, 100)
	success := make(chan bool, 1)
	isLeader := make(chan bool, 1)

	// ==============================================================
	// Asynchronous Consumer Loop
	// ==============================================================
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case rd, ok := <-bftNode.Ready():
				if !ok {
					return
				}

				if rd.SoftState != nil && rd.SoftState.Lead == 1 {
					select {
					case isLeader <- true:
					default:
					}
				}

				if len(rd.Entries) > 0 {
					storage.Append(rd.Entries)
				}

				for _, m := range rd.Messages {
					outboundMsgs <- m
				}

				for _, ent := range rd.CommittedEntries {
					if ent.GetType() == pb.EntryConfChange {
						cc := &pb.ConfChange{}
						require.NoError(t, proto.Unmarshal(ent.GetData(), cc))
						bftNode.ApplyConfChange(cc)
					} else if ent.GetType() == pb.EntryNormal && len(ent.GetData()) > 0 {
						if string(ent.GetData()) == "integration-test-data" {
							select {
							case success <- true:
							default:
							}
						}
					}
				}
				bftNode.Advance()
			}
		}
	}()

	// TODO Leader election/View Change: Using natural ticks to elect leader instead of forcing Campaign
WaitLeader:
	for {
		bftNode.Tick()
		select {
		case <-isLeader:
			break WaitLeader
		case <-time.After(10 * time.Millisecond):
		}
	}

	time.Sleep(50 * time.Millisecond)

	// 2. Submit BFT Client Proposal
	payloadData := []byte("integration-test-data")
	err = bftClient.Propose(ctx, payloadData)
	require.NoError(t, err)

	clientMsg := <-bftClient.Ready()
	err = bftNode.Step(ctx, clientMsg)
	require.NoError(t, err)

	// 3. Catch outbound PhasePrePrepare (Drain 3 messages sent to peers 2, 3, and 4)
	for i := 0; i < 3; i++ {
		ppMsg := <-outboundMsgs
		_, origCtx, _ := VerifyBFTMessageSignature(ppMsg, nodePubs[1])
		bctx, err := decodeBFTContext(origCtx)
		require.NoError(t, err)
		require.Equal(t, PhasePrePrepare, bctx.Phase)
	}

	// 4. Inject 2x Peer PhasePrepares
	bctx := BFTContext{Phase: PhasePrepare, View: 0, SeqNum: 1, Digest: hashData(payloadData)}
	encPCtx, _ := encodeBFTContext(bctx)
	for i := uint64(2); i <= 3; i++ {
		pMsg := &pb.Message{Type: pb.MsgApp.Enum(), From: u64p(i), Term: u64p(1), Context: encPCtx}
		signPeerMsg(pMsg, nodePrivs[i])
		err = bftNode.Step(ctx, pMsg)
		require.NoError(t, err)
	}

	// 5. Catch outbound PhaseCommit (Drain 3 messages sent to peers 2, 3, and 4)
	for i := 0; i < 3; i++ {
		cMsgOut := <-outboundMsgs
		_, origCtx, _ := VerifyBFTMessageSignature(cMsgOut, nodePubs[1])
		cCtx, _ := decodeBFTContext(origCtx)
		require.Equal(t, PhaseCommit, cCtx.Phase)
	}

	// 6. Inject 2x Peer PhaseCommits
	bctx.Phase = PhaseCommit
	encCCtx, _ := encodeBFTContext(bctx)
	for i := uint64(2); i <= 3; i++ {
		cMsg := &pb.Message{Type: pb.MsgApp.Enum(), From: u64p(i), Term: u64p(1), Context: encCCtx}
		signPeerMsg(cMsg, nodePrivs[i])
		err = bftNode.Step(ctx, cMsg)
		require.NoError(t, err)
	}

	// 7. Wait for Real Raft Log Confirmation
	select {
	case <-success:
		// Success!
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for payload to execute on internal Raft log")
	}
}

// -------------------------------------------------------------
// BFT Adversarial & Edge Case Scenarios
// -------------------------------------------------------------

// Scenario 1 & 10: Candidate/Follower declares itself leader or emits AppendEntry
func TestBFT_Adversary_FollowerEmitsPrePrepare(t *testing.T) {
	node, _, nodePrivs, _ := setupCluster(t)
	ctx := context.Background()

	// In View 0, Node 1 is the primary ((0 % 4) + 1 = 1).
	// Node 3 maliciously attempts to act as the primary by broadcasting a PRE-PREPARE.
	bctx := BFTContext{Phase: PhasePrePrepare, View: 0, SeqNum: 1, Digest: hashData([]byte("forged_data"))}
	encCtx, _ := encodeBFTContext(bctx)
	
	msg := &pb.Message{Type: pb.MsgApp.Enum(), From: u64p(3), Context: encCtx}
	signPeerMsgForTest(msg, nodePrivs[3], time.Now().UnixNano())

	err := node.Step(ctx, msg)
	
	// PBFT Invariant: Honest nodes drop Pre-Prepares from non-primaries.
	require.ErrorContains(t, err, "sender is not the primary", "Honest backups must drop Pre-Prepares from non-primaries")
}

// Scenario 2 & 4: Leader claims it received a request when it hasn't (Forged Client Payload)
func TestBFT_Adversary_LeaderForgesClientRequest(t *testing.T) {
	node, _, nodePrivs, _ := setupCluster(t)
	ctx := context.Background()

	// Leader (Node 1) crafts a PRE-PREPARE for a client request, but the client signature is invalid/missing.
	bctx := BFTContext{Phase: PhasePrePrepare, View: 0, SeqNum: 1, Digest: hashData([]byte("fake_client_req"))}
	encCtx, _ := encodeBFTContext(bctx)
	
	// Create a payload that lacks a valid client Ed25519 signature wrapper
	msg := &pb.Message{
		Type:    pb.MsgApp.Enum(),
		From:    u64p(1), 
		Context: encCtx,
		Entries: []*pb.Entry{{Data: []byte("fake_client_req")}},
	}
	signPeerMsgForTest(msg, nodePrivs[1], time.Now().UnixNano())

	// Step the message into an honest backup (Node 2)
	node.selfID = 2
	err := node.Step(ctx, msg)

	// Since the inner Entries lack a valid Client signature verify pass, 
	// the honest backup should either reject it or refuse to PREPARE.
	require.ErrorContains(t, err, "missing client authentication", "Honest backups must reject a leader's request lacking a valid client signature")
}

// Scenario 3 & 9: Follower adds entries to its log that did not happen / Answers without appending
func TestBFT_Adversary_FollowerFabricatesCommit(t *testing.T) {
	node, _, nodePrivs, _ := setupCluster(t)
	ctx := context.Background()

	// Node 3 maliciously broadcasts a PhaseCommit for a sequence number and digest that was never prepared.
	bctx := BFTContext{Phase: PhaseCommit, View: 0, SeqNum: 99, Digest: hashData([]byte("ghost_entry"))}
	encCtx, _ := encodeBFTContext(bctx)

	msg := &pb.Message{Type: pb.MsgApp.Enum(), From: u64p(3), Context: encCtx}
	signPeerMsgForTest(msg, nodePrivs[3], time.Now().UnixNano())

	err := node.Step(ctx, msg)
	require.NoError(t, err) // Protocol allows out-of-order buffering of validly signed messages

	// However, the local state machine MUST NOT execute it because it lacks 2f+1 commits
	node.mu.Lock()
	committed := node.committedLocal[bftSeqKey{view: 0, seq: 99}]
	node.mu.Unlock()

	require.False(t, committed, "A single malicious PhaseCommit cannot trigger local execution")
}

// Scenario 5: Leader answers the client without checking with followers
func TestBFT_Adversary_LeaderUnilateralReply(t *testing.T) {
	_, client, nodePrivs, _ := setupCluster(t)
	ctx := context.Background()

	// Client sends a proposal
	err := client.Propose(ctx, []byte("valid_req"))
	require.NoError(t, err)

	var reqTs int64
	for ts := range client.pending {
		reqTs = ts
	}

	// Malicious Leader (Node 1) immediately replies "success" without running PBFT consensus
	replyCtx := BFTContext{Phase: PhaseReply, Result: []byte("success")}
	encCtx, _ := encodeBFTContext(replyCtx)

	msg := &pb.Message{Type: pb.MsgApp.Enum(), From: u64p(1), Context: encCtx}
	origCtx := normalizeContext(msg.Context)
	data, _ := messageSignBytes(msg, origCtx, reqTs)
	msg.Context = packSignature(ed25519.Sign(nodePrivs[1], data), reqTs, origCtx)

	err = client.Step(ctx, msg)
	require.NoError(t, err)

	// Assert the client is STILL pending because f+1 replies are required
	client.mu.Lock()
	_, stillPending := client.pending[reqTs]
	repliesCount := len(client.replies[reqTs])
	client.mu.Unlock()

	require.True(t, stillPending, "Client must not accept a unilateral reply from the leader")
	require.Equal(t, 1, repliesCount, "Client should buffer the leader's reply but await a quorum")
}

// Scenario 6 & 7: Follower/Leader removes entries from its log (Simulated by dropping messages)
func TestBFT_Adversary_NodeDropsEntriesMaintainsLiveness(t *testing.T) {
	_, client, nodePrivs, _ := setupCluster(t)
	ctx := context.Background()

	err := client.Propose(ctx, []byte("liveness_test"))
	require.NoError(t, err)

	var reqTs int64
	for ts := range client.pending {
		reqTs = ts
	}

	replyCtx := BFTContext{Phase: PhaseReply, Result: []byte("success")}
	encCtx, _ := encodeBFTContext(replyCtx)

	// Simulate Node 4 maliciously dropping the entry and refusing to reply.
	// As long as Nodes 1, 2, and 3 reply (f+1 = 2 replies needed for client in a 4 node cluster),
	// the system maintains consensus and liveness.
	for i := uint64(1); i <= 2; i++ {
		msg := &pb.Message{Type: pb.MsgApp.Enum(), From: u64p(i), Context: encCtx}
		origCtx := normalizeContext(msg.Context)
		data, _ := messageSignBytes(msg, origCtx, reqTs)
		msg.Context = packSignature(ed25519.Sign(nodePrivs[i], data), reqTs, origCtx)
		
		_ = client.Step(ctx, msg)
	}

	// Because f+1 valid replies were received, consensus is achieved despite Node 4 dropping it.
	select {
	case result := <-client.ConsensusC:
		require.Equal(t, []byte("success"), result)
	case <-time.After(50 * time.Millisecond):
		t.Fatal("System lost liveness when a single node dropped an entry")
	}
}

// Scenario 8: Leader reorders its log entries
func TestBFT_Adversary_LeaderReordersLogEntries(t *testing.T) {
	node, _, nodePrivs, _ := setupCluster(t)
	ctx := context.Background()

	// Malicious Leader prepares and commits Sequence 2 BEFORE Sequence 1
	bctx2 := BFTContext{Phase: PhaseCommit, View: 0, SeqNum: 2, Digest: hashData([]byte("req_2"))}
	encCtx2, _ := encodeBFTContext(bctx2)
	node.mu.Lock()
	node.reqs[bftSeqKey{view: 0, seq: 2}] = []*pb.Entry{{Data: []byte("req_2")}}
	node.mu.Unlock()

	// Inject 2f+1 commits for Sequence 2
	for i := uint64(1); i <= 3; i++ {
		msg := &pb.Message{Type: pb.MsgApp.Enum(), From: u64p(i), Context: encCtx2}
		signPeerMsgForTest(msg, nodePrivs[i], time.Now().UnixNano())
		_ = node.Step(ctx, msg)
	}

	// Verify Sequence 2 is buffered but NOT executed
	require.Equal(t, uint64(0), node.lastExecuted, "Sequence 2 must be buffered due to strict ordering invariant")

	// Now inject Sequence 1
	bctx1 := BFTContext{Phase: PhaseCommit, View: 0, SeqNum: 1, Digest: hashData([]byte("req_1"))}
	encCtx1, _ := encodeBFTContext(bctx1)
	node.mu.Lock()
	node.reqs[bftSeqKey{view: 0, seq: 1}] = []*pb.Entry{{Data: []byte("req_1")}}
	node.mu.Unlock()

	for i := uint64(1); i <= 3; i++ {
		msg := &pb.Message{Type: pb.MsgApp.Enum(), From: u64p(i), Context: encCtx1}
		signPeerMsgForTest(msg, nodePrivs[i], time.Now().UnixNano())
		_ = node.Step(ctx, msg)
	}

	// Execution should automatically unblock and apply Seq 1, then Seq 2.
	require.Equal(t, uint64(2), node.lastExecuted, "Node failed to reconstruct sequential execution from reordered leader messages")
}

// Scenario 11: Faulty Candidate continually asks for votes (View Change Spam)
func TestBFT_Adversary_SpamViewChange(t *testing.T) {
	node, _, nodePrivs, _ := setupCluster(t)
	ctx := context.Background()

	initialView := node.view

	// Node 3 repeatedly spams VIEW-CHANGE for view 1 to try and force an election
	bctx := BFTContext{Phase: PhaseViewChange, View: 1, CheckpointSeqNum: 0}
	encCtx, _ := encodeBFTContext(bctx)

	for i := 0; i < 10; i++ {
		msg := &pb.Message{Type: pb.MsgApp.Enum(), From: u64p(3), Context: encCtx}
		signPeerMsgForTest(msg, nodePrivs[3], time.Now().UnixNano()+int64(i))
		_ = node.Step(ctx, msg)
	}

	// Because only Node 3 is asking, we do not have 2f+1 view changes.
	require.Equal(t, initialView, node.view, "Honest node changed views without a 2f+1 quorum")
}

// Scenario 12: Faulty Candidate continually asks for votes for higher and higher terms without waiting
func TestBFT_Adversary_HighTermSpam(t *testing.T) {
	node, _, nodePrivs, _ := setupCluster(t)
	ctx := context.Background()

	initialView := node.view

	// Node 3 spams VIEW-CHANGE requests for rapidly increasing views (View 100, 101, 102...)
	for i := uint64(100); i < 110; i++ {
		bctx := BFTContext{Phase: PhaseViewChange, View: i, CheckpointSeqNum: 0}
		encCtx, _ := encodeBFTContext(bctx)
		
		msg := &pb.Message{Type: pb.MsgApp.Enum(), From: u64p(3), Context: encCtx}
		signPeerMsgForTest(msg, nodePrivs[3], time.Now().UnixNano())
		_ = node.Step(ctx, msg)
	}

	// The system must safely buffer or ignore these, maintaining its current view
	require.Equal(t, initialView, node.view, "Honest node succumbed to high-term view change spam without quorum")
	
	node.mu.Lock()
	vcCount := len(node.vcMsgs[105])
	node.mu.Unlock()
	
	require.Equal(t, 1, vcCount, "Node should isolate the spammer's view change request to the respective view map")
}

// Integration Test w/ Real Multi-Node Cluster and Network Router
func TestBFT_Integration_RealRaftNetwork(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	clientPub, clientPriv, err := ed25519.GenerateKey(nil)
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

	nodes := make(map[uint64]*BFTNode)
	storages := make(map[uint64]*MemoryStorage)
	peers := []Peer{{ID: 1}, {ID: 2}, {ID: 3}, {ID: 4}}

	for i := uint64(1); i <= 4; i++ {
		storage := NewMemoryStorage()
		raftCfg := &Config{
			ID:              i,
			ElectionTick:    10,
			HeartbeatTick:   1,
			Storage:         storage,
			MaxSizePerMsg:   4096,
			MaxInflightMsgs: 256,
		}

		realNode := StartNode(raftCfg, peers)
		defer realNode.Stop()
		storages[i] = storage
		nodes[i] = WrapBFTNode(realNode, i, 4, nodePrivs[i], nodePubs, clientIDs, clientPub, cfg)
	}

	bftClient := NewBFTClient(100, 4, clientPriv, nodePubs, clientIDs, clientPub, cfg)

	msgRouter := make(chan *pb.Message, 1000)
	successTracker := make(chan bool, 1)
	leaderChan := make(chan uint64, 10)

	for id, bn := range nodes {
		go func(nodeID uint64, bftN *BFTNode, store *MemoryStorage) {
			for {
				select {
				case <-ctx.Done():
					return
				case rd, ok := <-bftN.Ready():
					if !ok {
						return
					}

					if rd.SoftState != nil && rd.SoftState.Lead != 0 {
						select {
						case leaderChan <- rd.SoftState.Lead:
						default:
						}
					}

					if len(rd.Entries) > 0 {
						store.Append(rd.Entries)
					}

					for _, m := range rd.Messages {
						msgRouter <- m
					}

					for _, ent := range rd.CommittedEntries {
						if ent.GetType() == pb.EntryConfChange {
							cc := &pb.ConfChange{}
							require.NoError(t, proto.Unmarshal(ent.GetData(), cc))
							bftN.ApplyConfChange(cc)
						} else if ent.GetType() == pb.EntryNormal && len(ent.GetData()) > 0 {
							if string(ent.GetData()) == "integration-test-data" {
								select {
								case successTracker <- true:
								default:
								}
							}
						}
					}
					bftN.Advance()
				}
			}
		}(id, bn, storages[id])
	}

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case m := <-msgRouter:
				if targetNode, exists := nodes[m.GetTo()]; exists {
					go func(msg *pb.Message) {
						_ = targetNode.Step(ctx, msg)
					}(m)
				}
			}
		}
	}()

WaitLeader:
	for {
		for _, bn := range nodes {
			bn.Tick()
		}
		select {
		case <-leaderChan: // <-- Just wait for a leader to be elected, without saving the ID
			break WaitLeader
		case <-time.After(10 * time.Millisecond):
		}
	}

	time.Sleep(100 * time.Millisecond)

	payloadData := []byte("integration-test-data")
	err = bftClient.Propose(ctx, payloadData)
	require.NoError(t, err)

	for i := 0; i < 4; i++ {
		clientMsg := <-bftClient.Ready()
		err = nodes[clientMsg.GetTo()].Step(ctx, clientMsg)
		require.NoError(t, err)
	}

	select {
	case <-successTracker:
		// Success!
	case <-time.After(3 * time.Second):
		t.Fatal("Timeout: The simulated 4-Node network failed to reach consensus.")
	}
}
