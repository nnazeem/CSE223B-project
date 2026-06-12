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

	bctx := BFTContext{Phase: PhasePrePrepare, View: 0, SeqNum: 1, Digest: hashData([]byte("test"))}
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

	bctxA := BFTContext{Phase: PhasePrePrepare, View: 0, SeqNum: 1, Digest: hashData([]byte("A"))}
	encA, _ := encodeBFTContext(bctxA)
	msgA := &pb.Message{Type: pb.MsgApp.Enum(), From: u64p(2), Term: u64p(1), Context: encA}

	dataA, _ := messageSignBytes(msgA, encA, 100)
	msgA.Context = packSignature(ed25519.Sign(nodePrivs[2], dataA), 100, encA)
	err := node.Step(ctx, msgA)
	require.NoError(t, err)

	bctxB := BFTContext{Phase: PhasePrePrepare, View: 0, SeqNum: 1, Digest: hashData([]byte("B"))}
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

	bctx := BFTContext{Phase: PhasePrePrepare, View: 0, SeqNum: 9999, Digest: hashData([]byte("data"))}
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

	bctx := BFTContext{Phase: PhasePrePrepare, View: 0, SeqNum: 1, Digest: hashData([]byte("test"))}
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
		case <-leaderChan:
			break WaitLeader
		case <-time.After(10 * time.Millisecond):
		}
	}

	time.Sleep(100 * time.Millisecond)

	payloadData := []byte("integration-test-data")
	err = bftClient.Propose(ctx, payloadData)
	require.NoError(t, err)

	clientMsg := <-bftClient.Ready()

	// Route to the PBFT primary (view 0 -> node 1), not the Raft leader.
	err = nodes[1].Step(ctx, clientMsg)
	require.NoError(t, err)

	select {
	case <-successTracker:
		// Success!
	case <-time.After(3 * time.Second):
		t.Fatal("Timeout: The simulated 4-Node network failed to reach consensus.")
	}
}
