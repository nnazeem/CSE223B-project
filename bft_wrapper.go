// with VSCode Agent Chat
package raft

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/gob"
	"errors"
	"sync"
	"time"

	pb "go.etcd.io/raft/v3/raftpb"
)

// ====================================================================
// BFT Context & Types
// ====================================================================

type BFTPhase uint8

const (
	PhaseUnknown BFTPhase = iota
	PhasePrePrepare
	PhasePrepare
	PhaseCommit
	PhaseReply
)

type BFTContext struct {
	Phase  BFTPhase
	View   uint64
	SeqNum uint64
	Digest [32]byte
	Result []byte // For PhaseReply
}

type bftSeqKey struct {
	view uint64
	seq  uint64
}

type ClientProofConfig struct {
	MaxAge time.Duration
	Now    func() time.Time
}

func (c *ClientProofConfig) maxAge() time.Duration {
	if c == nil || c.MaxAge <= 0 {
		return DefaultMaxMessageAge
	}
	return c.MaxAge
}

func (c *ClientProofConfig) now() time.Time {
	if c == nil || c.Now == nil {
		return time.Now()
	}
	return c.Now()
}

func hashData(data []byte) [32]byte {
	return sha256.Sum256(data)
}

func encodeBFTContext(bctx BFTContext) ([]byte, error) {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(bctx); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func decodeBFTContext(data []byte) (BFTContext, error) {
	var bctx BFTContext
	if len(data) == 0 {
		return bctx, nil
	}
	err := gob.NewDecoder(bytes.NewReader(data)).Decode(&bctx)
	return bctx, err
}

// ====================================================================
// Shared Cryptographic Utility
// ====================================================================

func VerifyBFTMessageSignature(m *pb.Message, pubKey ed25519.PublicKey) (int64, []byte, error) {
	if len(pubKey) == 0 {
		return 0, nil, ErrUnknownSigner
	}

	sig, ts, origCtx, err := parseSignature(m.Context)
	if err != nil {
		return 0, nil, err
	}

	data, err := messageSignBytes(m, origCtx, ts)
	if err != nil {
		return 0, nil, err
	}

	if !ed25519.Verify(pubKey, data, sig) {
		return 0, nil, ErrInvalidSignature
	}

	return ts, origCtx, nil
}

// ====================================================================
// BFT Node Implementation
// ====================================================================

type BFTNode struct {
	Node
	selfID      uint64
	n           uint64
	f           uint64
	nodePubKeys map[uint64]ed25519.PublicKey
	clientIDs   map[uint64]struct{}
	clientPub   ed25519.PublicKey
	priv        ed25519.PrivateKey

	view uint64
	log  []pb.Entry

	pp       map[bftSeqKey][32]byte
	prepares map[bftSeqKey]map[uint64]struct{}
	commits  map[bftSeqKey]map[uint64]struct{}
	reqs     map[bftSeqKey][]pb.Entry // Buffer to hold full payloads during PBFT consensus

	lowW     uint64
	highW    uint64
	nextSeqN uint64

	cfg ClientProofConfig

	mu         sync.Mutex
	clientSeen map[uint64]int64

	bftMsgs  []pb.Message
	readyc   chan Ready
	triggerc chan struct{}
	advancec chan struct{}
}

func WrapBFTNode(
	n Node, selfID uint64, totalNodes uint64, priv ed25519.PrivateKey,
	nodePubKeys map[uint64]ed25519.PublicKey, clientIDs []uint64,
	clientPub ed25519.PublicKey, cfg *ClientProofConfig,
) *BFTNode {
	var c ClientProofConfig
	if cfg != nil {
		c = *cfg
	}

	bn := &BFTNode{
		Node:        n,
		selfID:      selfID,
		n:           totalNodes,
		f:           (totalNodes - 1) / 3,
		priv:        priv,
		nodePubKeys: nodePubKeys,
		clientIDs:   clientIDSet(clientIDs),
		clientPub:   clientPub,
		cfg:         c,

		pp:       make(map[bftSeqKey][32]byte),
		prepares: make(map[bftSeqKey]map[uint64]struct{}),
		commits:  make(map[bftSeqKey]map[uint64]struct{}),
		reqs:     make(map[bftSeqKey][]pb.Entry),

		lowW:     0,
		highW:    2000,
		nextSeqN: 1,

		clientSeen: make(map[uint64]int64),
		bftMsgs:    make([]pb.Message, 0),
		readyc:     make(chan Ready),
		triggerc:   make(chan struct{}, 1),
		advancec:   make(chan struct{}),
	}

	go bn.forwardReady()
	return bn
}

func (bn *BFTNode) forwardReady() {
	for {
		select {
		case rd, ok := <-bn.Node.Ready():
			if !ok {
				return
			}
			bn.mu.Lock()
			if len(bn.bftMsgs) > 0 {
				rd.Messages = append(rd.Messages, bn.bftMsgs...)
				bn.bftMsgs = nil
			}
			bn.mu.Unlock()
			bn.readyc <- rd
			<-bn.advancec
			bn.Node.Advance()

		case <-bn.triggerc:
			bn.mu.Lock()
			if len(bn.bftMsgs) > 0 {
				rd := Ready{Messages: bn.bftMsgs}
				bn.bftMsgs = nil
				bn.mu.Unlock()
				bn.readyc <- rd
				<-bn.advancec
			} else {
				bn.mu.Unlock()
			}
		}
	}
}

func (bn *BFTNode) Ready() <-chan Ready { return bn.readyc }

func (bn *BFTNode) Advance() {
	bn.advancec <- struct{}{}
}

func (bn *BFTNode) Tick() { bn.Node.Tick() }

func (bn *BFTNode) Propose(ctx context.Context, data []byte) error {
	return errors.New("bft: nodes must propose via BFTClient")
}

func (bn *BFTNode) Step(ctx context.Context, m *pb.Message) error {
	if m == nil {
		return errors.New("cannot step with nil message")
	}

	defer func() {
		bn.mu.Lock()
		hasMsgs := len(bn.bftMsgs) > 0
		bn.mu.Unlock()
		if hasMsgs {
			select {
			case bn.triggerc <- struct{}{}:
			default:
			}
		}
	}()

	if bn.isInternalMessage(m) {
		return bn.Node.Step(ctx, *m)
	}

	if err := bn.verifyMessage(m); err != nil {
		return err
	}

	bn.mu.Lock()
	defer bn.mu.Unlock()

	if bn.isClientRequest(m) {
		if bn.isLeader() {
			bctx, ppMsg, err := bn.ConstructPP(m)
			if err != nil {
				return err
			}

			key := bftSeqKey{view: bctx.View, seq: bctx.SeqNum}
			bn.pp[key] = bctx.Digest

			// Buffer the client payload locally
			if len(m.Entries) > 0 {
				bn.reqs[key] = m.Entries
			}

			if bn.prepares[key] == nil {
				bn.prepares[key] = make(map[uint64]struct{})
			}
			bn.prepares[key][bn.selfID] = struct{}{}

			bn.broadcast(ppMsg)
		}
		return nil
	}

	bctx, err := decodeBFTContext(m.Context)
	if err != nil {
		return bn.Node.Step(ctx, *m)
	}

	key := bftSeqKey{view: bctx.View, seq: bctx.SeqNum}

	switch bctx.Phase {
	case PhasePrePrepare:
		if bctx.View != bn.view {
			return errors.New("view mismatch")
		}
		if bctx.SeqNum <= bn.lowW || bctx.SeqNum > bn.highW {
			return errors.New("sequence number out of bounds")
		}
		if existing, exists := bn.pp[key]; exists && existing != bctx.Digest {
			return errors.New("conflicting pre-prepare digest")
		}

		bn.pp[key] = bctx.Digest

		// Buffer the payload received from the leader
		if len(m.Entries) > 0 {
			bn.reqs[key] = m.Entries
		}

		pMsg, err := bn.ConstructP(bctx)
		if err != nil {
			return err
		}

		if bn.prepares[key] == nil {
			bn.prepares[key] = make(map[uint64]struct{})
		}

		bn.prepares[key][m.From] = struct{}{}

		wasBelow := uint64(len(bn.prepares[key])) < (2*bn.f + 1)
		bn.prepares[key][bn.selfID] = struct{}{} // Self-vote
		isAbove := uint64(len(bn.prepares[key])) >= (2*bn.f + 1)

		bn.broadcast(pMsg)

		if wasBelow && isAbove {
			cMsg, err := bn.ConstructC(bctx)
			if err == nil {
				if bn.commits[key] == nil {
					bn.commits[key] = make(map[uint64]struct{})
				}
				bn.commits[key][bn.selfID] = struct{}{}
				bn.broadcast(cMsg)

				// Apply instantly if single node / f=0
				if uint64(len(bn.commits[key])) >= (2*bn.f + 1) {
					if entries, ok := bn.reqs[key]; ok {
						for _, ent := range entries {
							_ = bn.Node.Propose(ctx, ent.Data)
						}
					}
				}
			}
		}

	case PhasePrepare:
		if bn.prepares[key] == nil {
			bn.prepares[key] = make(map[uint64]struct{})
		}

		wasBelow := uint64(len(bn.prepares[key])) < (2*bn.f + 1)
		bn.prepares[key][m.From] = struct{}{}
		isAbove := uint64(len(bn.prepares[key])) >= (2*bn.f + 1)

		if wasBelow && isAbove {
			cMsg, err := bn.ConstructC(bctx)
			if err != nil {
				return err
			}

			if bn.commits[key] == nil {
				bn.commits[key] = make(map[uint64]struct{})
			}
			bn.commits[key][bn.selfID] = struct{}{}
			bn.broadcast(cMsg)

			if uint64(len(bn.commits[key])) >= (2*bn.f + 1) {
				if entries, ok := bn.reqs[key]; ok {
					for _, ent := range entries {
						_ = bn.Node.Propose(ctx, ent.Data)
					}
				}
			}
		}

	case PhaseCommit:
		if bn.commits[key] == nil {
			bn.commits[key] = make(map[uint64]struct{})
		}

		wasBelow := uint64(len(bn.commits[key])) < (2*bn.f + 1)
		bn.commits[key][m.From] = struct{}{}
		isAbove := uint64(len(bn.commits[key])) >= (2*bn.f + 1)

		if wasBelow && isAbove {
			// Retrieve the buffered entries from PrePrepare step to execute
			if entries, ok := bn.reqs[key]; ok {
				for _, ent := range entries {
					_ = bn.Node.Propose(ctx, ent.Data)
				}
			}
		}
	}

	return nil
}

func (bn *BFTNode) verifyMessage(m *pb.Message) error {
	if bn.isClientRequest(m) {
		return bn.VerifyClient(m)
	}

	pubKey, ok := bn.nodePubKeys[m.From]
	if !ok {
		return ErrUnknownSigner
	}

	_, origCtx, err := VerifyBFTMessageSignature(m, pubKey)
	if err != nil {
		return err
	}
	m.Context = origCtx
	return nil
}

func (bn *BFTNode) VerifyClient(m *pb.Message) error {
	if _, ok := bn.clientIDs[m.From]; !ok {
		return ErrUnknownSigner
	}

	ts, origCtx, err := VerifyBFTMessageSignature(m, bn.clientPub)
	if err != nil {
		return err
	}

	bn.mu.Lock()
	if last, ok := bn.clientSeen[m.From]; ok && ts <= last {
		bn.mu.Unlock()
		return ErrStaleMessage
	}
	bn.clientSeen[m.From] = ts
	bn.mu.Unlock()

	m.Context = origCtx
	return nil
}

func (bn *BFTNode) ConstructPP(m *pb.Message) (BFTContext, *pb.Message, error) {
	seq := bn.nextSeqN
	bn.nextSeqN++

	var data []byte
	if len(m.Entries) > 0 {
		data = m.Entries[0].Data
	}
	bctx := BFTContext{Phase: PhasePrePrepare, View: bn.view, SeqNum: seq, Digest: hashData(data)}
	encCtx, err := encodeBFTContext(bctx)
	if err != nil {
		return bctx, nil, err
	}

	return bctx, &pb.Message{Type: pb.MsgApp, From: bn.selfID, Context: encCtx, Entries: m.Entries}, nil
}

func (bn *BFTNode) ConstructP(bctx BFTContext) (*pb.Message, error) {
	bctx.Phase = PhasePrepare
	encCtx, err := encodeBFTContext(bctx)
	if err != nil {
		return nil, err
	}
	return &pb.Message{Type: pb.MsgApp, From: bn.selfID, Context: encCtx}, nil
}

func (bn *BFTNode) ConstructC(bctx BFTContext) (*pb.Message, error) {
	bctx.Phase = PhaseCommit
	encCtx, err := encodeBFTContext(bctx)
	if err != nil {
		return nil, err
	}
	return &pb.Message{Type: pb.MsgApp, From: bn.selfID, Context: encCtx}, nil
}

func (bn *BFTNode) broadcast(m *pb.Message) {
	for id := uint64(1); id <= bn.n; id++ {
		if id == bn.selfID {
			continue
		}
		mCopy := *m
		mCopy.To = id
		bn.bftMsgs = append(bn.bftMsgs, mCopy)
	}
}

func (bn *BFTNode) isLeader() bool { return (bn.view%bn.n)+1 == bn.selfID }
func (bn *BFTNode) isInternalMessage(m *pb.Message) bool {
	return IsLocalMsg(m.Type) || IsLocalMsgTarget(m.To) || IsLocalMsgTarget(m.From)
}
func (bn *BFTNode) isClientRequest(m *pb.Message) bool {
	return m != nil && m.Type == pb.MsgProp
}

// ====================================================================
// BFT Client Implementation
// ====================================================================

type pendingRequest struct {
	msg       pb.Message
	timestamp int64
	ticks     int
}

type BFTClient struct {
	selfID      uint64
	n           uint64
	f           uint64
	nodePubKeys map[uint64]ed25519.PublicKey
	clientIDs   map[uint64]struct{}
	clientPub   ed25519.PublicKey
	priv        ed25519.PrivateKey

	pending map[int64]*pendingRequest
	replies map[int64]map[uint64][]byte

	cfg ClientProofConfig

	mu         sync.Mutex
	lastSent   int64
	readyc     chan pb.Message
	ConsensusC chan []byte
}

func NewBFTClient(
	selfID uint64, totalNodes uint64, priv ed25519.PrivateKey,
	nodePubKeys map[uint64]ed25519.PublicKey, clientIDs []uint64,
	clientPub ed25519.PublicKey, cfg *ClientProofConfig,
) *BFTClient {
	var c ClientProofConfig
	if cfg != nil {
		c = *cfg
	}
	return &BFTClient{
		selfID:      selfID,
		n:           totalNodes,
		f:           (totalNodes - 1) / 3,
		priv:        priv,
		nodePubKeys: nodePubKeys,
		clientIDs:   clientIDSet(clientIDs),
		clientPub:   clientPub,
		cfg:         c,
		pending:     make(map[int64]*pendingRequest),
		replies:     make(map[int64]map[uint64][]byte),
		readyc:      make(chan pb.Message, 100),
		ConsensusC:  make(chan []byte, 10),
	}
}

func (c *BFTClient) Tick() {
	c.mu.Lock()
	defer c.mu.Unlock()

	for ts, req := range c.pending {
		req.ticks++
		if req.ticks > 10 {
			for id := uint64(1); id <= c.n; id++ {
				mCopy := req.msg
				mCopy.To = id

				origCtx := normalizeContext(mCopy.Context)
				dataSign, _ := messageSignBytes(&mCopy, origCtx, ts)
				sig := ed25519.Sign(c.priv, dataSign)
				mCopy.Context = packSignature(sig, ts, origCtx)

				c.readyc <- mCopy
			}
			req.ticks = 0
		}
		c.pending[ts] = req
	}
}

func (c *BFTClient) Ready() <-chan pb.Message { return c.readyc }

func (c *BFTClient) Propose(ctx context.Context, data []byte) error {
	c.mu.Lock()
	ts := c.cfg.now().UnixNano()
	if ts <= c.lastSent {
		ts = c.lastSent + 1
	}
	c.lastSent = ts
	c.mu.Unlock()

	baseMsg := pb.Message{
		Type:    pb.MsgProp,
		From:    c.selfID,
		Entries: []pb.Entry{{Data: data}},
	}

	c.mu.Lock()
	c.pending[ts] = &pendingRequest{msg: baseMsg, timestamp: ts, ticks: 0}
	c.mu.Unlock()

	for id := uint64(1); id <= c.n; id++ {
		mCopy := baseMsg
		mCopy.To = id

		origCtx := normalizeContext(mCopy.Context)
		dataSign, err := messageSignBytes(&mCopy, origCtx, ts)
		if err != nil {
			return err
		}
		sig := ed25519.Sign(c.priv, dataSign)
		mCopy.Context = packSignature(sig, ts, origCtx)

		select {
		case c.readyc <- mCopy:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func (c *BFTClient) Step(ctx context.Context, m *pb.Message) error {
	if m == nil {
		return errors.New("nil message")
	}

	ts, err := c.verifyMessage(m)
	if err != nil {
		return err
	}

	bctx, err := decodeBFTContext(m.Context)
	if err != nil || bctx.Phase != PhaseReply {
		return errors.New("invalid reply message")
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if _, exists := c.pending[ts]; !exists {
		return nil
	}

	if c.replies[ts] == nil {
		c.replies[ts] = make(map[uint64][]byte)
	}
	c.replies[ts][m.From] = bctx.Result

	resultCounts := make(map[string]uint64)
	for _, res := range c.replies[ts] {
		resultCounts[string(res)]++

		if resultCounts[string(res)] == (c.f + 1) {
			delete(c.pending, ts)
			delete(c.replies, ts)

			select {
			case c.ConsensusC <- res:
			default:
			}
			return nil
		}
	}
	return nil
}

func (c *BFTClient) verifyMessage(m *pb.Message) (int64, error) {
	pubKey, ok := c.nodePubKeys[m.From]
	if !ok {
		return 0, ErrUnknownSigner
	}

	ts, origCtx, err := VerifyBFTMessageSignature(m, pubKey)
	if err != nil {
		return 0, err
	}

	m.Context = origCtx
	return ts, nil
}

func (c *BFTClient) AddClientProof(m *pb.Message) (int64, error) {
	m.From = c.selfID
	origCtx := normalizeContext(m.Context)

	c.mu.Lock()
	ts := c.cfg.now().UnixNano()
	if ts <= c.lastSent {
		ts = c.lastSent + 1
	}
	c.lastSent = ts
	c.mu.Unlock()

	data, err := messageSignBytes(m, origCtx, ts)
	if err != nil {
		return 0, err
	}
	sig := ed25519.Sign(c.priv, data)
	m.Context = packSignature(sig, ts, origCtx)
	return ts, nil
}
