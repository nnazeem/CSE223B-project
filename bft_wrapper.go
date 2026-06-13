package raft

import (
	"context"
	"crypto/ed25519"
	"errors"
	"sync"

	"github.com/golang/protobuf/proto"

	pb "go.etcd.io/raft/v3/raftpb"
)

// ====================================================================
// BFT Context & Types
// ====================================================================

// type BFTPhase uint8

// const (
// 	PhaseUnknown BFTPhase = iota
// 	PhasePrePrepare
// 	PhasePrepare
// 	PhaseCommit
// 	PhaseReply
// )

// type BFTContext struct {
// 	Phase  BFTPhase
// 	View   uint64
// 	SeqNum uint64
// 	Digest [32]byte
// 	Result []byte // For PhaseReply
// }

type StableCheckpoint struct {
	SeqNum uint64
	Digest [32]byte

	Proof BFTCheckpointProof // proofs of the stable checkpoint, should be 2f+1
}

type bftSeqKey struct {
	view uint64
	seq  uint64
}

// shouldSign reports whether an outbound message must be signed before delivery.
func clientIDSet(ids []uint64) map[uint64]struct{} {
	if len(ids) == 0 {
		return nil
	}
	set := make(map[uint64]struct{}, len(ids))
	for _, id := range ids {
		if id != 0 {
			set[id] = struct{}{}
		}
	}
	return set
}

// type ClientProofConfig struct {
// 	MaxAge time.Duration
// 	Now    func() time.Time
// }

// func (c *ClientProofConfig) maxAge() time.Duration {
// 	if c == nil || c.MaxAge <= 0 {
// 		return DefaultMaxMessageAge
// 	}
// 	return c.MaxAge
// }

// func (c *ClientProofConfig) now() time.Time {
// 	if c == nil || c.Now == nil {
// 		return time.Now()
// 	}
// 	return c.Now()
// }

// func hashData(data []byte) [32]byte {
// 	return sha256.Sum256(data)
// }

// func encodeBFTContext(bctx BFTContext) ([]byte, error) {
// 	var buf bytes.Buffer
// 	if err := gob.NewEncoder(&buf).Encode(bctx); err != nil {
// 		return nil, err
// 	}
// 	return buf.Bytes(), nil
// }

// func decodeBFTContext(data []byte) (BFTContext, error) {
// 	var bctx BFTContext
// 	if len(data) == 0 {
// 		return bctx, nil
// 	}
// 	err := gob.NewDecoder(bytes.NewReader(data)).Decode(&bctx)
// 	return bctx, err
// }

// ====================================================================
// Shared Cryptographic Utility
// ====================================================================

// func VerifyBFTMessageSignature(m *pb.Message, pubKey ed25519.PublicKey) (int64, []byte, error) {
// 	if len(pubKey) == 0 {
// 		return 0, nil, ErrUnknownSigner
// 	}

// 	sig, ts, origCtx, err := parseSignature(m.Context)
// 	if err != nil {
// 		return 0, nil, err
// 	}

// 	data, err := messageSignBytes(m, origCtx, ts)
// 	if err != nil {
// 		return 0, nil, err
// 	}

// 	if !ed25519.Verify(pubKey, data, sig) {
// 		return 0, nil, ErrInvalidSignature
// 	}

// 	return ts, origCtx, nil
// }

// ====================================================================
// BFT Node Implementation
// ====================================================================

const (
	// CheckpointInterval (X): create a checkpoint every X executed sequence numbers.
	CheckpointInterval = 100
	// WatermarkWindow (k): H = h + k; must be greater than CheckpointInterval.
	WatermarkWindow = 200
)

type BFTNode struct {
	Node
	selfID      uint64
	n           uint64
	f           uint64
	nodePubKeys map[uint64]ed25519.PublicKey
	clientIDs   map[uint64]struct{}
	clientPub   ed25519.PublicKey
	priv        ed25519.PrivateKey

	bftMessageBuilder *BFTMessageBuilder

	nodePhase BFTNodePhase
	view      uint64
	log       map[uint64]*pb.Message

	pp       map[bftSeqKey][32]byte
	prepares map[bftSeqKey]map[uint64]*pb.Message
	commits  map[bftSeqKey]map[uint64]struct{}
	reqs     map[bftSeqKey]*pb.Message // Buffer to hold full payloads during PBFT consensus

	requestTS     map[bftSeqKey]int64
	requestClient map[bftSeqKey]uint64

	timer         *PendingTimer
	pending       []uint64
	vc            map[uint64]map[uint64]*pb.Message
	vc_timer      *PendingTimer
	campaign_view uint64
	last_replied  uint64

	lowW     uint64
	highW    uint64
	nextSeqN uint64

	cfg ClientProofConfig

	mu         sync.Mutex
	clientSeen map[uint64]int64

	bftMsgs  []*pb.Message
	readyc   chan Ready
	triggerc chan struct{}
	advancec chan struct{}

	checkpoints map[uint64]map[[32]byte]map[uint64]*pb.Message

	stableCheckpoint *StableCheckpoint
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

		bftMessageBuilder: NewBFTMessageBuilder(selfID, priv, &c),

		pp:            make(map[bftSeqKey][32]byte),
		prepares:      make(map[bftSeqKey]map[uint64]*pb.Message),
		commits:       make(map[bftSeqKey]map[uint64]struct{}),
		reqs:          make(map[bftSeqKey]*pb.Message),
		requestTS:     make(map[bftSeqKey]int64),
		requestClient: make(map[bftSeqKey]uint64),

		pending:       make([]uint64, 0),
		timer:         NewPendingTimer(100),
		nodePhase:     Normal,
		log:           make(map[uint64]*pb.Message),
		vc:            make(map[uint64]map[uint64]*pb.Message),
		vc_timer:      NewPendingTimer(30 / 2),
		campaign_view: 0,

		lowW:     0,
		highW:    WatermarkWindow,
		nextSeqN: 1,

		clientSeen: make(map[uint64]int64),
		bftMsgs:    make([]*pb.Message, 0),
		readyc:     make(chan Ready),
		triggerc:   make(chan struct{}, 1),
		advancec:   make(chan struct{}),

		checkpoints:      make(map[uint64]map[[32]byte]map[uint64]*pb.Message),
		stableCheckpoint: nil,
	}

	go bn.forwardReady()
	return bn
}

func (bn *BFTNode) signOutboundMessages(msgs []*pb.Message) {
	for i := range msgs {
		if msgs[i] == nil {
			continue
		}

		// Forwarded client requests must preserve the client's signature.
		// A backup may change To to point at the primary, but it must not
		// replace the client signature with the replica signature.
		if bn.isClientRequest(msgs[i]) {
			continue
		}

		ts := bn.cfg.now().UnixNano()
		origCtx := normalizeContext(msgs[i].Context)

		dataSign, err := messageSignBytes(msgs[i], origCtx, ts)
		if err != nil {
			continue
		}

		sig := ed25519.Sign(bn.priv, dataSign)
		msgs[i].Context = packSignature(sig, ts, origCtx)
	}
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

			bn.signOutboundMessages(rd.Messages)

			bn.readyc <- rd
			<-bn.advancec
			bn.Node.Advance()

		case <-bn.triggerc:
			bn.mu.Lock()
			if len(bn.bftMsgs) > 0 {
				rd := Ready{Messages: bn.bftMsgs}
				bn.bftMsgs = nil
				bn.mu.Unlock()

				bn.signOutboundMessages(rd.Messages)

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

func (bn *BFTNode) TriggerViewChange(newView uint64) error {
	bn.nodePhase = ViewChange
	bn.pending = make([]uint64, 0)
	bn.timer.Stop()

	vc, err := bn.ConstructViewChange(newView)
	if err != nil {
		return err
	}

	vcEvidence, err := bn.signEvidence(vc)
	if err != nil {
		return err
	}

	if bn.vc[newView] == nil {
		bn.vc[newView] = make(map[uint64]*pb.Message)
	}
	bn.vc[newView][bn.selfID] = vcEvidence

	bn.campaign_view = newView
	bn.vc_timer.StartExp()

	bn.broadcast(vc)
	return nil
}

func (bn *BFTNode) ConstructViewChange(newView uint64) (*pb.Message, error) {
	lastStableSeq := uint64(0)
	checkpointProof := BFTCheckpointProof{}

	if bn.stableCheckpoint != nil {
		lastStableSeq = bn.stableCheckpoint.SeqNum
		checkpointProof = bn.stableCheckpoint.Proof
	}

	var preparedProofs []BFTPreparedProof
	for key := range bn.pp {
		if key.seq <= lastStableSeq {
			continue
		}

		pKey := bftSeqKey{view: key.view, seq: key.seq}
		if uint64(len(bn.prepares[pKey])) >= 2*bn.f {
			preparedProofs = append(preparedProofs, BFTPreparedProof{
				View:     pKey.view,
				SeqNum:   pKey.seq,
				Digest:   bn.pp[pKey],
				Prepares: MapValues(bn.prepares[pKey]),
			})
		}
	}

	bctx := BFTContext{
		Phase:            PhaseViewChange,
		View:             newView,
		SeqNum:           lastStableSeq,
		CheckpointSeqNum: lastStableSeq,
		CheckpointDigest: checkpointProof.Digest,
		CheckpointProofs: checkpointProof,
		PreparedProofs:   preparedProofs,
	}

	encCtx, err := encodeBFTContext(bctx)
	if err != nil {
		return nil, err
	}

	return &pb.Message{
		Type:    pb.MsgApp.Enum(),
		From:    u64p(bn.selfID),
		Context: encCtx,
	}, nil
}

func (bn *BFTNode) notifyReadyIfNeeded() {
	bn.mu.Lock()
	hasMsgs := len(bn.bftMsgs) > 0
	bn.mu.Unlock()

	if hasMsgs {
		select {
		case bn.triggerc <- struct{}{}:
		default:
		}
	}
}

func (bn *BFTNode) TriggerNewView(view uint64) error {
	nv, err := bn.ConstructNewView(view)
	if err != nil {
		return err
	}

	bctx, err := decodeBFTContext(nv.Context)
	if err != nil {
		return err
	}

	if err := bn.installNewView(bctx); err != nil {
		return err
	}

	bn.broadcast(nv)
	return nil
}

func (bn *BFTNode) ConstructNewView(view uint64) (*pb.Message, error) {
	vcs := bn.vc[view]
	if uint64(len(vcs)) < 2*bn.f+1 {
		return nil, errors.New("insufficient view-change quorum")
	}

	viewSet := make([]pb.Message, 0, len(vcs))
	for _, vc := range vcs {
		if vc != nil {
			viewSet = append(viewSet, *proto.Clone(vc).(*pb.Message))
		}
	}

	if uint64(len(viewSet)) < 2*bn.f+1 {
		return nil, errors.New("insufficient non-nil view-change quorum")
	}

	prePrepareSet, err := bn.computeNewViewPrePrepareSet(view, vcs)
	if err != nil {
		return nil, err
	}

	bctx := BFTContext{
		Phase:         PhaseNewView,
		View:          view,
		ViewSet:       viewSet,
		PrePrepareSet: prePrepareSet,
	}

	encCtx, err := encodeBFTContext(bctx)
	if err != nil {
		return nil, err
	}

	return &pb.Message{
		Type:    pb.MsgApp.Enum(),
		From:    u64p(bn.selfID),
		Context: encCtx,
	}, nil
}

func (bn *BFTNode) computeNewViewPrePrepareSet(
	newView uint64,
	vcs map[uint64]*pb.Message,
) ([]pb.Message, error) {
	type selected struct {
		preparedView     uint64
		seq              uint64
		digest           [32]byte
		entries          []*pb.Entry
		requestTimestamp int64
		clientID         uint64
		clientRequest    pb.Message
	}

	selectedBySeq := make(map[uint64]selected)

	for replica, signedVC := range vcs {
		pub, ok := bn.nodePubKeys[replica]
		if !ok {
			return nil, ErrUnknownSigner
		}

		_, origCtx, err := VerifyBFTMessageSignature(signedVC, pub)
		if err != nil {
			return nil, err
		}

		vcCtx, err := decodeBFTContext(origCtx)
		if err != nil {
			return nil, err
		}

		for _, proof := range vcCtx.PreparedProofs {
			if proof.SeqNum <= vcCtx.CheckpointSeqNum {
				continue
			}

			entries, requestTS, clientID, clientReq, ok := extractPreparedPrePrepare(proof)
			if !ok {
				return nil, ErrInvalidPreparedProof
			}

			cur, exists := selectedBySeq[proof.SeqNum]
			if !exists || proof.View > cur.preparedView {
				selectedBySeq[proof.SeqNum] = selected{
					preparedView:     proof.View,
					seq:              proof.SeqNum,
					digest:           proof.Digest,
					entries:          entries,
					requestTimestamp: requestTS,
					clientID:         clientID,
					clientRequest:    clientReq,
				}
			}
		}
	}

	out := make([]pb.Message, 0, len(selectedBySeq))
	for _, sel := range selectedBySeq {
		bctx := BFTContext{
			Phase:            PhasePrePrepare,
			View:             newView,
			SeqNum:           sel.seq,
			Digest:           sel.digest,
			RequestTimestamp: sel.requestTimestamp,
			ClientID:         sel.clientID,
			ClientRequest:    sel.clientRequest,
		}
		encCtx, err := encodeBFTContext(bctx)
		if err != nil {
			return nil, err
		}

		pp := &pb.Message{
			Type:    pb.MsgApp.Enum(),
			From:    u64p(bn.primaryForView(newView)),
			Context: encCtx,
			Entries: cloneEntries(sel.entries),
		}

		signedPP, err := bn.signEvidence(pp)
		if err != nil {
			return nil, err
		}

		out = append(out, *signedPP)
	}

	return out, nil
}

func (bn *BFTNode) Tick() {
	// println("bft: tick")
	bn.Node.Tick()
	bn.mu.Lock()
	expired := false
	if bn.nodePhase == Normal {
		expired = bn.timer.Tick()
		if expired {
			err := bn.TriggerViewChange(bn.view + 1)
			if err != nil {
				println("error triggering view change")
			}
			//println("bft: view change triggered")
		}
	} else {
		expired = bn.vc_timer.Tick()
		if expired {
			err := bn.TriggerViewChange(bn.campaign_view + 1)
			if err != nil {
				println("error triggering view change after expiry")
			}
			//println("bft: triggered view change after expiry")
		}
	}
	bn.mu.Unlock()

	if expired {
		bn.notifyReadyIfNeeded()
	}
}

func (bn *BFTNode) Propose(ctx context.Context, data []byte) error {
	return errors.New("bft: nodes must propose via BFTClient")
}

func (bn *BFTNode) Step(ctx context.Context, m *pb.Message) error {
	if m == nil {
		return errors.New("cannot step with nil message")
	}

	defer bn.notifyReadyIfNeeded()

	if bn.isInternalMessage(m) {
		return bn.Node.Step(ctx, m)
	}

	var clientReqTS int64

	signedMsg := proto.Clone(m).(*pb.Message)

	if bn.isClientRequest(m) {
		ts, err := bn.VerifyClient(m)
		if err != nil {
			return err
		}
		clientReqTS = ts
	} else {
		if err := bn.verifyMessage(m); err != nil {
			return err
		}
	}

	var pendingProposals [][]byte

	bn.mu.Lock()
	if bn.nodePhase == Normal {
		if bn.isClientRequest(m) {
			//println("bft: client_request")
			if bn.isLeader() {
				bctx, ppMsg, err := bn.ConstructPP(m, signedMsg, clientReqTS)
				if err != nil {
					bn.mu.Unlock()
					return err
				}

				key := bftSeqKey{view: bctx.View, seq: bctx.SeqNum}
				bn.requestTS[key] = bctx.RequestTimestamp
				bn.requestClient[key] = bctx.ClientID
				bn.pp[key] = bctx.Digest
				if !containsSeq(bn.pending, key.seq) {
					bn.pending = append(bn.pending, key.seq)
				}
				bn.timer.Start()

				bn.reqs[key] = m

				if bn.prepares[key] == nil {
					bn.prepares[key] = make(map[uint64]*pb.Message)
				}

				ppEvidence, err := bn.signEvidence(ppMsg)
				if err != nil {
					bn.mu.Unlock()
					return err
				}
				bn.prepares[key][bn.selfID] = ppEvidence

				bn.broadcast(ppMsg)
			} else {
				forward := proto.Clone(signedMsg).(*pb.Message)
				forward.To = u64p(bn.primaryForView(bn.view))
				bn.bftMsgs = append(bn.bftMsgs, forward)
			}
			bn.mu.Unlock()
			return nil
		}
	}

	bctx, err := decodeBFTContext(m.Context)
	// TUNNEL: Pass authenticated native Raft traffic to the inner core!
	if err != nil || bctx.Phase == PhaseUnknown {
		bn.mu.Unlock()
		return bn.Node.Step(ctx, m)
	}

	key := bftSeqKey{view: bctx.View, seq: bctx.SeqNum}

	switch bctx.Phase {
	case PhaseCheckpoint:
		//println("bft: checkpoint")
		seq := bctx.CheckpointSeqNum
		dig := bctx.CheckpointDigest
		bn.acceptCheckpoint(seq, dig, m.GetFrom(), signedMsg)
		bn.mu.Unlock()
		return nil
	case PhaseViewChange:
		if bn.vc[bctx.View] == nil {
			bn.vc[bctx.View] = make(map[uint64]*pb.Message)
		}
		bn.vc[bctx.View][signedMsg.GetFrom()] = signedMsg

		count, minView, ok := countMessagesAfterAndMinKey(bn.vc, bn.view)
		if ok && uint64(count) >= bn.f+1 && bn.campaign_view < minView {
			if err := bn.TriggerViewChange(minView); err != nil {
				bn.mu.Unlock()
				return err
			}
		}

		if uint64(len(bn.vc[bctx.View])) >= 2*bn.f+1 {
			if bn.vc_timer.isOn() {
				bn.vc_timer.StopAndResetBackoff()
			}

			if bn.isPrimaryForView(bctx.View) {
				if err := bn.TriggerNewView(bctx.View); err != nil {
					bn.mu.Unlock()
					return err
				}
			}
		}

		bn.mu.Unlock()
		return nil
	case PhaseNewView:
		if err := bn.installNewView(bctx); err != nil {
			bn.mu.Unlock()
			return err
		}
		bn.mu.Unlock()
		return nil
	}

	if bn.nodePhase == Normal {
		switch bctx.Phase {
		case PhasePrePrepare:
			//println("bft: pp")
			if bctx.View != bn.view {
				bn.mu.Unlock()
				return errors.New("view mismatch")
			}
			// this means only message completes at a time
			// (bctx.SeqNum > bn.last_replied+1)
			if bctx.SeqNum <= bn.lowW || bctx.SeqNum > bn.highW {
				bn.mu.Unlock()
				return errors.New("sequence number out of bounds")
			}
			if existing, exists := bn.pp[key]; exists && existing != bctx.Digest {
				bn.mu.Unlock()
				return errors.New("conflicting pre-prepare digest")
			}

			bn.pp[key] = bctx.Digest
			bn.requestTS[key] = bctx.RequestTimestamp
			bn.requestClient[key] = bctx.ClientID
			if !containsSeq(bn.pending, key.seq) {
				bn.pending = append(bn.pending, key.seq)
			}
			bn.timer.Start()

			bn.reqs[key] = m

			pMsg, err := bn.ConstructP(bctx)
			if err != nil {
				bn.mu.Unlock()
				return err
			}

			if bn.prepares[key] == nil {
				bn.prepares[key] = make(map[uint64]*pb.Message)
			}

			bn.prepares[key][m.GetFrom()] = signedMsg
			wasBelow := uint64(len(bn.prepares[key])) < (2*bn.f + 1)
			pEvidence, err := bn.signEvidence(pMsg)
			if err != nil {
				bn.mu.Unlock()
				return err
			}
			bn.prepares[key][bn.selfID] = pEvidence
			isAbove := uint64(len(bn.prepares[key])) >= (2*bn.f + 1)

			bn.broadcast(pMsg)

			if wasBelow && isAbove {
				cMsg, err := bn.ConstructC(bctx)
				if err != nil {
					bn.mu.Unlock()
					return err
				}

				if bn.commits[key] == nil {
					bn.commits[key] = make(map[uint64]struct{})
				}
				bn.commits[key][bn.selfID] = struct{}{}
				bn.broadcast(cMsg)

				if uint64(len(bn.commits[key])) >= (2*bn.f + 1) {
					pendingProposals = append(pendingProposals, bn.onCommitQuorum(key)...)
				}
			}

		case PhasePrepare:
			//println("bft: ch")
			if !bn.acceptedDigestMatches(key, bctx.Digest) {
				bn.mu.Unlock()
				return errors.New("raft: prepare does not match accepted pre-prepare")
			}
			if m.GetFrom() == bn.primaryForView(bctx.View) {
				bn.mu.Unlock()
				return errors.New("raft: primary must not send prepare")
			}

			if bn.prepares[key] == nil {
				bn.prepares[key] = make(map[uint64]*pb.Message)
			}

			wasBelow := uint64(len(bn.prepares[key])) < (2*bn.f + 1)
			bn.prepares[key][m.GetFrom()] = signedMsg
			isAbove := uint64(len(bn.prepares[key])) >= (2*bn.f + 1)

			if wasBelow && isAbove {
				cMsg, err := bn.ConstructC(bctx)
				if err != nil {
					bn.mu.Unlock()
					return err
				}

				if bn.commits[key] == nil {
					bn.commits[key] = make(map[uint64]struct{})
				}
				bn.commits[key][bn.selfID] = struct{}{}
				bn.broadcast(cMsg)

				if uint64(len(bn.commits[key])) >= (2*bn.f + 1) {
					pendingProposals = append(pendingProposals, bn.onCommitQuorum(key)...)
				}
			}

		case PhaseCommit:
			//println("bft: commit")
			if !bn.acceptedDigestMatches(key, bctx.Digest) {
				bn.mu.Unlock()
				return errors.New("raft: commit does not match accepted pre-prepare")
			}
			if uint64(len(bn.prepares[key])) < 2*bn.f+1 {
				bn.mu.Unlock()
				return errors.New("raft: commit before prepared certificate")
			}

			if bn.commits[key] == nil {
				bn.commits[key] = make(map[uint64]struct{})
			}

			wasBelow := uint64(len(bn.commits[key])) < (2*bn.f + 1)
			bn.commits[key][m.GetFrom()] = struct{}{}
			isAbove := uint64(len(bn.commits[key])) >= (2*bn.f + 1)

			if wasBelow && isAbove {
				pendingProposals = append(pendingProposals, bn.onCommitQuorum(key)...)
			}
			//println("bft: commit done")
		}
	}

	bn.mu.Unlock()

	for _, data := range pendingProposals {
		go func(d []byte) {
			_ = bn.Node.Propose(context.Background(), d)
		}(data)
	}

	return nil
}

func (bn *BFTNode) verifyMessage(m *pb.Message) error {
	if m == nil {
		return ErrInvalidBFTMessage
	}

	if bn.isClientRequest(m) {
		_, err := bn.VerifyClient(m)
		return err
	}

	pubKey, ok := bn.nodePubKeys[m.GetFrom()]
	if !ok {
		return ErrUnknownSigner
	}

	_, origCtx, err := VerifyBFTMessageSignature(m, pubKey)
	if err != nil {
		return err
	}

	bctx, decodeErr := decodeBFTContext(origCtx)
	if decodeErr == nil && bctx.Phase.IsBFTMessagePhase() {
		if err := bn.validateBFTMessage(m, bctx); err != nil {
			return err
		}
	}

	// Preserve existing tunnel behavior: signed non-BFT raft traffic is allowed
	// through after signature verification.
	m.Context = origCtx
	return nil
}

func (bn *BFTNode) VerifyClient(m *pb.Message) (int64, error) {
	if _, ok := bn.clientIDs[m.GetFrom()]; !ok {
		return 0, ErrUnknownSigner
	}

	ts, origCtx, err := VerifyBFTMessageSignature(m, bn.clientPub)
	if err != nil {
		return 0, err
	}

	bn.mu.Lock()
	if last, ok := bn.clientSeen[m.GetFrom()]; ok && ts <= last {
		bn.mu.Unlock()
		return 0, ErrStaleMessage
	}
	bn.clientSeen[m.GetFrom()] = ts
	bn.mu.Unlock()

	m.Context = origCtx
	return ts, nil
}

func (bn *BFTNode) ConstructPP(
	m *pb.Message,
	signedClientReq *pb.Message,
	requestTS int64,
) (BFTContext, *pb.Message, error) {
	seq := bn.nextSeqN
	bn.nextSeqN++

	entries := cloneEntries(m.GetEntries())
	digest, err := hashEntryBatch(entries)
	if err != nil {
		return BFTContext{}, nil, err
	}

	clientReqCopy := pb.Message{}
	if signedClientReq != nil {
		clientReqCopy = *proto.Clone(signedClientReq).(*pb.Message)
	}

	bctx := BFTContext{
		Phase:            PhasePrePrepare,
		View:             bn.view,
		SeqNum:           seq,
		Digest:           digest,
		RequestTimestamp: requestTS,
		ClientID:         m.GetFrom(),
		ClientRequest:    clientReqCopy,
	}

	encCtx, err := encodeBFTContext(bctx)
	if err != nil {
		return bctx, nil, err
	}

	return bctx, &pb.Message{
		Type:    pb.MsgApp.Enum(),
		From:    u64p(bn.selfID),
		Context: encCtx,
		Entries: entries,
	}, nil
}

func (bn *BFTNode) ConstructP(bctx BFTContext) (*pb.Message, error) {
	bctx.Phase = PhasePrepare
	encCtx, err := encodeBFTContext(bctx)
	if err != nil {
		return nil, err
	}
	return &pb.Message{Type: pb.MsgApp.Enum(), From: u64p(bn.selfID), Context: encCtx}, nil
}

func (bn *BFTNode) ConstructC(bctx BFTContext) (*pb.Message, error) {
	bctx.Phase = PhaseCommit
	encCtx, err := encodeBFTContext(bctx)
	if err != nil {
		return nil, err
	}
	return &pb.Message{Type: pb.MsgApp.Enum(), From: u64p(bn.selfID), Context: encCtx}, nil
}

func (bn *BFTNode) ConstructCheckpoint(seq uint64, digest [32]byte) (*pb.Message, error) {
	bctx := BFTContext{
		Phase:            PhaseCheckpoint,
		View:             bn.view,
		SeqNum:           seq,
		Digest:           digest,
		CheckpointSeqNum: seq,
		CheckpointDigest: digest,
	}

	encCtx, err := encodeBFTContext(bctx)
	if err != nil {
		return nil, err
	}

	return &pb.Message{
		Type:    pb.MsgApp.Enum(),
		From:    u64p(bn.selfID),
		Context: encCtx,
	}, nil
}

func (bn *BFTNode) committedKeyForSeq(seq uint64) (bftSeqKey, bool) {
	var selected bftSeqKey
	found := false

	for key, committers := range bn.commits {
		if key.seq != seq {
			continue
		}
		if uint64(len(committers)) < 2*bn.f+1 {
			continue
		}
		if bn.reqs[key] == nil {
			continue
		}
		if _, ok := bn.pp[key]; !ok {
			continue
		}
		if !found || key.view > selected.view {
			selected = key
			found = true
		}
	}

	return selected, found
}

func (bn *BFTNode) removePendingSeq(seq uint64) {
	newPending := bn.pending[:0]
	for _, pendingSeq := range bn.pending {
		if pendingSeq != seq {
			newPending = append(newPending, pendingSeq)
		}
	}
	bn.pending = newPending
}

func (bn *BFTNode) refreshPendingTimer() {
	if len(bn.pending) == 0 {
		bn.timer.Stop()
		return
	}
	bn.timer.Reset()
}

func (bn *BFTNode) onCommitQuorum(key bftSeqKey) [][]byte {
	var data [][]byte

	// A commit certificate only makes a request durable. It must not become
	// visible in the executed log until every lower sequence number has also
	// committed. Otherwise a Byzantine primary can make honest replicas expose
	// log[2] while log[1] is missing, which is an order-safety violation.
	for {
		nextSeq := bn.last_replied + 1
		nextKey, ok := bn.committedKeyForSeq(nextSeq)
		if !ok {
			break
		}

		req := bn.reqs[nextKey]
		if req == nil {
			break
		}

		bn.log[nextSeq] = req
		bn.last_replied = nextSeq

		for _, ent := range req.GetEntries() {
			if ent != nil {
				data = append(data, append([]byte(nil), ent.Data...))
			}
		}

		reply, err := bn.ConstructReply(nextKey, []byte("OK"))
		if err == nil && reply != nil {
			bn.bftMsgs = append(bn.bftMsgs, reply)
		}

		bn.removePendingSeq(nextSeq)
		bn.constructCheckpointIfNeeded(nextSeq)
	}

	bn.refreshPendingTimer()
	return data
}

func (bn *BFTNode) getLog() map[uint64]*pb.Message {
	return bn.log
}

func (bn *BFTNode) stateDigestAt(seq uint64) [32]byte {
	var logAtSeq []*pb.Message
	for s := uint64(1); s <= seq; s++ {
		logAtSeq = append(logAtSeq, bn.log[s])
		// k := bftSeqKey{view: bn.view, seq: s}
		// if d, ok := bn.pp[k]; ok {
		// 	buf = append(buf, d[:]...)
		// }
	}

	h, err := hashMessageBatch(logAtSeq)

	if err != nil {
		println("stateDigestAt: hashing failed -- should not happen")
	}

	return h
}

func (bn *BFTNode) hasExecutedThrough(seq uint64) bool {
	for s := uint64(1); s <= seq; s++ {
		if _, ok := bn.log[s]; !ok {
			return false
		}
	}
	return true
}

func (bn *BFTNode) localCheckpointDigest(seq uint64) ([32]byte, bool) {
	if !bn.hasExecutedThrough(seq) {
		return [32]byte{}, false
	}
	digest := bn.stateDigestAt(seq)
	return digest, true
}

func (bn *BFTNode) recordCheckpoint(seq uint64, dig [32]byte, replica uint64, msg *pb.Message) {
	if bn.checkpoints[seq] == nil {
		bn.checkpoints[seq] = make(map[[32]byte]map[uint64]*pb.Message)
	}
	if bn.checkpoints[seq][dig] == nil {
		bn.checkpoints[seq][dig] = make(map[uint64]*pb.Message)
	}
	bn.checkpoints[seq][dig][replica] = msg
}

// acceptCheckpoint records a peer checkpoint only if this replica has executed
// through seq and agrees on the state digest. Stabilization requires 2f+1 such
// proofs (at least f+1 non-faulty replicas in the f < n/3 model).
func (bn *BFTNode) acceptCheckpoint(seq uint64, dig [32]byte, replica uint64, msg *pb.Message) {
	localDig, ok := bn.localCheckpointDigest(seq)
	if !ok || localDig != dig {
		return
	}
	bn.recordCheckpoint(seq, dig, replica, msg)
	if uint64(len(bn.checkpoints[seq][dig])) >= 2*bn.f+1 {
		bn.stabilizeCheckpoint(seq, dig)
	}
}

// constructCheckpointIfNeeded creates and multicasts a CHECKPOINT after executing
// seq when seq is a multiple of CheckpointInterval.
func (bn *BFTNode) constructCheckpointIfNeeded(seq uint64) {
	if seq == 0 || seq%CheckpointInterval != 0 {
		return
	}
	if bn.stableCheckpoint != nil && seq <= bn.stableCheckpoint.SeqNum {
		return
	}

	dig, ok := bn.localCheckpointDigest(seq)
	if !ok {
		return
	}

	cpMsg, err := bn.ConstructCheckpoint(seq, dig)
	if err != nil {
		return
	}

	cpEvidence, err := bn.signEvidence(cpMsg)
	if err != nil {
		return
	}

	bn.recordCheckpoint(seq, dig, bn.selfID, cpEvidence)
	bn.broadcast(cpMsg)

	if uint64(len(bn.checkpoints[seq][dig])) >= 2*bn.f+1 {
		bn.stabilizeCheckpoint(seq, dig)
	}
}

func (bn *BFTNode) stabilizeCheckpoint(seq uint64, dig [32]byte) {
	localDig, ok := bn.localCheckpointDigest(seq)
	if !ok || localDig != dig {
		return
	}
	if bn.stableCheckpoint != nil && seq <= bn.stableCheckpoint.SeqNum {
		return
	}

	checkpoints := make([]pb.Message, 0, len(bn.checkpoints[seq][dig]))
	for _, msg := range bn.checkpoints[seq][dig] {
		if msg != nil {
			checkpoints = append(checkpoints, *msg)
		}
	}

	bn.stableCheckpoint = &StableCheckpoint{
		SeqNum: seq,
		Digest: dig,
		Proof: BFTCheckpointProof{
			SeqNum:      seq,
			Digest:      dig,
			Checkpoints: checkpoints,
		},
	}

	bn.lowW = seq
	bn.highW = seq + WatermarkWindow
	bn.garbageCollect(seq)
}

// StableCheckpoint returns a copy of the latest stable checkpoint certificate,
// including 2f+1 proofs usable for view-change / state transfer to lagging replicas.
func (bn *BFTNode) StableCheckpoint() *StableCheckpoint {
	bn.mu.Lock()
	defer bn.mu.Unlock()

	if bn.stableCheckpoint == nil {
		return nil
	}

	sc := *bn.stableCheckpoint
	sc.Proof.Checkpoints = append([]pb.Message(nil), bn.stableCheckpoint.Proof.Checkpoints...)
	return &sc
}

// garbageCollect discards request state at or below a stable checkpoint sequence.
func (bn *BFTNode) garbageCollect(seq uint64) {
	for key := range bn.pp {
		if key.seq <= seq {
			delete(bn.pp, key)
			delete(bn.prepares, key)
			delete(bn.commits, key)
			delete(bn.reqs, key)
		}
	}
	for cpSeq := range bn.checkpoints {
		if cpSeq < seq {
			delete(bn.checkpoints, cpSeq)
		}
	}
}

func (bn *BFTNode) broadcast(m *pb.Message) {
	for id := uint64(1); id <= bn.n; id++ {
		if id == bn.selfID {
			continue
		}
		mCopy := proto.Clone(m).(*pb.Message)
		mCopy.To = u64p(id)
		bn.bftMsgs = append(bn.bftMsgs, mCopy)
	}
}

func (bn *BFTNode) isInternalMessage(m *pb.Message) bool {
	return IsLocalMsg(m.GetType()) || IsLocalMsgTarget(m.GetTo()) || IsLocalMsgTarget(m.GetFrom())
}

func (bn *BFTNode) isClientRequest(m *pb.Message) bool {
	if m == nil || m.GetType() != pb.MsgProp {
		return false
	}
	_, ok := bn.clientIDs[m.GetFrom()]
	return ok
}

// ====================================================================
// BFT Client Implementation
// ====================================================================

type pendingRequest struct {
	msg       *pb.Message
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
	readyc     chan *pb.Message
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
		readyc:      make(chan *pb.Message, 100),
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
				mCopy := proto.Clone(req.msg).(*pb.Message)
				mCopy.To = u64p(id)

				origCtx := normalizeContext(mCopy.Context)
				dataSign, _ := messageSignBytes(mCopy, origCtx, ts)
				sig := ed25519.Sign(c.priv, dataSign)
				mCopy.Context = packSignature(sig, ts, origCtx)

				c.readyc <- mCopy
			}
			req.ticks = 0
		}
		c.pending[ts] = req
	}
}

func (c *BFTClient) Ready() <-chan *pb.Message { return c.readyc }

func (c *BFTClient) Propose(ctx context.Context, data []byte) error {
	c.mu.Lock()
	ts := c.cfg.now().UnixNano()
	if ts <= c.lastSent {
		ts = c.lastSent + 1
	}
	c.lastSent = ts
	c.mu.Unlock()

	baseMsg := &pb.Message{
		Type:    pb.MsgProp.Enum(),
		From:    u64p(c.selfID),
		Entries: []*pb.Entry{{Data: data}},
	}

	c.mu.Lock()
	c.pending[ts] = &pendingRequest{msg: baseMsg, timestamp: ts, ticks: 0}
	c.mu.Unlock()

	for id := uint64(1); id <= c.n; id++ {
		mCopy := proto.Clone(baseMsg).(*pb.Message)
		mCopy.To = u64p(id)

		origCtx := normalizeContext(mCopy.Context)
		dataSign, err := messageSignBytes(mCopy, origCtx, ts)
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

	if err := c.verifyMessage(m); err != nil {
		return err
	}

	bctx, err := decodeBFTContext(m.Context)
	if err != nil || bctx.Phase != PhaseReply {
		return errors.New("invalid reply message")
	}

	reqTS := bctx.RequestTimestamp
	if reqTS == 0 {
		return ErrInvalidBFTContext
	}
	if bctx.ClientID != c.selfID {
		return ErrInvalidBFTContext
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if _, exists := c.pending[reqTS]; !exists {
		return nil
	}

	if c.replies[reqTS] == nil {
		c.replies[reqTS] = make(map[uint64][]byte)
	}
	c.replies[reqTS][m.GetFrom()] = append([]byte(nil), bctx.Result...)

	resultCounts := make(map[string]uint64)
	for _, res := range c.replies[reqTS] {
		resultCounts[string(res)]++

		if resultCounts[string(res)] == c.f+1 && bctx.ClientID == c.selfID && bctx.RequestTimestamp == reqTS && len(bctx.Result) > 0 {
			delete(c.pending, reqTS)
			delete(c.replies, reqTS)

			select {
			case c.ConsensusC <- res:
			default:
			}
			return nil
		}
	}

	return nil
}

func (c *BFTClient) AddClientProof(m *pb.Message) (int64, error) {
	m.From = u64p(c.selfID)
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

func (bn *BFTNode) validateBFTMessage(signedMsg *pb.Message, bctx BFTContext) error {
	if signedMsg.GetType() != pb.MsgApp {
		return ErrInvalidBFTMessage
	}

	switch bctx.Phase {
	case PhasePrePrepare:
		return bn.validatePrePrepareMessage(signedMsg, bctx)

	case PhasePrepare:
		return bn.validatePrepareMessage(signedMsg, bctx)

	case PhaseCommit:
		return bn.validateCommitMessage(signedMsg, bctx)

	case PhaseCheckpoint:
		return bn.validateCheckpointMessage(signedMsg, bctx)

	case PhaseViewChange:
		return bn.validateIncomingViewChangeMessage(signedMsg, bctx, bctx.View)

	case PhaseNewView:
		return bn.validateNewViewMessage(signedMsg, bctx)

	case PhaseReply:
		return bn.validateReplyMessage(signedMsg, bctx)

	default:
		return ErrInvalidBFTContext
	}
}

func (c *BFTClient) verifyMessage(m *pb.Message) error {
	pubKey, ok := c.nodePubKeys[m.GetFrom()]
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

func (bn *BFTNode) ConstructReply(key bftSeqKey, result []byte) (*pb.Message, error) {
	clientID := bn.requestClient[key]
	requestTS := bn.requestTS[key]

	if clientID == 0 || requestTS == 0 {
		return nil, ErrInvalidBFTContext
	}

	bctx := BFTContext{
		Phase:            PhaseReply,
		View:             bn.view,
		RequestTimestamp: requestTS,
		ClientID:         clientID,
		Result:           append([]byte(nil), result...),
	}

	encCtx, err := encodeBFTContext(bctx)
	if err != nil {
		return nil, err
	}

	return &pb.Message{
		Type:    pb.MsgApp.Enum(),
		From:    u64p(bn.selfID),
		To:      u64p(clientID),
		Context: encCtx,
	}, nil
}
