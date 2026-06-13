package raft

import (
	"crypto/ed25519"
	"errors"

	pb "go.etcd.io/raft/v3/raftpb"
	"google.golang.org/protobuf/proto"
)

func countMessagesAfterAndMinKey(
	msgs map[uint64]map[uint64]*pb.Message,
	minFirstKey uint64,
) (count int, minKey uint64, ok bool) {
	for firstKey, inner := range msgs {
		if firstKey <= minFirstKey {
			continue
		}

		localCount := 0
		for _, msg := range inner {
			if msg != nil {
				localCount++
			}
		}
		if localCount == 0 {
			continue
		}

		count += localCount
		if !ok || firstKey < minKey {
			minKey = firstKey
			ok = true
		}
	}

	return count, minKey, ok
}

func MapValues[K comparable, V any](m map[K]*V) []V {
	values := make([]V, 0, len(m))
	for _, v := range m {
		values = append(values, *v)
	}
	return values
}

func (bn *BFTNode) installNewView(bctx BFTContext) error {
	if bctx.Phase != PhaseNewView {
		return ErrInvalidNewView
	}
	if bctx.View < bn.view {
		return ErrInvalidNewView
	}
	if bctx.View == bn.view && bn.nodePhase == Normal {
		return nil
	}

	bn.view = bctx.View
	bn.nodePhase = Normal
	bn.campaign_view = 0
	bn.vc_timer.StopAndResetBackoff()
	bn.timer.Stop()
	bn.pending = bn.pending[:0]

	maxSeq := bn.lowW

	for i := range bctx.PrePrepareSet {
		pp := &bctx.PrePrepareSet[i]

		ppCtx, err := decodeMessageBFTContext(pp, bn.nodePubKeys[bn.primaryForView(bctx.View)])
		if err != nil {
			return err
		}
		if err := bn.validatePrePrepareShape(pp, ppCtx); err != nil {
			return err
		}
		if ppCtx.View != bctx.View {
			return ErrInvalidNewView
		}
		if ppCtx.SeqNum <= bn.lowW || ppCtx.SeqNum > bn.highW {
			return ErrInvalidNewView
		}
		if ppCtx.SeqNum > maxSeq {
			maxSeq = ppCtx.SeqNum
		}

		key := bftSeqKey{view: ppCtx.View, seq: ppCtx.SeqNum}

		if existing, ok := bn.pp[key]; ok && existing != ppCtx.Digest {
			return ErrInvalidNewView
		}

		bn.pp[key] = ppCtx.Digest
		bn.reqs[key] = proto.Clone(pp).(*pb.Message)

		pMsg, err := bn.ConstructP(ppCtx)
		if err != nil {
			return err
		}

		pEvidence, err := bn.signEvidence(pMsg)
		if err != nil {
			return err
		}

		if bn.prepares[key] == nil {
			bn.prepares[key] = make(map[uint64]*pb.Message)
		}

		bn.prepares[key][bn.primaryForView(bctx.View)] = proto.Clone(pp).(*pb.Message)
		bn.prepares[key][bn.selfID] = pEvidence

		bn.broadcast(pMsg)
	}

	if bn.nextSeqN <= maxSeq {
		bn.nextSeqN = maxSeq + 1
	}

	return nil
}

func (bn *BFTNode) primaryForView(view uint64) uint64 {
	return (view % bn.n) + 1
}

func (bn *BFTNode) isPrimaryForView(view uint64) bool {
	return bn.primaryForView(view) == bn.selfID
}

func (bn *BFTNode) signEvidence(m *pb.Message) (*pb.Message, error) {
	cp := proto.Clone(m).(*pb.Message)
	cp.To = nil // canonical certificate form; do not mutate after signing

	ts := bn.cfg.now().UnixNano()
	origCtx := normalizeContext(cp.Context)
	data, err := messageSignBytes(cp, origCtx, ts)
	if err != nil {
		return nil, err
	}

	cp.Context = packSignature(ed25519.Sign(bn.priv, data), ts, origCtx)
	return cp, nil
}

func (bn *BFTNode) acceptedDigestMatches(key bftSeqKey, digest [32]byte) bool {
	accepted, ok := bn.pp[key]
	return ok && accepted == digest
}

func (bn *BFTNode) validateEmbeddedClientRequest(pp *pb.Message, bctx BFTContext) error {
	req := &bctx.ClientRequest

	if req.GetType() != pb.MsgProp {
		return ErrInvalidBFTMessage
	}
	if req.GetFrom() != bctx.ClientID {
		return ErrInvalidBFTContext
	}
	if _, ok := bn.clientIDs[req.GetFrom()]; !ok {
		return ErrUnknownSigner
	}

	ts, origCtx, err := VerifyBFTMessageSignature(req, bn.clientPub)
	if err != nil {
		return err
	}
	if ts != bctx.RequestTimestamp {
		return ErrInvalidBFTContext
	}
	if len(origCtx) != 0 {
		return ErrInvalidBFTContext
	}

	reqDigest, err := hashEntryBatch(req.GetEntries())
	if err != nil {
		return err
	}
	if reqDigest != bctx.Digest {
		return errors.New("raft: embedded client request digest mismatch")
	}

	ppDigest, err := hashEntryBatch(pp.GetEntries())
	if err != nil {
		return err
	}
	if ppDigest != reqDigest {
		return errors.New("raft: pre-prepare entries do not match client request")
	}

	return nil
}

func (bn *BFTNode) validatePrePrepareShape(m *pb.Message, bctx BFTContext) error {
	if bctx.Phase != PhasePrePrepare {
		return ErrInvalidBFTContext
	}
	if bctx.SeqNum == 0 || zeroDigest(bctx.Digest) {
		return ErrInvalidBFTContext
	}
	if bctx.RequestTimestamp == 0 || bctx.ClientID == 0 {
		return ErrInvalidBFTContext
	}
	if len(m.GetEntries()) == 0 {
		return ErrInvalidBFTMessage
	}

	digest, err := hashEntryBatch(m.GetEntries())
	if err != nil {
		return err
	}
	if digest != bctx.Digest {
		return errors.New("raft: pre-prepare digest mismatch")
	}

	if err := bn.validateEmbeddedClientRequest(m, bctx); err != nil {
		return err
	}

	return nil
}

func (bn *BFTNode) validatePrePrepareMessage(m *pb.Message, bctx BFTContext) error {
	if bctx.View != bn.view {
		return errors.New("raft: pre-prepare view mismatch")
	}
	if m.GetFrom() != bn.primaryForView(bctx.View) {
		return errors.New("raft: pre-prepare from non-primary")
	}
	if bctx.SeqNum <= bn.lowW || bctx.SeqNum > bn.highW {
		return errors.New("raft: pre-prepare sequence outside watermarks")
	}
	return bn.validatePrePrepareShape(m, bctx)
}

func (bn *BFTNode) validatePrepareMessage(m *pb.Message, bctx BFTContext) error {
	if bctx.SeqNum == 0 {
		return ErrInvalidBFTContext
	}
	if zeroDigest(bctx.Digest) {
		return ErrInvalidBFTContext
	}
	if len(m.GetEntries()) != 0 {
		return ErrInvalidBFTMessage
	}
	return nil
}

func (bn *BFTNode) validateCommitMessage(m *pb.Message, bctx BFTContext) error {
	if bctx.SeqNum == 0 {
		return ErrInvalidBFTContext
	}
	if zeroDigest(bctx.Digest) {
		return ErrInvalidBFTContext
	}
	if len(m.GetEntries()) != 0 {
		return ErrInvalidBFTMessage
	}
	return nil
}

func (bn *BFTNode) validateCheckpointMessage(m *pb.Message, bctx BFTContext) error {
	if len(m.GetEntries()) != 0 {
		return ErrInvalidCheckpoint
	}
	if bctx.CheckpointSeqNum == 0 {
		return ErrInvalidCheckpoint
	}
	if bctx.SeqNum != bctx.CheckpointSeqNum {
		return ErrInvalidCheckpoint
	}
	if bctx.Digest != bctx.CheckpointDigest {
		return ErrInvalidCheckpoint
	}
	if zeroDigest(bctx.CheckpointDigest) {
		return ErrInvalidCheckpoint
	}
	return nil
}

func (bn *BFTNode) validateIncomingViewChangeMessage(
	m *pb.Message,
	bctx BFTContext,
	expectedView uint64,
) error {
	if bctx.View <= bn.view {
		return ErrInvalidViewChange
	}
	return bn.validateViewChangeCertificate(m, bctx, expectedView)
}

func containsSeq(xs []uint64, seq uint64) bool {
	for _, x := range xs {
		if x == seq {
			return true
		}
	}
	return false
}

func (bn *BFTNode) validateViewChangeCertificate(
	m *pb.Message,
	bctx BFTContext,
	expectedView uint64,
) error {
	if bctx.Phase != PhaseViewChange {
		return ErrInvalidViewChange
	}
	if bctx.View != expectedView {
		return ErrInvalidViewChange
	}
	if bctx.SeqNum != bctx.CheckpointSeqNum {
		return ErrInvalidViewChange
	}

	if bctx.CheckpointSeqNum != bctx.CheckpointProofs.SeqNum {
		return ErrInvalidViewChange
	}
	if bctx.CheckpointDigest != bctx.CheckpointProofs.Digest {
		if bctx.CheckpointSeqNum != 0 {
			return ErrInvalidViewChange
		}
	}

	if err := bn.validateCheckpointCertificate(bctx.CheckpointProofs); err != nil {
		return err
	}

	for _, proof := range bctx.PreparedProofs {
		if err := bn.validatePreparedProof(proof, bctx.View, bctx.CheckpointSeqNum); err != nil {
			return err
		}
	}

	return nil
}

func (bn *BFTNode) validateCheckpointCertificate(proof BFTCheckpointProof) error {
	// Initial checkpoint n=0 is valid with an empty proof.
	if proof.SeqNum == 0 {
		if !zeroDigest(proof.Digest) {
			return ErrInvalidCheckpointCert
		}
		if len(proof.Checkpoints) != 0 {
			return ErrInvalidCheckpointCert
		}
		return nil
	}

	if zeroDigest(proof.Digest) {
		return ErrInvalidCheckpointCert
	}
	if uint64(len(proof.Checkpoints)) < 2*bn.f+1 {
		return ErrInvalidCheckpointCert
	}

	seen := make(map[uint64]struct{})

	for i := range proof.Checkpoints {
		msg := &proof.Checkpoints[i]
		from := msg.GetFrom()

		if _, dup := seen[from]; dup {
			return ErrInvalidCheckpointCert
		}
		seen[from] = struct{}{}

		pub, ok := bn.nodePubKeys[from]
		if !ok {
			return ErrInvalidCheckpointCert
		}

		_, origCtx, err := VerifyBFTMessageSignature(msg, pub)
		if err != nil {
			return ErrInvalidCheckpointCert
		}

		bctx, err := decodeBFTContext(origCtx)
		if err != nil {
			return ErrInvalidCheckpointCert
		}

		if bctx.Phase != PhaseCheckpoint {
			return ErrInvalidCheckpointCert
		}
		if bctx.CheckpointSeqNum != proof.SeqNum {
			return ErrInvalidCheckpointCert
		}
		if bctx.SeqNum != proof.SeqNum {
			return ErrInvalidCheckpointCert
		}
		if bctx.CheckpointDigest != proof.Digest {
			return ErrInvalidCheckpointCert
		}
		if bctx.Digest != proof.Digest {
			return ErrInvalidCheckpointCert
		}
		if len(msg.GetEntries()) != 0 {
			return ErrInvalidCheckpointCert
		}
	}

	return nil
}

func (bn *BFTNode) validatePreparedProof(
	proof BFTPreparedProof,
	newView uint64,
	checkpointSeq uint64,
) error {
	if proof.SeqNum <= checkpointSeq {
		return ErrInvalidPreparedProof
	}
	if proof.View >= newView {
		return ErrInvalidPreparedProof
	}
	if proof.SeqNum == 0 {
		return ErrInvalidPreparedProof
	}
	if zeroDigest(proof.Digest) {
		return ErrInvalidPreparedProof
	}
	if uint64(len(proof.Prepares)) < 2*bn.f {
		return ErrInvalidPreparedProof
	}

	seen := make(map[uint64]struct{})
	hasPrePrepare := false

	for i := range proof.Prepares {
		msg := &proof.Prepares[i]
		from := msg.GetFrom()

		if _, dup := seen[from]; dup {
			return ErrInvalidPreparedProof
		}
		seen[from] = struct{}{}

		pub, ok := bn.nodePubKeys[from]
		if !ok {
			return ErrInvalidPreparedProof
		}

		_, origCtx, err := VerifyBFTMessageSignature(msg, pub)
		if err != nil {
			return ErrInvalidPreparedProof
		}

		msgCtx, err := decodeBFTContext(origCtx)
		if err != nil {
			return ErrInvalidPreparedProof
		}

		if msgCtx.View != proof.View ||
			msgCtx.SeqNum != proof.SeqNum ||
			msgCtx.Digest != proof.Digest {
			return ErrInvalidPreparedProof
		}

		switch msgCtx.Phase {
		case PhasePrePrepare:
			hasPrePrepare = true

			if len(msg.GetEntries()) == 0 {
				return ErrInvalidPreparedProof
			}

			digest, err := hashEntryBatch(msg.GetEntries())
			if err != nil || digest != proof.Digest {
				return ErrInvalidPreparedProof
			}

			if err := bn.validateEmbeddedClientRequest(msg, msgCtx); err != nil {
				return ErrInvalidPreparedProof
			}

		case PhasePrepare:
			if len(msg.GetEntries()) != 0 {
				return ErrInvalidPreparedProof
			}

		default:
			return ErrInvalidPreparedProof
		}
	}

	if !hasPrePrepare {
		return ErrInvalidPreparedProof
	}

	return nil
}

func (bn *BFTNode) validateNewViewMessage(m *pb.Message, bctx BFTContext) error {
	if bctx.Phase != PhaseNewView {
		return ErrInvalidNewView
	}
	if bctx.View < bn.view {
		return ErrInvalidNewView
	}
	if m.GetFrom() != bn.primaryForView(bctx.View) {
		return ErrInvalidNewView
	}
	if uint64(len(bctx.ViewSet)) < 2*bn.f+1 {
		return ErrInvalidNewView
	}

	vcs := make(map[uint64]*pb.Message)

	for i := range bctx.ViewSet {
		vc := &bctx.ViewSet[i]
		from := vc.GetFrom()

		if _, dup := vcs[from]; dup {
			return ErrInvalidNewView
		}

		pub, ok := bn.nodePubKeys[from]
		if !ok {
			return ErrInvalidNewView
		}

		_, origCtx, err := VerifyBFTMessageSignature(vc, pub)
		if err != nil {
			return ErrInvalidNewView
		}

		vcCtx, err := decodeBFTContext(origCtx)
		if err != nil {
			return ErrInvalidNewView
		}

		if err := bn.validateViewChangeCertificate(vc, vcCtx, bctx.View); err != nil {
			return ErrInvalidNewView
		}

		vcs[from] = proto.Clone(vc).(*pb.Message)
	}

	if uint64(len(vcs)) < 2*bn.f+1 {
		return ErrInvalidNewView
	}

	expectedO, err := bn.computeNewViewPrePrepareSet(bctx.View, vcs)
	if err != nil {
		return ErrInvalidNewView
	}

	if !bn.samePrePrepareMessageSet(expectedO, bctx.PrePrepareSet) {
		return ErrInvalidNewView
	}

	return nil
}

func extractPreparedPrePrepare(proof BFTPreparedProof) ([]*pb.Entry, int64, uint64, pb.Message, bool) {
	for i := range proof.Prepares {
		msg := &proof.Prepares[i]

		_, _, origCtx, err := parseSignature(msg.Context)
		if err != nil {
			continue
		}

		bctx, err := decodeBFTContext(origCtx)
		if err != nil {
			continue
		}

		if bctx.Phase != PhasePrePrepare {
			continue
		}
		if bctx.View != proof.View ||
			bctx.SeqNum != proof.SeqNum ||
			bctx.Digest != proof.Digest {
			continue
		}

		return cloneEntries(msg.GetEntries()),
			bctx.RequestTimestamp,
			bctx.ClientID,
			*proto.Clone(&bctx.ClientRequest).(*pb.Message),
			true
	}

	return nil, 0, 0, pb.Message{}, false
}

func (bn *BFTNode) samePrePrepareMessageSet(a, b []pb.Message) bool {
	if len(a) != len(b) {
		return false
	}

	type k struct {
		view             uint64
		seq              uint64
		digest           [32]byte
		requestTimestamp int64
		clientID         uint64
	}

	toMap := func(in []pb.Message) (map[k]struct{}, bool) {
		out := make(map[k]struct{}, len(in))

		for i := range in {
			msg := &in[i]

			var bctx BFTContext
			var err error
			if pub, ok := bn.nodePubKeys[msg.GetFrom()]; ok {
				_, origCtx, verifyErr := VerifyBFTMessageSignature(msg, pub)
				if verifyErr == nil {
					bctx, err = decodeBFTContext(origCtx)
				} else {
					bctx, err = decodeBFTContext(msg.Context)
				}
			} else {
				bctx, err = decodeBFTContext(msg.Context)
			}
			if err != nil {
				return nil, false
			}
			if bctx.Phase != PhasePrePrepare {
				return nil, false
			}
			if bctx.SeqNum == 0 || zeroDigest(bctx.Digest) {
				return nil, false
			}

			if msg.GetFrom() != 0 && msg.GetFrom() != bn.primaryForView(bctx.View) {
				return nil, false
			}

			digest, err := hashEntryBatch(msg.GetEntries())
			if err != nil || digest != bctx.Digest {
				return nil, false
			}

			key := k{
				view:             bctx.View,
				seq:              bctx.SeqNum,
				digest:           bctx.Digest,
				requestTimestamp: bctx.RequestTimestamp,
				clientID:         bctx.ClientID,
			}
			if _, dup := out[key]; dup {
				return nil, false
			}
			out[key] = struct{}{}
		}

		return out, true
	}

	am, ok := toMap(a)
	if !ok {
		return false
	}

	bm, ok := toMap(b)
	if !ok {
		return false
	}

	if len(am) != len(bm) {
		return false
	}

	for key := range am {
		if _, ok := bm[key]; !ok {
			return false
		}
	}

	return true
}

func (bn *BFTNode) validateReplyMessage(m *pb.Message, bctx BFTContext) error {
	if bctx.ClientID == 0 {
		return ErrInvalidBFTContext
	}
	if bctx.RequestTimestamp == 0 {
		return ErrInvalidBFTContext
	}
	if len(bctx.Result) == 0 {
		return ErrInvalidBFTContext
	}
	if len(m.GetEntries()) != 0 {
		return ErrInvalidBFTMessage
	}
	return nil
}

func (bn *BFTNode) isLeader() bool {
	return bn.isPrimaryForView(bn.view)
}

func decodeMessageBFTContext(m *pb.Message, pub ed25519.PublicKey) (BFTContext, error) {
	_, origCtx, err := VerifyBFTMessageSignature(m, pub)
	if err == nil {
		return decodeBFTContext(origCtx)
	}

	// Allow unsigned internal/test messages when explicitly used before signing.
	return decodeBFTContext(m.Context)
}
