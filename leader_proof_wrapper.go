package raft

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"

	"github.com/golang/protobuf/proto"

	pb "go.etcd.io/raft/v3/raftpb"
)

const (
	leaderProofMagic    = "raftlead1"
	leaderProofOverhead = len(leaderProofMagic) + 4 + 2 // magic + orig ctx len + proof count
)

var (
	// ErrInvalidLeaderProof is returned when a leader proof envelope is malformed.
	ErrInvalidLeaderProof = errors.New("raft: invalid leader proof")
	// ErrInsufficientLeaderProof is returned when fewer than quorum unique attestations verify.
	ErrInsufficientLeaderProof = errors.New("raft: insufficient leader proof")
)

// AddLeaderProof adds a quorum proof to a leader-originated message by embedding
// a set of recently verified follower attestations in the message context.
func (sn *SignNode) AddLeaderProof(m *pb.Message) error {
	q := sn.cfg.leaderProofQuorum()
	if q <= 0 {
		return nil
	}
	proofs := sn.collectLeaderAttestations(m.GetTerm())
	if len(proofs) < q {
		return ErrInsufficientLeaderProof
	}
	m.Context = packLeaderProof(m.Context, proofs)
	return nil
}

// VerifyLeader validates the quorum proof attached to a leader-originated
// message and restores the original message context.
func (sn *SignNode) VerifyLeader(m *pb.Message) error {
	q := sn.cfg.leaderProofQuorum()
	if q <= 0 {
		return nil
	}
	origCtx, proofs, err := parseLeaderProof(m.Context)
	if err != nil {
		return err
	}
	if len(proofs) < q {
		return ErrInsufficientLeaderProof
	}

	now := sn.cfg.now().UnixNano()
	maxAge := sn.cfg.maxAge().Nanoseconds()
	seen := make(map[uint64]struct{}, len(proofs))
	// Double-check that proofs are valid, fresh, and from unique peers before trusting the original context.
	for i := range proofs {
		p := proofs[i]
		if !isLeaderAttestationMessage(p, m.GetFrom()) {
			continue
		}
		if p.GetTerm() != m.GetTerm() {
			continue
		}
		if _, dup := seen[p.GetFrom()]; dup {
			continue
		}
		sig, ts, proofCtx, err := parseSignature(p.Context)
		if err != nil {
			continue
		}
		if !timestampWithinAge(now, ts, maxAge) {
			continue
		}
		pub, ok := sn.attestationPubKey(p.GetFrom())
		if !ok {
			continue
		}
		data, err := messageSignBytes(p, proofCtx, ts)
		if err != nil {
			continue
		}
		if !ed25519.Verify(pub, data, sig) {
			continue
		}
		seen[p.GetFrom()] = struct{}{}
		if len(seen) >= q {
			m.Context = origCtx
			return nil
		}
	}
	return ErrInsufficientLeaderProof
}

func shouldAttachLeaderProof(m *pb.Message, selfID uint64, peerPubKeys map[uint64]ed25519.PublicKey, clientIDs map[uint64]struct{}, clientPub ed25519.PublicKey, q int) bool {
	if q <= 0 || m.GetFrom() != selfID || isInternalMessage(m) || IsResponseMsg(m.GetType()) {
		return false
	}
	return isPeerOrClient(m.GetTo(), selfID, peerPubKeys, clientIDs, clientPub)
}

func shouldVerifyLeaderProof(m *pb.Message, selfID uint64, peerPubKeys map[uint64]ed25519.PublicKey, q int) bool {
	if q <= 0 || isInternalMessage(m) || IsResponseMsg(m.GetType()) {
		return false
	}
	if m.GetFrom() == 0 || m.GetFrom() == selfID {
		return false
	}
	_, ok := peerPubKeys[m.GetFrom()]
	return ok
}

func shouldRecordLeaderAttestation(m *pb.Message, selfID uint64, peerPubKeys map[uint64]ed25519.PublicKey) bool {
	_, ok := peerPubKeys[m.GetFrom()]
	if !ok {
		return false
	}
	return isLeaderAttestationMessage(m, selfID)
}

func isLeaderAttestationMessage(m *pb.Message, expectedLeader uint64) bool {
	if m.GetTo() != expectedLeader || m.GetFrom() == 0 || m.GetFrom() == expectedLeader {
		return false
	}
	return m.GetType() == pb.MsgHeartbeatResp || m.GetType() == pb.MsgAppResp
}

func (sn *SignNode) recordLeaderAttestation(m *pb.Message, ts int64) {
	sn.mu.Lock()
	defer sn.mu.Unlock()
	if cur, ok := sn.leaderSeen[m.GetFrom()]; ok {
		_, curTS, _, err := parseSignature(cur.Context)
		if err == nil && ts <= curTS {
			return
		}
	}
	sn.leaderSeen[m.GetFrom()] = proto.Clone(m).(*pb.Message)
}

func (sn *SignNode) collectLeaderAttestations(term uint64) []*pb.Message {
	now := sn.cfg.now().UnixNano()
	maxAge := sn.cfg.maxAge().Nanoseconds()

	sn.mu.Lock()
	defer sn.mu.Unlock()

	out := make([]*pb.Message, 0, len(sn.leaderSeen))
	for _, m := range sn.leaderSeen {
		if m.GetTerm() != term {
			continue
		}
		_, ts, _, err := parseSignature(m.Context)
		if err != nil || !timestampWithinAge(now, ts, maxAge) {
			continue
		}
		out = append(out, proto.Clone(m).(*pb.Message))
	}
	return out
}

func packLeaderProof(origCtx []byte, proofs []*pb.Message) []byte {
	origCtx = normalizeContext(origCtx)
	encoded := make([][]byte, len(proofs))
	total := leaderProofOverhead + len(origCtx)
	for i := range proofs {
		b, err := proto.Marshal(proofs[i])
		if err != nil {
			panic(err)
		}
		encoded[i] = b
		total += 4 + len(b)
	}
	out := make([]byte, total)
	copy(out, leaderProofMagic)
	binary.BigEndian.PutUint32(out[len(leaderProofMagic):], uint32(len(origCtx)))
	binary.BigEndian.PutUint16(out[len(leaderProofMagic)+4:], uint16(len(encoded)))
	pos := leaderProofOverhead
	copy(out[pos:], origCtx)
	pos += len(origCtx)
	for _, b := range encoded {
		binary.BigEndian.PutUint32(out[pos:], uint32(len(b)))
		pos += 4
		copy(out[pos:], b)
		pos += len(b)
	}
	return out
}

func parseLeaderProof(ctx []byte) (origCtx []byte, proofs []*pb.Message, err error) {
	if len(ctx) < leaderProofOverhead {
		return nil, nil, ErrInvalidLeaderProof
	}
	if string(ctx[:len(leaderProofMagic)]) != leaderProofMagic {
		return nil, nil, ErrInvalidLeaderProof
	}
	origLen := int(binary.BigEndian.Uint32(ctx[len(leaderProofMagic):]))
	count := int(binary.BigEndian.Uint16(ctx[len(leaderProofMagic)+4:]))
	pos := leaderProofOverhead
	if origLen < 0 || pos+origLen > len(ctx) {
		return nil, nil, ErrInvalidLeaderProof
	}
	origCtx = normalizeContext(ctx[pos : pos+origLen])
	pos += origLen
	proofs = make([]*pb.Message, 0, count)
	for i := 0; i < count; i++ {
		if pos+4 > len(ctx) {
			return nil, nil, ErrInvalidLeaderProof
		}
		n := int(binary.BigEndian.Uint32(ctx[pos:]))
		pos += 4
		if n < 0 || pos+n > len(ctx) {
			return nil, nil, ErrInvalidLeaderProof
		}
		var m pb.Message
		if err := proto.Unmarshal(ctx[pos:pos+n], &m); err != nil {
			return nil, nil, ErrInvalidLeaderProof
		}
		proofs = append(proofs, &m)
		pos += n
	}
	if pos != len(ctx) {
		return nil, nil, ErrInvalidLeaderProof
	}
	return origCtx, proofs, nil
}

func timestampWithinAge(now, ts, maxAge int64) bool {
	age := now - ts
	if age < 0 {
		age = -age
	}
	return age <= maxAge
}

func (sn *SignNode) attestationPubKey(id uint64) (ed25519.PublicKey, bool) {
	if pub, ok := sn.peerPubKeys[id]; ok {
		return pub, true
	}
	if id == sn.selfID && len(sn.priv) == ed25519.PrivateKeySize {
		pub, ok := sn.priv.Public().(ed25519.PublicKey)
		if ok {
			return pub, true
		}
	}
	return nil, false
}
