// via cursor

package raft

import (
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"sync"
	"time"

	"github.com/golang/protobuf/proto"

	pb "go.etcd.io/raft/v3/raftpb"
)

const (
	sigMagic    = "raftsig2"
	sigOverhead = len(sigMagic) + 8 + ed25519.SignatureSize + 4 // magic + unix ns + sig + ctx len
)

// DefaultMaxMessageAge is the maximum age of a signed message accepted on verify.
const DefaultMaxMessageAge = 30 * time.Second

var (
	// ErrInvalidSignature is returned when a message signature does not verify.
	ErrInvalidSignature = errors.New("raft: invalid message signature")
	// ErrUnknownSigner is returned when the sender has no registered public key.
	ErrUnknownSigner = errors.New("raft: unknown signer")
	// ErrStaleMessage is returned when a message timestamp is too old or repeats a prior one.
	ErrStaleMessage = errors.New("raft: stale message")
)

// SignConfig configures freshness checks for signed messages.
type SignConfig struct {
	// MaxAge is the maximum allowed age of a message timestamp. Defaults to DefaultMaxMessageAge.
	MaxAge time.Duration
	// Now returns the current time. Defaults to time.Now.
	Now func() time.Time
	// LeaderProofQuorum enables leader proof attach/verify when > 0.
	LeaderProofQuorum int
}

func (c *SignConfig) maxAge() time.Duration {
	if c == nil || c.MaxAge <= 0 {
		return DefaultMaxMessageAge
	}
	return c.MaxAge
}

func (c *SignConfig) now() time.Time {
	if c == nil || c.Now == nil {
		return time.Now()
	}
	return c.Now()
}

func (c *SignConfig) leaderProofQuorum() int {
	if c == nil || c.LeaderProofQuorum <= 0 {
		return 0
	}
	return c.LeaderProofQuorum
}

// SignNode wraps a Node and signs outbound raft messages destined for other
// raft peers or client nodes. Incoming messages from those nodes are verified
// before being passed to the inner node. Internal/local messages (MsgHup,
// storage threads, etc.) are left unsigned.
type SignNode struct {
	Node
	selfID      uint64
	priv        ed25519.PrivateKey
	peerPubKeys map[uint64]ed25519.PublicKey
	clientIDs   map[uint64]struct{}
	clientPub   ed25519.PublicKey
	cfg         SignConfig

	mu        sync.Mutex
	lastSeen  map[uint64]int64 // sender ID -> last accepted unix nanos
	localSent int64            // last timestamp used when signing outbound messages
	leaderSeen map[uint64]*pb.Message

	readyc chan Ready
	done   chan struct{}
}

// WrapNode returns a Node that signs messages sent to peers and client nodes
// and verifies messages received from them. peerPubKeys maps raft peer IDs to
// public keys. clientIDs lists client node IDs that share clientPub; pass nil
// clientIDs or a nil clientPub to disable client signing. cfg may be nil.
func WrapNode(
	n Node,
	selfID uint64,
	priv ed25519.PrivateKey,
	peerPubKeys map[uint64]ed25519.PublicKey,
	clientIDs []uint64,
	clientPub ed25519.PublicKey,
	cfg *SignConfig,
) *SignNode {
	var c SignConfig
	if cfg != nil {
		c = *cfg
	}
	sn := &SignNode{
		Node:        n,
		selfID:      selfID,
		priv:        priv,
		peerPubKeys: peerPubKeys,
		clientIDs:   clientIDSet(clientIDs),
		clientPub:   clientPub,
		cfg:         c,
		lastSeen:    make(map[uint64]int64),
		leaderSeen:  make(map[uint64]*pb.Message),
		readyc:      make(chan Ready),
		done:        make(chan struct{}),
	}
	go sn.forwardReady()
	return sn
}

func (sn *SignNode) forwardReady() {
	for {
		select {
		case <-sn.done:
			return
		case rd := <-sn.Node.Ready():
			rd.Messages = sn.signMessages(rd.Messages)
			select {
			case sn.readyc <- rd:
			case <-sn.done:
				return
			}
		}
	}
}

func (sn *SignNode) Ready() <-chan Ready {
	return sn.readyc
}

func (sn *SignNode) Step(ctx context.Context, m *pb.Message) error {
	if m == nil {
		return errors.New("cannot step with nil message")
	}
	if err := sn.verifyMessage(m); err != nil {
		return err
	}
	if shouldVerifyLeaderProof(m, sn.selfID, sn.peerPubKeys, sn.cfg.leaderProofQuorum()) {
		if err := sn.VerifyLeader(m); err != nil {
			return err
		}
	}
	return sn.Node.Step(ctx, m)
}

func (sn *SignNode) Stop() {
	select {
	case <-sn.done:
	default:
		close(sn.done)
	}
	sn.Node.Stop()
}

func (sn *SignNode) signMessages(msgs []*pb.Message) []*pb.Message {
	if len(msgs) == 0 {
		return msgs
	}
	out := make([]*pb.Message, len(msgs))
	for i, m := range msgs {
		out[i] = sn.signMessageTree(m)
	}
	return out
}

func (sn *SignNode) signMessageTree(m *pb.Message) *pb.Message {
	mm := proto.Clone(m).(*pb.Message)
	if shouldAttachLeaderProof(mm, sn.selfID, sn.peerPubKeys, sn.clientIDs, sn.clientPub, sn.cfg.leaderProofQuorum()) {
		if err := sn.AddLeaderProof(mm); err != nil {
			panic(err)
		}
	}
	if shouldSign(mm, sn.selfID, sn.peerPubKeys, sn.clientIDs, sn.clientPub) {
		if err := sn.signMessage(mm); err != nil {
			panic(err)
		}
	}
	for i := range mm.Responses {
		mm.Responses[i] = sn.signMessageTree(mm.Responses[i])
	}
	return mm
}

func (sn *SignNode) verifyMessage(m *pb.Message) error {
	if !shouldVerify(m, sn.selfID, sn.peerPubKeys, sn.clientIDs, sn.clientPub) {
		return nil
	}
	var signedForProof *pb.Message
	if sn.cfg.leaderProofQuorum() > 0 && shouldRecordLeaderAttestation(m, sn.selfID, sn.peerPubKeys) {
		signedForProof = proto.Clone(m).(*pb.Message)
	}
	sig, ts, origCtx, err := parseSignature(m.Context)
	if err != nil {
		return err
	}
	if err := sn.checkFreshness(m.GetFrom(), ts); err != nil {
		return err
	}
	pub, ok := lookupPubKey(m.GetFrom(), sn.peerPubKeys, sn.clientIDs, sn.clientPub)
	if !ok {
		return ErrUnknownSigner
	}
	data, err := messageSignBytes(m, origCtx, ts)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, data, sig) {
		return ErrInvalidSignature
	}
	sn.recordSeen(m.GetFrom(), ts)
	if signedForProof != nil {
		sn.recordLeaderAttestation(signedForProof, ts)
	}
	m.Context = origCtx
	for i := range m.Responses {
		if err := sn.verifyMessage(m.Responses[i]); err != nil {
			return err
		}
	}
	return nil
}

func (sn *SignNode) nextSignTimestamp() int64 {
	ts := sn.cfg.now().UnixNano()
	sn.mu.Lock()
	defer sn.mu.Unlock()
	if ts <= sn.localSent {
		ts = sn.localSent + 1
	}
	sn.localSent = ts
	return ts
}

func (sn *SignNode) signMessage(m *pb.Message) error {
	origCtx := normalizeContext(m.Context)
	ts := sn.nextSignTimestamp()
	data, err := messageSignBytes(m, origCtx, ts)
	if err != nil {
		return err
	}
	sig := ed25519.Sign(sn.priv, data)
	m.Context = packSignature(sig, ts, origCtx)
	return nil
}

func (sn *SignNode) checkFreshness(from uint64, ts int64) error {
	now := sn.cfg.now().UnixNano()
	maxAge := sn.cfg.maxAge().Nanoseconds()
	age := now - ts
	if age < 0 {
		age = -age
	}
	if age > maxAge {
		return ErrStaleMessage
	}
	sn.mu.Lock()
	defer sn.mu.Unlock()
	if last, ok := sn.lastSeen[from]; ok && ts <= last {
		return ErrStaleMessage
	}
	return nil
}

func (sn *SignNode) recordSeen(from uint64, ts int64) {
	sn.mu.Lock()
	defer sn.mu.Unlock()
	if ts > sn.lastSeen[from] {
		sn.lastSeen[from] = ts
	}
}

func messageSignBytes(m *pb.Message, context []byte, ts int64) ([]byte, error) {
	mm := proto.Clone(m).(*pb.Message)
	mm.Context = normalizeContext(context)
	mm.Responses = nil
	payload, err := proto.Marshal(mm)
	if err != nil {
		return nil, err
	}
	return append(payload, timestampBytes(ts)...), nil
}

func timestampBytes(ts int64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(ts))
	return b[:]
}

func normalizeContext(ctx []byte) []byte {
	if len(ctx) == 0 {
		return nil
	}
	return ctx
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

func shouldSign(m *pb.Message, selfID uint64, peerPubKeys map[uint64]ed25519.PublicKey, clientIDs map[uint64]struct{}, clientPub ed25519.PublicKey) bool {
	if isInternalMessage(m) {
		return false
	}
	return isPeerOrClient(m.GetTo(), selfID, peerPubKeys, clientIDs, clientPub)
}

// shouldVerify reports whether an inbound message must carry a valid signature.
func shouldVerify(m *pb.Message, selfID uint64, peerPubKeys map[uint64]ed25519.PublicKey, clientIDs map[uint64]struct{}, clientPub ed25519.PublicKey) bool {
	if isInternalMessage(m) {
		return false
	}
	return isPeerOrClient(m.GetFrom(), selfID, peerPubKeys, clientIDs, clientPub)
}

func isInternalMessage(m *pb.Message) bool {
	if IsLocalMsg(m.GetType()) {
		return true
	}
	if IsLocalMsgTarget(m.GetTo()) || IsLocalMsgTarget(m.GetFrom()) {
		return true
	}
	return false
}

func isPeerOrClient(id, selfID uint64, peerPubKeys map[uint64]ed25519.PublicKey, clientIDs map[uint64]struct{}, clientPub ed25519.PublicKey) bool {
	if id == 0 || id == selfID {
		return false
	}
	_, ok := lookupPubKey(id, peerPubKeys, clientIDs, clientPub)
	return ok
}

func lookupPubKey(id uint64, peerPubKeys map[uint64]ed25519.PublicKey, clientIDs map[uint64]struct{}, clientPub ed25519.PublicKey) (ed25519.PublicKey, bool) {
	if pub, ok := peerPubKeys[id]; ok {
		return pub, true
	}
	if len(clientPub) > 0 {
		if _, ok := clientIDs[id]; ok {
			return clientPub, true
		}
	}
	return nil, false
}

func packSignature(sig []byte, ts int64, origCtx []byte) []byte {
	out := make([]byte, sigOverhead+len(origCtx))
	copy(out, sigMagic)
	binary.BigEndian.PutUint64(out[len(sigMagic):], uint64(ts))
	copy(out[len(sigMagic)+8:], sig)
	binary.BigEndian.PutUint32(out[len(sigMagic)+8+ed25519.SignatureSize:], uint32(len(origCtx)))
	copy(out[sigOverhead:], origCtx)
	return out
}

func parseSignature(ctx []byte) (sig []byte, ts int64, origCtx []byte, err error) {
	if len(ctx) < sigOverhead {
		return nil, 0, nil, ErrInvalidSignature
	}
	if string(ctx[:len(sigMagic)]) != sigMagic {
		return nil, 0, nil, ErrInvalidSignature
	}
	ts = int64(binary.BigEndian.Uint64(ctx[len(sigMagic):]))
	sig = ctx[len(sigMagic)+8 : len(sigMagic)+8+ed25519.SignatureSize]
	n := binary.BigEndian.Uint32(ctx[len(sigMagic)+8+ed25519.SignatureSize : sigOverhead])
	if uint64(sigOverhead)+uint64(n) != uint64(len(ctx)) {
		return nil, 0, nil, ErrInvalidSignature
	}
	origCtx = normalizeContext(ctx[sigOverhead:])
	return sig, ts, origCtx, nil
}
