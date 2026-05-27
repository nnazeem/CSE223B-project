// via cursor

package raft

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sync/atomic"
	"sync"

	"github.com/golang/protobuf/proto"

	pb "go.etcd.io/raft/v3/raftpb"
)

const (
	logMagic    = "raftlog1"
	hashSize    = sha256.Size
	randomBytes = 16
	logOverhead = len(logMagic) + 2 + randomBytes + hashSize + 4 // magic + rlen + R + H + orig ctx len
)

var (
	// ErrInvalidLog is returned when the expected iterative log hash does not match.
	ErrInvalidLog = errors.New("bft: final log state does not match")
	// ErrInvalidLogContext is returned when a message context is malformed.
	ErrInvalidLogContext = errors.New("bft: invalid log context")
)

// LogPVNode wraps a Node and tracks an iterative hash over appended log entries.
// For non-local messages with non-empty entries:
// - outbound: attach (R, H) in context, where H=SHA256(nextLogHash || R)
// - inbound: verify attached H against local nextLogHash and R
// The original context is preserved/restored transparently.
type LogPVNode struct {
	Node
	selfID uint64

	mu      sync.Mutex
	logHash [hashSize]byte
	seq     uint64

	readyc chan Ready
	done   chan struct{}
}

// WrapLogPVNode returns a Node wrapper that enforces iterative log-hash proofs.
func WrapLogPVNode(
	n Node,
	selfID uint64,
) *LogPVNode {
	ln := &LogPVNode{
		Node:   n,
		selfID: selfID,
		readyc: make(chan Ready),
		done:   make(chan struct{}),
	}
	go ln.forwardReady()
	return ln
}

func (ln *LogPVNode) forwardReady() {
	for {
		select {
		case <-ln.done:
			return
		case rd := <-ln.Node.Ready():
			ln.updateHashFromStorageMessages(rd.Messages)
			rd.Messages = ln.attachMessages(rd.Messages)
			select {
			case ln.readyc <- rd:
			case <-ln.done:
				return
			}
		}
	}
}

func (ln *LogPVNode) Ready() <-chan Ready {
	return ln.readyc
}

func (ln *LogPVNode) Step(ctx context.Context, m *pb.Message) error {
	if m == nil {
		return errors.New("cannot step with nil message")
	}
	if err := ln.verifyMessageTree(m); err != nil {
		return err
	}
	return ln.Node.Step(ctx, *m)
}

func (ln *LogPVNode) Stop() {
	select {
	case <-ln.done:
	default:
		close(ln.done)
	}
	ln.Node.Stop()
}

// InitFromEntries initializes the tracked hash from an already-populated log.
// Use this when wrapping a restarted node with preexisting entries.
func (ln *LogPVNode) InitFromEntries(entries []pb.Entry) {
	var zero [hashSize]byte
	ln.setLogHash(iterativeEntriesHash(zero, entries))
}

func (ln *LogPVNode) attachMessages(msgs []pb.Message) []pb.Message {
	if len(msgs) == 0 {
		return msgs
	}
	out := make([]pb.Message, len(msgs))
	for i := range msgs {
		out[i] = ln.attachMessageTree(msgs[i])
	}
	return out
}

func (ln *LogPVNode) attachMessageTree(m pb.Message) pb.Message {
	mm := proto.Clone(&m).(*pb.Message)
	if ln.shouldAttach(mm) {
		origCtx := normalizeContext(mm.Context)
		r := ln.newRandomValue()
		_, h := ln.computeHashForEntries(mm.Entries, r)
		mm.Context = packLogProof(r, h, origCtx)
	}
	for i := range mm.Responses {
		mm.Responses[i] = ln.attachMessageTree(mm.Responses[i])
	}
	return *mm
}

func (ln *LogPVNode) verifyMessageTree(m *pb.Message) error {
	if ln.shouldVerify(m) {
		r, h, origCtx, err := parseLogProof(m.Context)
		if err != nil {
			return err
		}
		_, expected := ln.computeHashForEntries(m.Entries, r)
		if !equalHash(expected, h) {
			return ErrInvalidLog
		}
		m.Context = origCtx
	}
	for i := range m.Responses {
		if err := ln.verifyMessageTree(&m.Responses[i]); err != nil {
			return err
		}
	}
	return nil
}

func (ln *LogPVNode) shouldAttach(m *pb.Message) bool {
	if len(m.Entries) == 0 {
		return false
	}
	if IsLocalMsg(m.Type) || IsLocalMsgTarget(m.To) || IsLocalMsgTarget(m.From) {
		return false
	}
	return m.To != 0 && m.To != ln.selfID
}

func (ln *LogPVNode) shouldVerify(m *pb.Message) bool {
	if len(m.Entries) == 0 {
		return false
	}
	if IsLocalMsg(m.Type) || IsLocalMsgTarget(m.To) || IsLocalMsgTarget(m.From) {
		return false
	}
	return m.From != 0 && m.From != ln.selfID
}

func (ln *LogPVNode) newRandomValue() []byte {
	r := make([]byte, randomBytes)
	if _, err := rand.Read(r); err != nil {
		seq := atomic.AddUint64(&ln.seq, 1)
		binary.BigEndian.PutUint64(r[:8], seq)
		binary.BigEndian.PutUint64(r[8:], seq^0xa5a5a5a5a5a5a5a5)
	}
	return r
}

func (ln *LogPVNode) computeHashForEntries(entries []pb.Entry, r []byte) ([hashSize]byte, []byte) {
	ln.mu.Lock()
	cur := ln.logHash
	ln.mu.Unlock()
	next := iterativeEntriesHash(cur, entries)
	sum := sha256.Sum256(appendHashAndBytes(next, r))
	return next, sum[:]
}

func (ln *LogPVNode) setLogHash(next [hashSize]byte) {
	ln.mu.Lock()
	defer ln.mu.Unlock()
	ln.logHash = next
}

func (ln *LogPVNode) updateHashFromStorageMessages(msgs []pb.Message) {
	for i := range msgs {
		ln.updateHashFromStorageMessageTree(&msgs[i])
	}
}

func (ln *LogPVNode) updateHashFromStorageMessageTree(m *pb.Message) {
	if m.Type == pb.MsgStorageAppend && IsLocalMsgTarget(m.To) && len(m.Entries) > 0 {
		ln.mu.Lock()
		ln.logHash = iterativeEntriesHash(ln.logHash, m.Entries)
		ln.mu.Unlock()
	}
	for i := range m.Responses {
		ln.updateHashFromStorageMessageTree(&m.Responses[i])
	}
}

func iterativeEntriesHash(base [hashSize]byte, entries []pb.Entry) [hashSize]byte {
	h := base
	for i := range entries {
		b, err := proto.Marshal(&entries[i])
		if err != nil {
			panic(err)
		}
		h = sha256.Sum256(appendHashAndBytes(h, b))
	}
	return h
}

func appendHashAndBytes(h [hashSize]byte, b []byte) []byte {
	out := make([]byte, 0, hashSize+len(b))
	out = append(out, h[:]...)
	out = append(out, b...)
	return out
}

func equalHash(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

func packLogProof(r, h, origCtx []byte) []byte {
	out := make([]byte, logOverhead+len(origCtx))
	copy(out, logMagic)
	binary.BigEndian.PutUint16(out[len(logMagic):], uint16(len(r)))
	copy(out[len(logMagic)+2:], r)
	copy(out[len(logMagic)+2+len(r):], h)
	binary.BigEndian.PutUint32(out[len(logMagic)+2+len(r)+hashSize:], uint32(len(origCtx)))
	copy(out[logOverhead:], origCtx)
	return out
}

func parseLogProof(ctx []byte) (r []byte, h []byte, origCtx []byte, err error) {
	if len(ctx) < logOverhead {
		return nil, nil, nil, ErrInvalidLogContext
	}
	if string(ctx[:len(logMagic)]) != logMagic {
		return nil, nil, nil, ErrInvalidLogContext
	}
	rlen := int(binary.BigEndian.Uint16(ctx[len(logMagic):]))
	if rlen != randomBytes {
		return nil, nil, nil, ErrInvalidLogContext
	}
	proofEnd := len(logMagic) + 2 + rlen + hashSize + 4
	if proofEnd > len(ctx) {
		return nil, nil, nil, ErrInvalidLogContext
	}
	r = ctx[len(logMagic)+2 : len(logMagic)+2+rlen]
	h = ctx[len(logMagic)+2+rlen : len(logMagic)+2+rlen+hashSize]
	n := binary.BigEndian.Uint32(ctx[len(logMagic)+2+rlen+hashSize : proofEnd])
	if uint64(proofEnd)+uint64(n) != uint64(len(ctx)) {
		return nil, nil, nil, ErrInvalidLogContext
	}
	origCtx = normalizeContext(ctx[proofEnd:])
	return r, h, origCtx, nil
}
