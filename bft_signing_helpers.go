package raft

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"time"

	"google.golang.org/protobuf/proto"

	pb "go.etcd.io/raft/v3/raftpb"
)

const (
	sigMagic = "bftsig1"
)

// DefaultMaxMessageAge is used by ClientProofConfig when MaxAge is unset.
const DefaultMaxMessageAge = 30 * time.Second

var (
	ErrInvalidSignature = errors.New("raft: invalid message signature")
	ErrUnknownSigner    = errors.New("raft: unknown signer")
	ErrStaleMessage     = errors.New("raft: stale message")
)

func u64p(v uint64) *uint64 { return &v }

// VerifyBFTMessageSignature verifies the signed envelope embedded in message context.
// It returns the signed timestamp and the original, unsigned context payload.
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

func u64Ptr(v uint64) *uint64 { return &v }

func cloneEntries(in []*pb.Entry) []*pb.Entry {
	if len(in) == 0 {
		return nil
	}
	out := make([]*pb.Entry, len(in))
	for i := range in {
		if in[i] == nil {
			continue
		}
		cp := *in[i]
		if len(cp.Data) > 0 {
			cp.Data = append([]byte(nil), cp.Data...)
		}
		out[i] = &cp
	}
	return out
}

func normalizeContext(ctx []byte) []byte {
	if len(ctx) == 0 {
		return nil
	}
	return append([]byte(nil), ctx...)
}

// messageSignBytes produces the byte slice that should be signed for a given message and timestamp.
func messageSignBytes(m *pb.Message, origCtx []byte, ts int64) ([]byte, error) {
	clone := proto.Clone(m).(*pb.Message)
	clone.Context = normalizeContext(origCtx)
	mb, err := proto.Marshal(clone)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(sigMagic)+8+len(mb))
	out = append(out, []byte(sigMagic)...)
	tb := make([]byte, 8)
	binary.BigEndian.PutUint64(tb, uint64(ts))
	out = append(out, tb...)
	out = append(out, mb...)
	return out, nil
}

// packSignature creates a new context byte slice by packing the signature, timestamp, and original context together.
func packSignature(sig []byte, ts int64, origCtx []byte) []byte {
	origCtx = normalizeContext(origCtx)
	out := make([]byte, 0, len(sigMagic)+8+2+len(sig)+4+len(origCtx))
	out = append(out, []byte(sigMagic)...)
	tb := make([]byte, 8)
	binary.BigEndian.PutUint64(tb, uint64(ts))
	out = append(out, tb...)
	lb := make([]byte, 2)
	binary.BigEndian.PutUint16(lb, uint16(len(sig)))
	out = append(out, lb...)
	out = append(out, sig...)
	cb := make([]byte, 4)
	binary.BigEndian.PutUint32(cb, uint32(len(origCtx)))
	out = append(out, cb...)
	out = append(out, origCtx...)
	return out
}

// parseSignature extracts the signature, timestamp, and original context from a packed context byte slice.
func parseSignature(ctx []byte) (sig []byte, ts int64, origCtx []byte, err error) {
	if len(ctx) < len(sigMagic)+8+2+4 {
		return nil, 0, nil, ErrInvalidSignature
	}
	if string(ctx[:len(sigMagic)]) != sigMagic {
		return nil, 0, nil, ErrInvalidSignature
	}
	pos := len(sigMagic)
	ts = int64(binary.BigEndian.Uint64(ctx[pos : pos+8]))
	pos += 8
	sigLen := int(binary.BigEndian.Uint16(ctx[pos : pos+2]))
	pos += 2
	if sigLen <= 0 || sigLen != ed25519.SignatureSize || pos+sigLen+4 > len(ctx) {
		return nil, 0, nil, ErrInvalidSignature
	}
	sig = append([]byte(nil), ctx[pos:pos+sigLen]...)
	pos += sigLen
	origLen := int(binary.BigEndian.Uint32(ctx[pos : pos+4]))
	pos += 4
	if origLen < 0 || pos+origLen != len(ctx) {
		return nil, 0, nil, ErrInvalidSignature
	}
	origCtx = normalizeContext(ctx[pos : pos+origLen])
	return sig, ts, origCtx, nil
}
