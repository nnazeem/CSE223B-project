// via VSCode Agent Chat

package raft

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/stretchr/testify/require"

	pb "go.etcd.io/raft/v3/raftpb"
)

func TestClientProofSignVerify(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	signer := NewClientProofSigner(10, priv, &ClientProofConfig{Now: func() time.Time { return now }})
	verifier := NewClientProofVerifier(map[uint64]ed25519.PublicKey{10: pub})

	m := &pb.Message{
		Type:    pb.MsgProp,
		Entries: []pb.Entry{{Data: []byte("hello")}},
		Context: []byte("orig"),
	}
	require.NoError(t, signer.AddClientProof(m))

	verified := proto.Clone(m).(*pb.Message)
	require.NoError(t, verifier.VerifyClient(verified))
	require.Equal(t, []byte("orig"), verified.Context)
}

func TestClientProofRejectsReplay(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	signer := NewClientProofSigner(42, priv, &ClientProofConfig{Now: func() time.Time { return now }})
	verifier := NewClientProofVerifier(map[uint64]ed25519.PublicKey{42: pub})

	m := &pb.Message{Type: pb.MsgProp, Entries: []pb.Entry{{Data: []byte("data")}}}
	require.NoError(t, signer.AddClientProof(m))

	signed := proto.Clone(m).(*pb.Message)
	require.NoError(t, verifier.VerifyClient(proto.Clone(signed).(*pb.Message)))
	err = verifier.VerifyClient(proto.Clone(signed).(*pb.Message))
	require.ErrorIs(t, err, ErrClientReplay)
}

func TestClientProofRejectsUnknownClient(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	signer := NewClientProofSigner(1, priv, nil)
	verifier := NewClientProofVerifier(map[uint64]ed25519.PublicKey{})

	m := &pb.Message{Type: pb.MsgProp, Entries: []pb.Entry{{Data: []byte("data")}}}
	require.NoError(t, signer.AddClientProof(m))

	err = verifier.VerifyClient(proto.Clone(m).(*pb.Message))
	require.ErrorIs(t, err, ErrUnknownClient)
}

func TestClientProofRejectsTamper(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	signer := NewClientProofSigner(7, priv, nil)
	verifier := NewClientProofVerifier(map[uint64]ed25519.PublicKey{7: pub})

	m := &pb.Message{Type: pb.MsgProp, Entries: []pb.Entry{{Data: []byte("data")}}}
	require.NoError(t, signer.AddClientProof(m))

	tampered := proto.Clone(m).(*pb.Message)
	tampered.Entries[0].Data = []byte("tampered")
	err = verifier.VerifyClient(tampered)
	require.ErrorIs(t, err, ErrInvalidClientProof)
}

func TestClientProofMonotonicTimestamp(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	signer := NewClientProofSigner(5, priv, &ClientProofConfig{Now: func() time.Time { return now }})
	verifier := NewClientProofVerifier(map[uint64]ed25519.PublicKey{5: pub})

	m1 := &pb.Message{Type: pb.MsgProp, Entries: []pb.Entry{{Data: []byte("a")}}}
	m2 := &pb.Message{Type: pb.MsgProp, Entries: []pb.Entry{{Data: []byte("b")}}}

	require.NoError(t, signer.AddClientProof(m1))
	require.NoError(t, signer.AddClientProof(m2))

	require.NoError(t, verifier.VerifyClient(proto.Clone(m1).(*pb.Message)))
	require.NoError(t, verifier.VerifyClient(proto.Clone(m2).(*pb.Message)))
}
