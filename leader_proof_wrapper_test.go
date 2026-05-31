package raft

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/stretchr/testify/require"

	pb "go.etcd.io/raft/v3/raftpb"
)

func newSignNodeForTest(selfID uint64, priv ed25519.PrivateKey, peerPubKeys map[uint64]ed25519.PublicKey, cfg SignConfig) *SignNode {
	return &SignNode{
		selfID:      selfID,
		priv:        priv,
		peerPubKeys: peerPubKeys,
		cfg:         cfg,
		lastSeen:    make(map[uint64]int64),
		leaderSeen:  make(map[uint64]pb.Message),
	}
}

func signWithNode(t *testing.T, now time.Time, selfID uint64, priv ed25519.PrivateKey, peerPubKeys map[uint64]ed25519.PublicKey, msg *pb.Message) {
	t.Helper()
	sn := newSignNodeForTest(selfID, priv, peerPubKeys, SignConfig{MaxAge: DefaultMaxMessageAge, Now: func() time.Time { return now }})
	require.NoError(t, sn.signMessage(msg))
}

func TestAddAndVerifyLeaderProof(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)

	leaderPub, leaderPriv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	f2Pub, f2Priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	f3Pub, f3Priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	leader := newSignNodeForTest(1, leaderPriv, map[uint64]ed25519.PublicKey{2: f2Pub, 3: f3Pub}, SignConfig{
		MaxAge:            DefaultMaxMessageAge,
		Now:               func() time.Time { return now },
		LeaderProofQuorum: 2,
	})

	att2 := &pb.Message{Type: pb.MsgHeartbeatResp, From: 2, To: 1, Term: 7}
	signWithNode(t, now, 2, f2Priv, map[uint64]ed25519.PublicKey{1: leaderPub}, att2)
	require.NoError(t, leader.verifyMessage(proto.Clone(att2).(*pb.Message)))

	att3 := &pb.Message{Type: pb.MsgHeartbeatResp, From: 3, To: 1, Term: 7}
	signWithNode(t, now, 3, f3Priv, map[uint64]ed25519.PublicKey{1: leaderPub}, att3)
	require.NoError(t, leader.verifyMessage(proto.Clone(att3).(*pb.Message)))

	out := &pb.Message{Type: pb.MsgApp, From: 1, To: 2, Term: 7, Context: []byte("client-rctx")}
	require.NoError(t, leader.AddLeaderProof(out))
	require.NoError(t, leader.signMessage(out))

	follower := newSignNodeForTest(2, f2Priv, map[uint64]ed25519.PublicKey{1: leaderPub, 3: f3Pub}, SignConfig{
		MaxAge:            DefaultMaxMessageAge,
		Now:               func() time.Time { return now },
		LeaderProofQuorum: 2,
	})

	in := proto.Clone(out).(*pb.Message)
	require.NoError(t, follower.verifyMessage(in))
	require.NoError(t, follower.VerifyLeader(in))
	require.Equal(t, []byte("client-rctx"), in.Context)
}

func TestAddLeaderProofInsufficientQuorum(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)

	leaderPub, leaderPriv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	f2Pub, f2Priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	leader := newSignNodeForTest(1, leaderPriv, map[uint64]ed25519.PublicKey{2: f2Pub}, SignConfig{
		MaxAge:            DefaultMaxMessageAge,
		Now:               func() time.Time { return now },
		LeaderProofQuorum: 2,
	})

	att2 := &pb.Message{Type: pb.MsgHeartbeatResp, From: 2, To: 1, Term: 5}
	signWithNode(t, now, 2, f2Priv, map[uint64]ed25519.PublicKey{1: leaderPub}, att2)
	require.NoError(t, leader.verifyMessage(proto.Clone(att2).(*pb.Message)))

	out := &pb.Message{Type: pb.MsgApp, From: 1, To: 2, Term: 5}
	require.ErrorIs(t, leader.AddLeaderProof(out), ErrInsufficientLeaderProof)
}

func TestVerifyLeaderFailsOnStaleProof(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	// leader given larger tolerance than follower, so proof is stale for follower but not leader
	leaderMaxAge := 2 * DefaultMaxMessageAge
	old := now.Add(-(DefaultMaxMessageAge + time.Second))

	leaderPub, leaderPriv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	f2Pub, f2Priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	f3Pub, f3Priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	leader := newSignNodeForTest(1, leaderPriv, map[uint64]ed25519.PublicKey{2: f2Pub, 3: f3Pub}, SignConfig{
		MaxAge:            leaderMaxAge,
		Now:               func() time.Time { return old },
		LeaderProofQuorum: 2,
	})

	att2 := &pb.Message{Type: pb.MsgHeartbeatResp, From: 2, To: 1, Term: 9}
	signWithNode(t, old, 2, f2Priv, map[uint64]ed25519.PublicKey{1: leaderPub}, att2)
	require.NoError(t, leader.verifyMessage(proto.Clone(att2).(*pb.Message)))
	att3 := &pb.Message{Type: pb.MsgHeartbeatResp, From: 3, To: 1, Term: 9}
	signWithNode(t, old, 3, f3Priv, map[uint64]ed25519.PublicKey{1: leaderPub}, att3)
	require.NoError(t, leader.verifyMessage(proto.Clone(att3).(*pb.Message)))

	out := &pb.Message{Type: pb.MsgApp, From: 1, To: 2, Term: 9}
	leader.cfg.Now = func() time.Time { return now }
	require.NoError(t, leader.AddLeaderProof(out))
	require.NoError(t, leader.signMessage(out))

	follower := newSignNodeForTest(2, f2Priv, map[uint64]ed25519.PublicKey{1: leaderPub, 3: f3Pub}, SignConfig{
		MaxAge:            DefaultMaxMessageAge,
		Now:               func() time.Time { return now },
		LeaderProofQuorum: 2,
	})

	in := proto.Clone(out).(*pb.Message)
	require.NoError(t, follower.verifyMessage(in))
	require.ErrorIs(t, follower.VerifyLeader(in), ErrInsufficientLeaderProof)
}
