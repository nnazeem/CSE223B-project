// via cursor

package raft

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	pb "go.etcd.io/raft/v3/raftpb"
)

func testSignNode(t *testing.T, now time.Time, maxAge time.Duration) (*SignNode, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	fixed := now
	sn := &SignNode{
		selfID:      2,
		priv:        priv,
		peerPubKeys: map[uint64]ed25519.PublicKey{1: pub, 2: pub},
		cfg: SignConfig{
			MaxAge: maxAge,
			Now:    func() time.Time { return fixed },
		},
		lastSeen: make(map[uint64]int64),
	}
	return sn, pub
}

func TestSignVerifyPeerMessage(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	sn, _ := testSignNode(t, now, DefaultMaxMessageAge)

	m := &pb.Message{
		Type: pb.MsgHeartbeat.Enum(),
		To:   uint64Ptr(2),
		From: uint64Ptr(1),
		Term: uint64Ptr(1),
	}
	require.True(t, shouldSign(m, 1, map[uint64]ed25519.PublicKey{2: sn.peerPubKeys[2]}, nil, nil))
	require.NoError(t, sn.signMessage(m))
	require.GreaterOrEqual(t, len(m.GetContext()), sigOverhead)

	mm := proto.Clone(m).(*pb.Message)
	require.NoError(t, sn.verifyMessage(mm))
	require.Empty(t, mm.GetContext())
}

func TestSignVerifyClientMessage(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	now := time.Unix(1_700_000_000, 0)
	clientIDs := clientIDSet([]uint64{100, 101})
	sn := &SignNode{
		selfID:    2,
		priv:      priv,
		clientIDs: clientIDs,
		clientPub: pub,
		cfg:       SignConfig{MaxAge: DefaultMaxMessageAge, Now: func() time.Time { return now }},
		lastSeen:  make(map[uint64]int64),
	}

	for _, clientID := range []uint64{100, 101} {
		m := &pb.Message{
			Type: pb.MsgApp.Enum(),
			To:   uint64Ptr(clientID),
			From: uint64Ptr(2),
			Term: uint64Ptr(1),
		}
		require.True(t, shouldSign(m, 2, nil, clientIDs, pub))
		require.NoError(t, sn.signMessage(m))
		require.NoError(t, sn.verifyMessage(proto.Clone(m).(*pb.Message)))
	}
}

func TestFreshnessRejectsOldMessage(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	sn, _ := testSignNode(t, now, 10*time.Second)

	m := &pb.Message{Type: pb.MsgHeartbeat.Enum(), To: uint64Ptr(2), From: uint64Ptr(1)}
	require.NoError(t, sn.signMessage(m))

	sn.cfg.Now = func() time.Time { return now.Add(11 * time.Second) }
	mm := proto.Clone(m).(*pb.Message)
	require.ErrorIs(t, sn.verifyMessage(mm), ErrStaleMessage)
}

func TestFreshnessRejectsReplay(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	sn, _ := testSignNode(t, now, DefaultMaxMessageAge)

	m := &pb.Message{Type: pb.MsgHeartbeat.Enum(), To: uint64Ptr(2), From: uint64Ptr(1)}
	require.NoError(t, sn.signMessage(m))

	mm := proto.Clone(m).(*pb.Message)
	require.NoError(t, sn.verifyMessage(mm))

	// Same timestamp/signature must not be accepted again.
	require.ErrorIs(t, sn.verifyMessage(proto.Clone(m).(*pb.Message)), ErrStaleMessage)
}

func TestInternalMessagesNotSigned(t *testing.T) {
	peerKeys := map[uint64]ed25519.PublicKey{2: {}}

	m := &pb.Message{Type: pb.MsgHup.Enum(), From: uint64Ptr(1), To: uint64Ptr(1)}
	require.False(t, shouldSign(m, 1, peerKeys, nil, nil))
	require.False(t, shouldVerify(m, 1, peerKeys, nil, nil))

	storage := &pb.Message{
		Type: pb.MsgStorageAppend.Enum(),
		To:   uint64Ptr(LocalAppendThread),
		From: uint64Ptr(1),
	}
	require.False(t, shouldSign(storage, 1, peerKeys, nil, nil))
}

func uint64Ptr(v uint64) *uint64 {
	return &v
}
