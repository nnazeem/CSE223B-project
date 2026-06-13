package raft

import (
	"crypto/ed25519"
	"testing"

	"github.com/stretchr/testify/require"
	pb "go.etcd.io/raft/v3/raftpb"
)

func signClientRequestForTest(
	t *testing.T,
	clientID uint64,
	to uint64,
	payload []byte,
	priv ed25519.PrivateKey,
	ts int64,
) *pb.Message {
	t.Helper()

	req := &pb.Message{
		Type:    pb.MsgProp.Enum(),
		From:    u64p(clientID),
		To:      u64p(to),
		Entries: []*pb.Entry{{Data: payload}},
	}

	origCtx := normalizeContext(req.Context)
	data, err := messageSignBytes(req, origCtx, ts)
	require.NoError(t, err)

	req.Context = packSignature(ed25519.Sign(priv, data), ts, origCtx)
	return req
}
