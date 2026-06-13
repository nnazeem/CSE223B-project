package raft

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/stretchr/testify/require"
	pb "go.etcd.io/raft/v3/raftpb"
)

func makeSignedViewChangeForByzantineTest(t *testing.T, fx *bftNetworkFixture, from uint64, newView uint64, ts int64) pb.Message {
	t.Helper()

	vc, err := fx.nodes[from].ConstructViewChange(newView)
	require.NoError(t, err)
	vc.To = nil
	signTestNodeMessage(t, vc, fx.nodePrivs[from], ts)
	return *vc
}

func makeSignedNewViewForByzantineTest(t *testing.T, fx *bftNetworkFixture, from uint64, to uint64, view uint64, viewSet []pb.Message, prePrepareSet []pb.Message, ts int64) *pb.Message {
	t.Helper()

	bctx := BFTContext{
		Phase:         PhaseNewView,
		View:          view,
		ViewSet:       append([]pb.Message(nil), viewSet...),
		PrePrepareSet: append([]pb.Message(nil), prePrepareSet...),
	}
	encCtx, err := encodeBFTContext(bctx)
	require.NoError(t, err)

	m := &pb.Message{
		Type:    pb.MsgApp.Enum(),
		From:    u64p(from),
		To:      u64p(to),
		Context: encCtx,
	}
	signTestNodeMessage(t, m, fx.nodePrivs[from], ts)
	return m
}

func makeFakeClientPrePrepareFromPrimary(t *testing.T, fx *bftNetworkFixture, to uint64, seq uint64, payload []byte, fakeReqTS int64, fakeClientID uint64, ts int64) *pb.Message {
	t.Helper()

	digest, err := hashEntryBatch([]*pb.Entry{{Data: payload}})
	require.NoError(t, err)

	_, attackerPriv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	clientReq := signClientRequestForTest(t, fakeClientID, to, payload, attackerPriv, fakeReqTS)

	bctx := BFTContext{
		Phase:            PhasePrePrepare,
		View:             0,
		SeqNum:           seq,
		Digest:           digest,
		RequestTimestamp: fakeReqTS,
		ClientID:         fakeClientID,
		ClientRequest:    *proto.Clone(clientReq).(*pb.Message),
	}
	encCtx, err := encodeBFTContext(bctx)
	require.NoError(t, err)

	m := &pb.Message{
		Type:    pb.MsgApp.Enum(),
		From:    u64p(1), // primary for view 0
		To:      u64p(to),
		Context: encCtx,
		Entries: []*pb.Entry{{Data: payload}},
	}
	signTestNodeMessage(t, m, fx.nodePrivs[1], ts)
	return m
}

func routeByzantineTestMessagesAmongBackups(t *testing.T, fx *bftNetworkFixture, initial []*pb.Message) []*pb.Message {
	t.Helper()

	queue := append([]*pb.Message(nil), initial...)
	var replies []*pb.Message

	for steps := 0; len(queue) > 0 && steps < 200; steps++ {
		msg := queue[0]
		queue = queue[1:]
		if msg == nil {
			continue
		}

		// The Byzantine primary is not needed to prove the attack path. Route only
		// honest-backup traffic and collect any client replies emitted by backups.
		switch msg.GetTo() {
		case 100:
			replies = append(replies, msg)
			continue
		case 2, 3, 4:
			// deliver below
		default:
			continue
		}

		err := fx.nodes[msg.GetTo()].Step(fx.ctx, proto.Clone(msg).(*pb.Message))
		if err != nil {
			continue
		}

		out := drainNodeReadyIfAny(t, fx.nodes[msg.GetTo()])
		for _, outMsg := range out {
			if outMsg.GetTo() == 100 {
				replies = append(replies, outMsg)
				continue
			}
			if outMsg.GetTo() == 2 || outMsg.GetTo() == 3 || outMsg.GetTo() == 4 {
				queue = append(queue, outMsg)
			}
		}
	}

	return replies
}

func TestBFTByzantine_NewViewWithoutViewChangeQuorumRejected(t *testing.T) {
	fx := newBFTNetworkFixture(t)

	// View 1's primary is node 2. It proposes a NEW-VIEW with only two
	// VIEW-CHANGE messages. For n=4, f=1, PBFT requires 2f+1 == 3.
	vc1 := makeSignedViewChangeForByzantineTest(t, fx, 1, 1, 101)
	vc2 := makeSignedViewChangeForByzantineTest(t, fx, 2, 1, 102)
	nv := makeSignedNewViewForByzantineTest(t, fx, 2, 3, 1, []pb.Message{vc1, vc2}, nil, 200)

	err := fx.nodes[3].Step(context.Background(), nv)
	require.ErrorIs(t, err, ErrInvalidNewView)
	require.Equal(t, uint64(0), fx.nodes[3].view)
	require.Equal(t, Normal, fx.nodes[3].nodePhase)
}

func TestBFTByzantine_PrimaryCannotReplicateFakeClientRequestOrReply(t *testing.T) {
	fx := newBFTNetworkFixture(t)
	payload := []byte("fake-client-write")
	fakeReqTS := time.Now().Add(time.Hour).UnixNano()

	var queue []*pb.Message
	for _, backupID := range []uint64{2, 3, 4} {
		pp := makeFakeClientPrePrepareFromPrimary(t, fx, backupID, 1, payload, fakeReqTS, 100, int64(100+backupID))
		err := fx.nodes[backupID].Step(fx.ctx, pp)
		require.Error(t, err)
	}

	replies := routeByzantineTestMessagesAmongBackups(t, fx, queue)

	key := bftSeqKey{view: 0, seq: 1}
	for _, backupID := range []uint64{2, 3, 4} {
		require.NotContains(t, fx.nodes[backupID].log, key, "backup %d replicated a fake client request", backupID)
	}
	require.Empty(t, replies, "honest backups must not reply to a fake request invented by the primary")
}
