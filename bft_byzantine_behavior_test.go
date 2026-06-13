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

func TestBFTByzantine_ReplicasCannotCommitGhostEntryWithoutPrePrepare(t *testing.T) {
	fx := newBFTNetworkFixture(t)
	seq := uint64(1)
	ghostPayload := []byte("ghost-entry-never-requested")
	ghostDigest := entryDigest(t, ghostPayload)
	target := fx.nodes[4]
	key := bftSeqKey{view: 0, seq: seq}

	// Two Byzantine replicas try to manufacture a prepared certificate and a
	// commit certificate for a sequence number this honest replica never accepted
	// via PRE-PREPARE. The honest replica must reject every phase because bn.pp
	// has no accepted digest for (view, seq).
	for _, from := range []uint64{2, 3} {
		prepare := makePhaseMessageForNetworkTest(t, PhasePrepare, from, seq, ghostDigest)
		signTestNodeMessage(t, prepare, fx.nodePrivs[from], int64(100+from))

		err := target.Step(fx.ctx, prepare)
		require.ErrorContains(t, err, "prepare does not match accepted pre-prepare")
	}

	for _, from := range []uint64{2, 3} {
		commit := makePhaseMessageForNetworkTest(t, PhaseCommit, from, seq, ghostDigest)
		signTestNodeMessage(t, commit, fx.nodePrivs[from], int64(200+from))

		err := target.Step(fx.ctx, commit)
		require.ErrorContains(t, err, "commit does not match accepted pre-prepare")
	}

	require.NotContains(t, target.pp, key)
	require.NotContains(t, target.prepares, key)
	require.NotContains(t, target.commits, key)
	require.NotContains(t, target.reqs, key)
	require.NotContains(t, target.log, seq)
	require.Empty(t, drainNodeReadyIfAny(t, target), "honest replica must not emit PBFT traffic or replies for a ghost entry")
}

func TestBFTByzantine_ReplicasCannotCommitDifferentEntryThanAcceptedPrePrepare(t *testing.T) {
	fx := newBFTNetworkFixture(t)
	target := fx.nodes[4]
	seq := uint64(1)
	clientID := uint64(100)
	requestTS := int64(1000)

	acceptedPayload := []byte("client-request-that-did-happen")
	acceptedPP, acceptedDigest := makePrePrepareForNetworkTest(t, fx, 1, seq, acceptedPayload, requestTS, clientID)
	signTestNodeMessage(t, acceptedPP, fx.nodePrivs[1], 1100)
	require.NoError(t, target.Step(fx.ctx, acceptedPP))
	_ = drainNodeReadyMessages(t, target)

	forgedPayload := []byte("byzantine-entry-that-did-not-happen")
	forgedDigest := entryDigest(t, forgedPayload)
	require.NotEqual(t, acceptedDigest, forgedDigest)

	// Byzantine replicas try to move the accepted sequence to a different digest.
	// The honest replica must reject both PREPARE and COMMIT because they do not
	// match the digest accepted from the primary's PRE-PREPARE.
	for _, from := range []uint64{2, 3} {
		prepare := makePhaseMessageForNetworkTest(t, PhasePrepare, from, seq, forgedDigest)
		signTestNodeMessage(t, prepare, fx.nodePrivs[from], int64(1200+from))

		err := target.Step(fx.ctx, prepare)
		require.ErrorContains(t, err, "prepare does not match accepted pre-prepare")
	}

	for _, from := range []uint64{2, 3} {
		commit := makePhaseMessageForNetworkTest(t, PhaseCommit, from, seq, forgedDigest)
		signTestNodeMessage(t, commit, fx.nodePrivs[from], int64(1300+from))

		err := target.Step(fx.ctx, commit)
		require.ErrorContains(t, err, "commit does not match accepted pre-prepare")
	}

	key := bftSeqKey{view: 0, seq: seq}
	require.Equal(t, acceptedDigest, target.pp[key])
	require.NotContains(t, target.log, seq)
	require.Empty(t, drainNodeReadyIfAny(t, target), "honest replica must not reply or commit a forged digest")
}

func TestBFTByzantine_PrimaryCannotCommitEntryBeforeFullPBFTReplication(t *testing.T) {
	fx := newBFTNetworkFixture(t)
	target := fx.nodes[2]
	seq := uint64(1)
	clientID := uint64(100)
	requestTS := int64(10_000)
	payload := []byte("entry-primary-tries-to-shortcut")

	// The primary sends a valid PRE-PREPARE, so the backup accepts the request
	// and emits its own PREPARE. At this point the backup has only:
	//   1. the primary's PRE-PREPARE evidence
	//   2. its own PREPARE evidence
	// For n=4, f=1, this is not a prepared certificate yet; it still needs one
	// additional matching PREPARE from another backup before COMMIT is valid.
	pp, digest := makePrePrepareForNetworkTest(t, fx, 1, seq, payload, requestTS, clientID)
	signTestNodeMessage(t, pp, fx.nodePrivs[1], 11_000)
	require.NoError(t, target.Step(fx.ctx, pp))
	prepareOut := drainNodeReadyMessages(t, target)
	require.NotEmpty(t, prepareOut)

	key := bftSeqKey{view: 0, seq: seq}
	require.Equal(t, digest, target.pp[key])
	require.Len(t, target.prepares[key], 2, "backup should have only primary PRE-PREPARE plus its own PREPARE")
	require.NotContains(t, target.commits, key)
	require.NotContains(t, target.log, seq)

	// Byzantine primary now tries to skip the rest of PBFT by sending COMMIT
	// directly, before the backup has observed 2f+1 prepare evidence.
	commitFromPrimary := makePhaseMessageForNetworkTest(t, PhaseCommit, 1, seq, digest)
	commitFromPrimary.To = u64p(2)
	signTestNodeMessage(t, commitFromPrimary, fx.nodePrivs[1], 12_000)

	err := target.Step(fx.ctx, commitFromPrimary)
	require.ErrorContains(t, err, "commit before prepared certificate")

	// Even if a second Byzantine replica joins the shortcut attempt, the honest
	// backup must continue rejecting COMMITs until the prepare certificate exists.
	commitFromByzantineBackup := makePhaseMessageForNetworkTest(t, PhaseCommit, 3, seq, digest)
	commitFromByzantineBackup.To = u64p(2)
	signTestNodeMessage(t, commitFromByzantineBackup, fx.nodePrivs[3], 12_001)

	err = target.Step(fx.ctx, commitFromByzantineBackup)
	require.ErrorContains(t, err, "commit before prepared certificate")

	require.Equal(t, digest, target.pp[key])
	require.Len(t, target.prepares[key], 2, "rejecting early COMMIT must not manufacture prepare evidence")
	require.NotContains(t, target.commits, key, "early COMMITs must not be recorded before prepared certificate")
	require.NotContains(t, target.log, seq, "entry must not reach the local PBFT log without full PBFT replication")
	require.Empty(t, drainNodeReadyIfAny(t, target), "honest backup must not emit COMMIT, Raft proposal, or client reply")
}

func makeClientReplyForByzantineTest(
	t *testing.T,
	from uint64,
	to uint64,
	requestTS int64,
	clientID uint64,
	result []byte,
	priv ed25519.PrivateKey,
	signTS int64,
) *pb.Message {
	t.Helper()

	bctx := BFTContext{
		Phase:            PhaseReply,
		View:             0,
		RequestTimestamp: requestTS,
		ClientID:         clientID,
		Result:           append([]byte(nil), result...),
	}
	encCtx, err := encodeBFTContext(bctx)
	require.NoError(t, err)

	m := &pb.Message{
		Type:    pb.MsgApp.Enum(),
		From:    u64p(from),
		To:      u64p(to),
		Context: encCtx,
	}
	signTestNodeMessage(t, m, priv, signTS)
	return m
}

func TestBFTByzantine_ClientRejectsRepliesWithoutFullPBFTReplicationQuorum(t *testing.T) {
	fx := newBFTNetworkFixture(t)
	payload := []byte("request-that-never-reaches-pbft-commit")

	require.NoError(t, fx.client.Propose(fx.ctx, payload))

	var reqTS int64
	for ts := range fx.client.pending {
		reqTS = ts
	}
	require.NotZero(t, reqTS)

	key := bftSeqKey{view: 0, seq: 1}
	for id := uint64(1); id <= 4; id++ {
		require.NotContains(t, fx.nodes[id].log, uint64(1))
		require.NotContains(t, fx.nodes[id].commits, key)
	}

	// A single Byzantine replica can lie and send a syntactically valid REPLY for
	// the client's pending request, even though no replica has committed or logged
	// the request. With n=4,f=1, this must not be enough: the client needs f+1 == 2
	// matching replies from distinct replicas.
	byzReply := makeClientReplyForByzantineTest(
		t,
		1,
		fx.client.selfID,
		reqTS,
		fx.client.selfID,
		[]byte("OK"),
		fx.nodePrivs[1],
		20_000,
	)
	require.NoError(t, fx.client.Step(fx.ctx, proto.Clone(byzReply).(*pb.Message)))

	select {
	case result := <-fx.client.ConsensusC:
		t.Fatalf("client accepted one Byzantine reply without PBFT replication: %q", string(result))
	case <-time.After(50 * time.Millisecond):
	}
	require.Contains(t, fx.client.pending, reqTS)

	// Duplicating the same Byzantine replica's reply must not count as another
	// replica vote, because replies are indexed by sender id.
	require.NoError(t, fx.client.Step(fx.ctx, proto.Clone(byzReply).(*pb.Message)))

	select {
	case result := <-fx.client.ConsensusC:
		t.Fatalf("client counted duplicate Byzantine replies as a quorum: %q", string(result))
	case <-time.After(50 * time.Millisecond):
	}
	require.Contains(t, fx.client.pending, reqTS)

	// A Byzantine sender cannot pretend to be a different replica unless it has
	// that replica's private key. This forged reply claims From=2 but is signed by
	// node 1, so client-side signature verification must reject it.
	forgedSecondReply := makeClientReplyForByzantineTest(
		t,
		2,
		fx.client.selfID,
		reqTS,
		fx.client.selfID,
		[]byte("OK"),
		fx.nodePrivs[1],
		20_001,
	)
	err := fx.client.Step(fx.ctx, forgedSecondReply)
	require.ErrorIs(t, err, ErrInvalidSignature)

	select {
	case result := <-fx.client.ConsensusC:
		t.Fatalf("client accepted a forged second reply without PBFT replication: %q", string(result))
	case <-time.After(50 * time.Millisecond):
	}
	require.Contains(t, fx.client.pending, reqTS)

	// Replies for a timestamp the client did not request must be ignored even if
	// they are signed by real replica keys. They cannot complete the pending
	// request's reply certificate.
	wrongTS := reqTS + 1_000_000
	for _, from := range []uint64{2, 3} {
		wrongTimestampReply := makeClientReplyForByzantineTest(
			t,
			from,
			fx.client.selfID,
			wrongTS,
			fx.client.selfID,
			[]byte("OK"),
			fx.nodePrivs[from],
			20_100+int64(from),
		)
		require.NoError(t, fx.client.Step(fx.ctx, wrongTimestampReply))
	}

	select {
	case result := <-fx.client.ConsensusC:
		t.Fatalf("client accepted replies for a non-pending timestamp: %q", string(result))
	case <-time.After(50 * time.Millisecond):
	}
	require.Contains(t, fx.client.pending, reqTS)

	for id := uint64(1); id <= 4; id++ {
		require.NotContains(t, fx.nodes[id].log, uint64(1), "node %d logged an entry without full PBFT replication", id)
		require.NotContains(t, fx.nodes[id].commits, key, "node %d recorded commits without full PBFT replication", id)
	}
}

func TestBFTByzantine_NonPrimariesCannotMakeHonestReplicaLoseCommittedLogEntry(t *testing.T) {
	fx := newBFTNetworkFixture(t)
	target := fx.nodes[4]
	seq := uint64(1)
	key := bftSeqKey{view: 0, seq: seq}
	clientID := uint64(100)
	requestTS := int64(30_000)
	payload := []byte("entry-that-must-not-be-lost")

	// First drive the honest replica through the real PBFT path for seq=1:
	// PRE-PREPARE from the primary, enough PREPARE evidence, and enough COMMIT
	// evidence. This establishes a real local PBFT log entry.
	pp, digest := makePrePrepareForNetworkTest(t, fx, 1, seq, payload, requestTS, clientID)
	pp.To = u64p(target.selfID)
	signTestNodeMessage(t, pp, fx.nodePrivs[1], 30_100)
	require.NoError(t, target.Step(fx.ctx, pp))
	_ = drainNodeReadyMessages(t, target)

	for _, from := range []uint64{2, 3} {
		prepare := makePhaseMessageForNetworkTest(t, PhasePrepare, from, seq, digest)
		prepare.To = u64p(target.selfID)
		signTestNodeMessage(t, prepare, fx.nodePrivs[from], 30_200+int64(from))
		require.NoError(t, target.Step(fx.ctx, prepare))
		_ = drainNodeReadyIfAny(t, target)
	}

	for _, from := range []uint64{2, 3} {
		commit := makePhaseMessageForNetworkTest(t, PhaseCommit, from, seq, digest)
		commit.To = u64p(target.selfID)
		signTestNodeMessage(t, commit, fx.nodePrivs[from], 30_300+int64(from))
		require.NoError(t, target.Step(fx.ctx, commit))
		_ = drainNodeReadyIfAny(t, target)
	}

	require.Contains(t, target.log, seq)
	require.Equal(t, payload, target.log[seq].GetEntries()[0].GetData())
	require.Equal(t, digest, target.pp[key])
	require.Contains(t, target.commits, key)

	// Byzantine non-primaries now try to make the honest replica move seq=1 to a
	// different value. A non-primary PRE-PREPARE must be rejected before it can
	// overwrite the accepted digest or request buffer.
	forgedPayload := []byte("byzantine-non-primary-overwrite")
	forgedPP, forgedDigest := makePrePrepareForNetworkTest(t, fx, 2, seq, forgedPayload, requestTS+1, clientID)
	forgedPP.To = u64p(target.selfID)
	signTestNodeMessage(t, forgedPP, fx.nodePrivs[2], 30_400)

	err := target.Step(fx.ctx, forgedPP)
	require.ErrorContains(t, err, "pre-prepare from non-primary")
	require.NotEqual(t, digest, forgedDigest)

	// Byzantine non-primaries also cannot replace or erase the committed entry by
	// sending conflicting PREPARE/COMMIT certificates for another digest.
	for _, from := range []uint64{2, 3} {
		badPrepare := makePhaseMessageForNetworkTest(t, PhasePrepare, from, seq, forgedDigest)
		badPrepare.To = u64p(target.selfID)
		signTestNodeMessage(t, badPrepare, fx.nodePrivs[from], 30_500+int64(from))

		err := target.Step(fx.ctx, badPrepare)
		require.ErrorContains(t, err, "prepare does not match accepted pre-prepare")
	}

	for _, from := range []uint64{2, 3} {
		badCommit := makePhaseMessageForNetworkTest(t, PhaseCommit, from, seq, forgedDigest)
		badCommit.To = u64p(target.selfID)
		signTestNodeMessage(t, badCommit, fx.nodePrivs[from], 30_600+int64(from))

		err := target.Step(fx.ctx, badCommit)
		require.ErrorContains(t, err, "commit does not match accepted pre-prepare")
	}

	// Finally, Byzantine non-primaries try bogus checkpoints for the same seq.
	// Checkpoints with a digest that does not match the local executed log must be
	// ignored and must not prune or modify the committed log entry.
	badCheckpointDigest := hashData([]byte("bogus-checkpoint-digest"))
	for _, from := range []uint64{2, 3} {
		bctx := BFTContext{
			Phase:            PhaseCheckpoint,
			View:             0,
			SeqNum:           seq,
			Digest:           badCheckpointDigest,
			CheckpointSeqNum: seq,
			CheckpointDigest: badCheckpointDigest,
		}
		encCtx, err := encodeBFTContext(bctx)
		require.NoError(t, err)

		checkpoint := &pb.Message{
			Type:    pb.MsgApp.Enum(),
			From:    u64p(from),
			To:      u64p(target.selfID),
			Context: encCtx,
		}
		signTestNodeMessage(t, checkpoint, fx.nodePrivs[from], 30_700+int64(from))
		require.NoError(t, target.Step(fx.ctx, checkpoint))
	}

	require.Contains(t, target.log, seq, "committed entry disappeared from the honest replica log")
	require.Equal(t, payload, target.log[seq].GetEntries()[0].GetData(), "committed entry payload changed")
	require.Equal(t, digest, target.pp[key], "accepted digest changed after Byzantine non-primary traffic")
	require.Contains(t, target.reqs, key, "request buffer for committed entry was unexpectedly removed")
	require.NotContains(t, target.checkpoints[seq], badCheckpointDigest, "bogus checkpoint digest should not be recorded")
}

func TestBFTByzantine_PrimaryCannotMakeHonestReplicaLoseCommittedLogEntry(t *testing.T) {
	fx := newBFTNetworkFixture(t)
	target := fx.nodes[4]
	seq := uint64(1)
	key := bftSeqKey{view: 0, seq: seq}
	clientID := uint64(100)
	requestTS := int64(40_000)
	payload := []byte("entry-that-primary-must-not-erase")

	// First establish a real committed local PBFT log entry on the honest target.
	// This goes through the complete normal path for this replica: primary
	// PRE-PREPARE, enough matching PREPARE evidence, and enough matching COMMIT
	// evidence.
	pp, digest := makePrePrepareForNetworkTest(t, fx, 1, seq, payload, requestTS, clientID)
	pp.To = u64p(target.selfID)
	signTestNodeMessage(t, pp, fx.nodePrivs[1], 40_100)
	require.NoError(t, target.Step(fx.ctx, pp))
	_ = drainNodeReadyMessages(t, target)

	for _, from := range []uint64{2, 3} {
		prepare := makePhaseMessageForNetworkTest(t, PhasePrepare, from, seq, digest)
		prepare.To = u64p(target.selfID)
		signTestNodeMessage(t, prepare, fx.nodePrivs[from], 40_200+int64(from))
		require.NoError(t, target.Step(fx.ctx, prepare))
		_ = drainNodeReadyIfAny(t, target)
	}

	for _, from := range []uint64{2, 3} {
		commit := makePhaseMessageForNetworkTest(t, PhaseCommit, from, seq, digest)
		commit.To = u64p(target.selfID)
		signTestNodeMessage(t, commit, fx.nodePrivs[from], 40_300+int64(from))
		require.NoError(t, target.Step(fx.ctx, commit))
		_ = drainNodeReadyIfAny(t, target)
	}

	require.Contains(t, target.log, seq)
	require.Equal(t, payload, target.log[seq].GetEntries()[0].GetData())
	require.Equal(t, digest, target.pp[key])
	require.Contains(t, target.reqs, key)
	require.Contains(t, target.commits, key)

	// The Byzantine primary now tries to overwrite the already accepted sequence
	// with a different valid client request. Because the honest replica already
	// accepted a digest for (view=0, seq=1), the conflicting PRE-PREPARE must be
	// rejected and must not replace pp/reqs/log.
	forgedPayload := []byte("primary-forged-overwrite-after-commit")
	forgedPP, forgedDigest := makePrePrepareForNetworkTest(t, fx, 1, seq, forgedPayload, requestTS+1, clientID)
	forgedPP.To = u64p(target.selfID)
	signTestNodeMessage(t, forgedPP, fx.nodePrivs[1], 40_400)
	require.NotEqual(t, digest, forgedDigest)

	err := target.Step(fx.ctx, forgedPP)
	require.ErrorContains(t, err, "conflicting pre-prepare digest")

	// The primary is not allowed to manufacture PREPARE evidence for its own value.
	// A primary PREPARE must be rejected and must not affect the committed entry.
	primaryPrepare := makePhaseMessageForNetworkTest(t, PhasePrepare, 1, seq, forgedDigest)
	primaryPrepare.To = u64p(target.selfID)
	signTestNodeMessage(t, primaryPrepare, fx.nodePrivs[1], 40_500)
	err = target.Step(fx.ctx, primaryPrepare)
	require.ErrorContains(t, err, "prepare does not match accepted pre-prepare")

	// A primary COMMIT for the forged digest also cannot move or delete the log,
	// because it does not match the digest this replica accepted and committed.
	primaryBadCommit := makePhaseMessageForNetworkTest(t, PhaseCommit, 1, seq, forgedDigest)
	primaryBadCommit.To = u64p(target.selfID)
	signTestNodeMessage(t, primaryBadCommit, fx.nodePrivs[1], 40_600)
	err = target.Step(fx.ctx, primaryBadCommit)
	require.ErrorContains(t, err, "commit does not match accepted pre-prepare")

	// The Byzantine primary may also try checkpoint traffic to trigger pruning or
	// state replacement. A bad checkpoint digest must be ignored; a single correct
	// checkpoint proof from only the primary is not enough to stabilize a checkpoint
	// or garbage-collect the committed log entry.
	badCheckpointDigest := hashData([]byte("primary-bogus-checkpoint-digest"))
	badCheckpointCtx := BFTContext{
		Phase:            PhaseCheckpoint,
		View:             0,
		SeqNum:           seq,
		Digest:           badCheckpointDigest,
		CheckpointSeqNum: seq,
		CheckpointDigest: badCheckpointDigest,
	}
	badCheckpointEnc, err := encodeBFTContext(badCheckpointCtx)
	require.NoError(t, err)
	badCheckpoint := &pb.Message{
		Type:    pb.MsgApp.Enum(),
		From:    u64p(1),
		To:      u64p(target.selfID),
		Context: badCheckpointEnc,
	}
	signTestNodeMessage(t, badCheckpoint, fx.nodePrivs[1], 40_700)
	require.NoError(t, target.Step(fx.ctx, badCheckpoint))

	localDigest, ok := target.localCheckpointDigest(seq)
	require.True(t, ok)
	goodCheckpointCtx := BFTContext{
		Phase:            PhaseCheckpoint,
		View:             0,
		SeqNum:           seq,
		Digest:           localDigest,
		CheckpointSeqNum: seq,
		CheckpointDigest: localDigest,
	}
	goodCheckpointEnc, err := encodeBFTContext(goodCheckpointCtx)
	require.NoError(t, err)
	goodCheckpoint := &pb.Message{
		Type:    pb.MsgApp.Enum(),
		From:    u64p(1),
		To:      u64p(target.selfID),
		Context: goodCheckpointEnc,
	}
	signTestNodeMessage(t, goodCheckpoint, fx.nodePrivs[1], 40_800)
	require.NoError(t, target.Step(fx.ctx, goodCheckpoint))

	require.Contains(t, target.log, seq, "committed entry disappeared after Byzantine primary traffic")
	require.Equal(t, payload, target.log[seq].GetEntries()[0].GetData(), "committed entry payload changed")
	require.Equal(t, digest, target.pp[key], "accepted digest changed after Byzantine primary traffic")
	require.Contains(t, target.reqs, key, "request buffer for committed entry was unexpectedly removed")
	require.Contains(t, target.commits, key, "commit certificate state was unexpectedly removed")
	require.NotContains(t, target.checkpoints[seq], badCheckpointDigest, "bad checkpoint digest should not be recorded")
	require.Nil(t, target.stableCheckpoint, "one Byzantine primary checkpoint must not stabilize or prune state")
}

func TestBFTByzantine_PrimaryCannotMakeHonestReplicaCommitOutOfOrder(t *testing.T) {
	fx := newBFTNetworkFixture(t)
	target := fx.nodes[2]
	clientID := uint64(100)

	seqOne := uint64(1)
	seqTwo := uint64(2)
	seqTwoKey := bftSeqKey{view: 0, seq: seqTwo}
	payloadTwo := []byte("second-entry-primary-tries-to-execute-first")
	requestTSTwo := int64(50_002)

	// A Byzantine primary skips sequence 1 and starts by proposing sequence 2.
	// Even if the rest of the PBFT evidence for sequence 2 is syntactically valid,
	// an honest replica must not execute or expose log[2] before log[1] exists.
	ppTwo, digestTwo := makePrePrepareForNetworkTest(t, fx, 1, seqTwo, payloadTwo, requestTSTwo, clientID)
	ppTwo.To = u64p(target.selfID)
	signTestNodeMessage(t, ppTwo, fx.nodePrivs[1], 50_100)
	require.NoError(t, target.Step(fx.ctx, ppTwo))
	_ = drainNodeReadyMessages(t, target)

	prepareTwo := makePhaseMessageForNetworkTest(t, PhasePrepare, 3, seqTwo, digestTwo)
	prepareTwo.To = u64p(target.selfID)
	signTestNodeMessage(t, prepareTwo, fx.nodePrivs[3], 50_200)
	require.NoError(t, target.Step(fx.ctx, prepareTwo))
	_ = drainNodeReadyIfAny(t, target)

	for _, from := range []uint64{1, 3} {
		commitTwo := makePhaseMessageForNetworkTest(t, PhaseCommit, from, seqTwo, digestTwo)
		commitTwo.To = u64p(target.selfID)
		signTestNodeMessage(t, commitTwo, fx.nodePrivs[from], 50_300+int64(from))
		require.NoError(t, target.Step(fx.ctx, commitTwo))
		_ = drainNodeReadyIfAny(t, target)
	}

	require.NotContains(t, target.log, seqOne, "test setup should not have committed sequence 1")
	require.NotContains(t, target.log, seqTwo, "honest replica must not execute sequence 2 before sequence 1")
	require.Equal(t, uint64(0), target.last_replied, "client-visible execution order must not advance past the missing sequence 1")
	require.Equal(t, digestTwo, target.pp[seqTwoKey], "replica may remember the accepted seq=2 digest while waiting for seq=1")
	require.Contains(t, target.commits, seqTwoKey, "replica may buffer the seq=2 commit certificate, but must not execute it out of order")
}

func TestBFTByzantine_NonPrimaryCannotCauseAcceptanceByAnsweringPhasesWithoutLocalLog(t *testing.T) {
	fx := newBFTNetworkFixture(t)
	target := fx.nodes[4]
	faultyID := uint64(3)
	seq := uint64(1)
	key := bftSeqKey{view: 0, seq: seq}
	clientID := uint64(100)
	payload := []byte("request-faulty-backup-answers-without-local-log")

	require.NoError(t, fx.client.Propose(fx.ctx, payload))
	var requestTS int64
	for ts := range fx.client.pending {
		requestTS = ts
	}
	require.NotZero(t, requestTS)

	// The honest target receives a valid PRE-PREPARE from the primary. The faulty
	// non-primary does not receive the PRE-PREPARE and therefore has no local PBFT
	// state/log entry for this sequence, but it will still try to answer later
	// phases as if it had participated correctly.
	pp, digest := makePrePrepareForNetworkTest(t, fx, 1, seq, payload, requestTS, clientID)
	pp.To = u64p(target.selfID)
	signTestNodeMessage(t, pp, fx.nodePrivs[1], 60_100)
	require.NoError(t, target.Step(fx.ctx, pp))
	_ = drainNodeReadyMessages(t, target)

	require.NotContains(t, fx.nodes[faultyID].pp, key)
	require.NotContains(t, fx.nodes[faultyID].reqs, key)
	require.NotContains(t, fx.nodes[faultyID].commits, key)
	require.NotContains(t, fx.nodes[faultyID].log, seq)

	// The faulty non-primary sends PREPARE without ever accepting/appending the
	// request locally. A single faulty phase response may help the honest target
	// reach the prepared threshold, but it must not by itself execute the entry or
	// create a client-visible result.
	faultyPrepare := makePhaseMessageForNetworkTest(t, PhasePrepare, faultyID, seq, digest)
	faultyPrepare.To = u64p(target.selfID)
	signTestNodeMessage(t, faultyPrepare, fx.nodePrivs[faultyID], 60_200)
	require.NoError(t, target.Step(fx.ctx, faultyPrepare))
	_ = drainNodeReadyIfAny(t, target)

	require.NotContains(t, target.log, seq)
	require.NotContains(t, fx.nodes[faultyID].log, seq)

	// The same faulty non-primary then sends COMMIT, still without having accepted
	// or executed the request locally. The honest target has at most its own COMMIT
	// plus the faulty COMMIT, which is below the 2f+1 commit threshold for n=4.
	faultyCommit := makePhaseMessageForNetworkTest(t, PhaseCommit, faultyID, seq, digest)
	faultyCommit.To = u64p(target.selfID)
	signTestNodeMessage(t, faultyCommit, fx.nodePrivs[faultyID], 60_300)
	require.NoError(t, target.Step(fx.ctx, faultyCommit))
	_ = drainNodeReadyIfAny(t, target)

	require.Contains(t, target.pp, key)
	require.Contains(t, target.prepares, key)
	require.Contains(t, target.commits, key)
	require.Less(t, uint64(len(target.commits[key])), 2*target.f+1)
	require.NotContains(t, target.log, seq, "faulty non-primary phase messages must not execute the entry without commit quorum")
	require.NotContains(t, fx.nodes[faultyID].log, seq, "faulty sender never appended/executed the entry locally")

	// Even if the faulty non-primary lies to the client with a syntactically valid
	// REPLY for the request timestamp, the client must not accept one reply from a
	// replica that did not go through the full PBFT replication path.
	byzReply := makeClientReplyForByzantineTest(
		t,
		faultyID,
		fx.client.selfID,
		requestTS,
		fx.client.selfID,
		[]byte("OK"),
		fx.nodePrivs[faultyID],
		60_400,
	)
	require.NoError(t, fx.client.Step(fx.ctx, byzReply))

	select {
	case result := <-fx.client.ConsensusC:
		t.Fatalf("client accepted a faulty non-primary reply without full PBFT replication: %q", string(result))
	case <-time.After(50 * time.Millisecond):
	}

	require.NotContains(t, target.log, seq)
	require.NotContains(t, fx.nodes[faultyID].log, seq)
}

func TestBFTByzantine_NonPrimaryCannotProposeClientRequestAsPrePrepare(t *testing.T) {
	fx := newBFTNetworkFixture(t)
	target := fx.nodes[4]
	nonPrimaryID := uint64(2)
	seq := uint64(1)
	clientID := uint64(100)
	payload := []byte("non-primary-tries-to-propose")

	reqTS := time.Now().UnixNano()
	clientReq := signClientRequestForTest(t, clientID, 1, payload, fx.client.priv, reqTS)
	digest, err := hashEntryBatch(clientReq.GetEntries())
	require.NoError(t, err)

	// Node 2 is a backup in view 0. It tries to behave like the primary by
	// sending a PRE-PREPARE for a valid client request. Even though the embedded
	// client request and digest are valid, honest replicas must reject it because
	// only primaryForView(0) == node 1 may propose PRE-PREPARE messages.
	bctx := BFTContext{
		Phase:            PhasePrePrepare,
		View:             0,
		SeqNum:           seq,
		Digest:           digest,
		RequestTimestamp: reqTS,
		ClientID:         clientID,
		ClientRequest:    *proto.Clone(clientReq).(*pb.Message),
	}
	encCtx, err := encodeBFTContext(bctx)
	require.NoError(t, err)

	ppFromBackup := &pb.Message{
		Type:    pb.MsgApp.Enum(),
		From:    u64p(nonPrimaryID),
		To:      u64p(target.selfID),
		Context: encCtx,
		Entries: cloneEntries(clientReq.GetEntries()),
	}
	signTestNodeMessage(t, ppFromBackup, fx.nodePrivs[nonPrimaryID], reqTS+1)

	err = target.Step(fx.ctx, ppFromBackup)
	require.ErrorContains(t, err, "pre-prepare from non-primary")

	key := bftSeqKey{view: 0, seq: seq}
	require.NotContains(t, target.pp, key)
	require.NotContains(t, target.reqs, key)
	require.NotContains(t, target.prepares, key)
	require.NotContains(t, target.commits, key)
	require.NotContains(t, target.log, seq)
	require.Empty(t, drainNodeReadyIfAny(t, target), "honest replica must not broadcast PREPARE for a non-primary PRE-PREPARE")
}

func TestBFTByzantine_SingleReplicaCannotForceViewChangeBySpammingViewChanges(t *testing.T) {
	fx := newBFTNetworkFixture(t)
	target := fx.nodes[3]
	faultyID := uint64(2)

	require.Equal(t, uint64(0), target.view)
	require.Equal(t, Normal, target.nodePhase)

	// A single Byzantine replica repeatedly asks for higher views. This must not
	// be treated as f+1 distinct replicas requesting a view change. For n=4,
	// f=1, an honest replica should require at least f+1 == 2 distinct replicas
	// before it leaves Normal because of observed VIEW-CHANGE traffic.
	for newView := uint64(1); newView <= 5; newView++ {
		vc := makeSignedViewChangeForByzantineTest(t, fx, faultyID, newView, int64(70_000+newView))
		err := target.Step(fx.ctx, proto.Clone(&vc).(*pb.Message))
		require.NoError(t, err)

		require.Equal(t, uint64(0), target.view, "one faulty replica must not advance the local view")
		require.Equal(t, Normal, target.nodePhase, "one faulty replica must not force the node into view-change mode")
		require.Empty(t, drainNodeReadyIfAny(t, target), "one faulty replica must not cause outbound VIEW-CHANGE traffic")
	}

	// The node may remember the spammed VIEW-CHANGE messages, but each view should
	// contain evidence from only the same single faulty replica, never a quorum.
	for newView := uint64(1); newView <= 5; newView++ {
		require.Len(t, target.vc[newView], 1)
		require.Contains(t, target.vc[newView], faultyID)
	}
}

func TestBFTByzantine_DuplicateViewChangeSpamFromSameReplicaDoesNotCountAsQuorum(t *testing.T) {
	fx := newBFTNetworkFixture(t)
	target := fx.nodes[3]
	faultyID := uint64(2)
	newView := uint64(1)

	for i := int64(0); i < 5; i++ {
		vc := makeSignedViewChangeForByzantineTest(t, fx, faultyID, newView, 80_000+i)
		err := target.Step(fx.ctx, proto.Clone(&vc).(*pb.Message))
		require.NoError(t, err)

		require.Equal(t, uint64(0), target.view)
		require.Equal(t, Normal, target.nodePhase)
		require.Len(t, target.vc[newView], 1)
		require.Contains(t, target.vc[newView], faultyID)
		require.Empty(t, drainNodeReadyIfAny(t, target))
	}
}

func TestBFTByzantine_SingleReplicaCannotRatchetViewsUpward(t *testing.T) {
	fx := newBFTNetworkFixture(t)
	target := fx.nodes[3]
	faultyID := uint64(2)

	requestedViews := []uint64{1, 2, 5, 10, 25, 100, 1_000}

	require.Equal(t, uint64(0), target.view)
	require.Equal(t, uint64(0), target.campaign_view)
	require.Equal(t, Normal, target.nodePhase)

	for i, newView := range requestedViews {
		vc := makeSignedViewChangeForByzantineTest(t, fx, faultyID, newView, int64(90_000+i))
		err := target.Step(fx.ctx, proto.Clone(&vc).(*pb.Message))
		require.NoError(t, err)

		require.Equal(t, uint64(0), target.view, "single faulty replica must not advance local view to %d", newView)
		require.Equal(t, uint64(0), target.campaign_view, "single faulty replica must not ratchet campaign view to %d", newView)
		require.Equal(t, Normal, target.nodePhase, "single faulty replica must not force view-change mode for view %d", newView)
		require.Empty(t, drainNodeReadyIfAny(t, target), "single faulty replica must not cause outbound view-change traffic for view %d", newView)
	}

	for _, newView := range requestedViews {
		require.Len(t, target.vc[newView], 1)
		require.Contains(t, target.vc[newView], faultyID)
	}
}
