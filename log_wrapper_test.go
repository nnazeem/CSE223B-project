// via cursor
package raft

import (
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/stretchr/testify/require"

	pb "go.etcd.io/raft/v3/raftpb"
)

func testLogWrapperNode(selfID uint64) *LogPVNode {
	return &LogPVNode{selfID: selfID}
}

func TestLogWrapperAttachAndVerifyPeerMessage(t *testing.T) {
	sender := testLogWrapperNode(1)
	receiver := testLogWrapperNode(2)

	m := pb.Message{
		Type:    pb.MsgApp,
		From:    1,
		To:      2,
		Context: []byte("orig"),
		Entries: []pb.Entry{
			{Index: 1, Term: 1, Data: []byte("a")},
			{Index: 2, Term: 1, Data: []byte("b")},
		},
	}

	signed := sender.attachMessageTree(m)
	require.NotEqual(t, []byte("orig"), signed.Context)

	in := proto.Clone(&signed).(*pb.Message)
	require.NoError(t, receiver.verifyMessageTree(in))
	require.Equal(t, []byte("orig"), in.Context)
}

func TestLogWrapperRejectsMismatchedHash(t *testing.T) {
	sender := testLogWrapperNode(1)
	receiver := testLogWrapperNode(2)

	m := pb.Message{
		Type: pb.MsgApp, From: 1, To: 2,
		Entries: []pb.Entry{{Index: 1, Term: 1, Data: []byte("x")}},
	}

	out := sender.attachMessageTree(m)
	in := proto.Clone(&out).(*pb.Message)
	in.Entries[0].Data = []byte("tampered")

	err := receiver.verifyMessageTree(in)
	require.ErrorIs(t, err, ErrInvalidLog)
}

func TestLogWrapperRejectsMalformedContext(t *testing.T) {
	receiver := testLogWrapperNode(2)
	m := &pb.Message{
		Type:    pb.MsgApp,
		From:    1,
		To:      2,
		Context: []byte("bad-context"),
		Entries: []pb.Entry{{Index: 1, Term: 1, Data: []byte("x")}},
	}
	err := receiver.verifyMessageTree(m)
	require.ErrorIs(t, err, ErrInvalidLogContext)
}

func TestLogWrapperSkipsVerificationForEmptyEntries(t *testing.T) {
	receiver := testLogWrapperNode(2)
	m := &pb.Message{
		Type:    pb.MsgHeartbeat,
		From:    1,
		To:      2,
		Context: []byte("no-proof-needed"),
	}
	require.NoError(t, receiver.verifyMessageTree(m))
	require.Equal(t, []byte("no-proof-needed"), m.Context)
}

func TestLogWrapperRecursivelyProcessesResponses(t *testing.T) {
	sender := testLogWrapperNode(1)
	receiver := testLogWrapperNode(2)

	m := pb.Message{
		Type: pb.MsgApp, From: 1, To: 2,
		Entries: []pb.Entry{{Index: 1, Term: 1, Data: []byte("root")}},
		Responses: []pb.Message{
			{
				Type:    pb.MsgAppResp,
				From:    1,
				To:      2,
				Context: []byte("nested"),
				Entries: []pb.Entry{{Index: 2, Term: 1, Data: []byte("nested-entry")}},
			},
		},
	}

	out := sender.attachMessageTree(m)
	in := proto.Clone(&out).(*pb.Message)
	require.NoError(t, receiver.verifyMessageTree(in))
	require.Equal(t, []byte("nested"), in.Responses[0].Context)
}

func TestLogWrapperLogHashUpdatesAsEntriesAreAdded(t *testing.T) {
	ln := testLogWrapperNode(1)
	var zero [hashSize]byte

	msg1 := pb.Message{
		Type:    pb.MsgStorageAppend,
		From:    1,
		To:      LocalAppendThread,
		Entries: []pb.Entry{{Index: 1, Term: 1, Data: []byte("first")}},
	}
	ln.updateHashFromStorageMessages([]pb.Message{msg1})
	expected1 := iterativeEntriesHash(zero, msg1.Entries)
	require.Equal(t, expected1, ln.logHash)
	require.NotEqual(t, zero, ln.logHash)

	msg2 := pb.Message{
		Type:    pb.MsgStorageAppend,
		From:    1,
		To:      LocalAppendThread,
		Entries: []pb.Entry{{Index: 2, Term: 1, Data: []byte("second")}},
	}
	ln.updateHashFromStorageMessages([]pb.Message{msg2})
	expected2 := iterativeEntriesHash(expected1, msg2.Entries)
	require.Equal(t, expected2, ln.logHash)
	require.NotEqual(t, expected1, ln.logHash)
}

func TestLogWrapperInitFromNonEmptyLogIsConsistent(t *testing.T) {
	existing := []pb.Entry{
		{Index: 1, Term: 1, Data: []byte("old-1")},
		{Index: 2, Term: 1, Data: []byte("old-2")},
	}

	sender := testLogWrapperNode(1)
	receiver := testLogWrapperNode(2)
	sender.InitFromEntries(existing)
	receiver.InitFromEntries(existing)
	var zero [hashSize]byte
	base := iterativeEntriesHash(zero, existing)

	msg := pb.Message{
		Type:    pb.MsgApp,
		From:    1,
		To:      2,
		Entries: []pb.Entry{{Index: 3, Term: 2, Data: []byte("new")}},
	}
	out := sender.attachMessageTree(msg)
	in := proto.Clone(&out).(*pb.Message)
	require.NoError(t, receiver.verifyMessageTree(in))
	require.Equal(t, base, sender.logHash)
	require.Equal(t, base, receiver.logHash)

	storageUpdate := pb.Message{
		Type:    pb.MsgStorageAppend,
		From:    1,
		To:      LocalAppendThread,
		Entries: msg.Entries,
	}
	sender.updateHashFromStorageMessages([]pb.Message{storageUpdate})
	receiver.updateHashFromStorageMessages([]pb.Message{storageUpdate})

	expected := iterativeEntriesHash(base, msg.Entries)
	require.Equal(t, expected, sender.logHash)
	require.Equal(t, expected, receiver.logHash)
}
