package raft

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBFTNode_PendingRequestExpiresIntoViewChange(t *testing.T) {
	node, client, _, _ := setupCluster(t)
	ctx := context.Background()

	require.Equal(t, Normal, node.nodePhase)

	err := client.Propose(ctx, []byte("expires-into-view-change"))
	require.NoError(t, err)

	clientMsg := <-client.Ready()
	err = node.Step(ctx, clientMsg)
	require.NoError(t, err)

	// Drain the PRE-PREPARE batch created by Step().
	rd := <-node.Ready()
	require.Len(t, rd.Messages, 3)
	node.Advance()

	node.mu.Lock()
	require.True(t, node.timer.timer_on)
	require.Equal(t, uint64(0), node.timer.timer)
	require.Equal(t, uint64(100), node.timer.expiry_const)
	require.Equal(t, []uint64{1}, node.pending)
	node.mu.Unlock()

	for i := 0; i < 100; i++ {
		node.Tick()
		require.Equal(t, Normal, node.nodePhase, "tick %d expired too early", i+1)
	}

	node.mu.Lock()
	require.True(t, node.timer.timer_on)
	require.Equal(t, uint64(100), node.timer.timer)
	node.mu.Unlock()

	// Tick 101 expires because PendingTimer.Tick uses timer > expiry_const.
	node.Tick()

	require.Equal(t, ViewChange, node.nodePhase)

	rd = <-node.Ready()
	require.Len(t, rd.Messages, 3)
	node.Advance()

	for _, m := range rd.Messages {
		require.Equal(t, uint64(1), m.GetFrom())
		require.NotZero(t, m.GetTo())

		_, origCtx, err := VerifyBFTMessageSignature(m, node.nodePubKeys[1])
		require.NoError(t, err)

		bctx, err := decodeBFTContext(origCtx)
		require.NoError(t, err)
		require.Equal(t, PhaseViewChange, bctx.Phase)
		require.Equal(t, uint64(1), bctx.View)
		require.Equal(t, uint64(0), bctx.CheckpointSeqNum)
		require.Empty(t, bctx.CheckpointProofs)
	}

	node.mu.Lock()
	require.False(t, node.timer.timer_on)
	require.Equal(t, uint64(0), node.timer.timer)
	require.Empty(t, node.pending)
	node.mu.Unlock()
}
