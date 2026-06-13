package raft

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPendingTimer_StartExpBacksOffAndResetClearsBackoff(t *testing.T) {
	timer := NewPendingTimer(10)

	timer.StartExp()
	require.Equal(t, uint64(10), timer.expiry_const)
	timer.Stop()

	timer.StartExp()
	require.Equal(t, uint64(20), timer.expiry_const)
	timer.Stop()

	timer.StartExp()
	require.Equal(t, uint64(40), timer.expiry_const)
	timer.Stop()

	timer.StopAndResetBackoff()
	require.Equal(t, uint64(10), timer.expiry_const)

	timer.StartExp()
	require.Equal(t, uint64(10), timer.expiry_const)
}

func TestPendingTimer_StartExpCapsAtMaxExpiry(t *testing.T) {
	timer := NewPendingTimer(10)

	for i := 0; i < 20; i++ {
		timer.StartExp()
		timer.Stop()
	}

	require.Equal(t, timer.max_expiry, timer.expiry_const)
	require.Equal(t, uint64(160), timer.max_expiry)
}
