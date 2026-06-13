package raft

import (
	"errors"
)

type RingQueue[T any] struct {
	buf      []T
	head     uint64
	tail     uint64
	size     uint64
	capacity uint64
}

func NewRingQueue[T any](capacity uint64) *RingQueue[T] {
	return &RingQueue[T]{
		buf:      make([]T, capacity),
		capacity: capacity,
		head:     0,
		tail:     0,
		size:     0,
	}
}

func (q *RingQueue[T]) Enqueue(v T) error {
	if q.size == q.capacity {
		return errors.New("Queue is full")
	}

	q.buf[q.tail] = v
	q.tail = (q.tail + 1) % q.capacity
	q.size++
	return nil
}

func (q *RingQueue[T]) Peek(i uint64) (T, error) {
	if q.size == 0 {
		var zero T
		return zero, errors.New("Queue is empty")
	}

	if i >= q.size {
		var zero T
		return zero, errors.New("index is past length")
	}

	v := q.buf[(q.head+i)%q.capacity]
	return v, nil
}

func (q *RingQueue[T]) Dequeue() (T, error) {
	if q.size == 0 {
		var zero T
		return zero, errors.New("Queue is empty")
	}

	v := q.buf[q.head]
	q.head = (q.head + 1) % q.capacity
	q.size--
	return v, nil
}

func (q *RingQueue[T]) Len() uint64 {
	return q.size
}

func (q *RingQueue[T]) Cap() uint64 {
	return q.capacity
}

func (q *RingQueue[T]) Empty() bool {
	return q.size == 0
}

func (q *RingQueue[T]) Full() bool {
	return q.size == q.capacity
}

func (q *RingQueue[T]) Clear() {
	q.head = 0
	q.tail = 0
	q.size = 0
}

type PendingTimer struct {
	timer_on bool
	timer    uint64

	base_expiry  uint64
	expiry_const uint64
	max_expiry   uint64
	exp_attempt  uint64
}

func NewPendingTimer(expiryConst uint64) *PendingTimer {
	if expiryConst == 0 {
		expiryConst = 1
	}

	return &PendingTimer{
		timer_on:     false,
		timer:        0,
		base_expiry:  expiryConst,
		expiry_const: expiryConst,
		max_expiry:   expiryConst * 16,
		exp_attempt:  0,
	}
}

func (t *PendingTimer) Tick() bool {
	if !t.timer_on {
		return false
	}

	t.timer++
	if t.timer > t.expiry_const {
		t.Stop()
		return true
	}

	return false
}

func (t *PendingTimer) Reset() {
	t.timer_on = true
	t.timer = 0
}

func (t *PendingTimer) Start() {
	if !t.timer_on {
		t.timer_on = true
		t.timer = 0
	}
}

func (t *PendingTimer) StartExp() {
	if t.timer_on {
		return
	}

	expiry := t.base_expiry
	for i := uint64(0); i < t.exp_attempt; i++ {
		if expiry >= t.max_expiry/2 {
			expiry = t.max_expiry
			break
		}
		expiry *= 2
	}

	if expiry > t.max_expiry {
		expiry = t.max_expiry
	}

	t.expiry_const = expiry
	t.exp_attempt++
	t.timer_on = true
	t.timer = 0
}

func (t *PendingTimer) Stop() {
	t.timer_on = false
	t.timer = 0
}

func (t *PendingTimer) StopAndResetBackoff() {
	t.timer_on = false
	t.timer = 0
	t.expiry_const = t.base_expiry
	t.exp_attempt = 0
}

func (t *PendingTimer) isOn() bool {
	return t.timer_on
}
