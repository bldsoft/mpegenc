package utils

import "fmt"

type CommitToken uint64

type commitSlot[T any] struct {
	value T
	ready bool
}

type CommitQueue[T any] struct {
	slots []commitSlot[T]
	head  int
	first CommitToken
	next  CommitToken
}

func (q *CommitQueue[T]) Reserve() CommitToken {
	token := q.next
	q.next++
	q.slots = append(q.slots, commitSlot[T]{})
	return token
}

func (q *CommitQueue[T]) ReserveWith(value T) CommitToken {
	token := q.next
	q.next++
	q.slots = append(q.slots, commitSlot[T]{value: value})
	return token
}

func (q *CommitQueue[T]) PushReady(value T) CommitToken {
	token := q.Reserve()
	slot := &q.slots[len(q.slots)-1]
	slot.value = value
	slot.ready = true
	return token
}

func (q *CommitQueue[T]) Peek(token CommitToken) (T, error) {
	var zero T
	if token < q.first || token >= q.next {
		return zero, fmt.Errorf("commit queue: token %d is not pending", token)
	}
	slot := &q.slots[q.head+int(token-q.first)]
	if slot.ready {
		return zero, fmt.Errorf("commit queue: token %d is already committed", token)
	}
	return slot.value, nil
}

func (q *CommitQueue[T]) Commit(token CommitToken, value T) error {
	if token < q.first || token >= q.next {
		return fmt.Errorf("commit queue: token %d is not pending", token)
	}
	slot := &q.slots[q.head+int(token-q.first)]
	if slot.ready {
		return fmt.Errorf("commit queue: token %d is already committed", token)
	}
	slot.value = value
	slot.ready = true
	return nil
}

func (q *CommitQueue[T]) Drain(write func(T) error) error {
	for q.head < len(q.slots) && q.slots[q.head].ready {
		slot := &q.slots[q.head]
		if err := write(slot.value); err != nil {
			q.compact()
			return err
		}
		var zero T
		slot.value = zero
		q.head++
		q.first++
	}
	q.compact()
	return nil
}

func (q *CommitQueue[T]) Len() int {
	return len(q.slots) - q.head
}

func (q *CommitQueue[T]) compact() {
	if q.head == 0 {
		return
	}
	if q.head == len(q.slots) {
		q.slots = q.slots[:0]
		q.head = 0
		return
	}
	if q.head*2 < len(q.slots) {
		return
	}
	pending := copy(q.slots, q.slots[q.head:])
	clear(q.slots[pending:])
	q.slots = q.slots[:pending]
	q.head = 0
}
