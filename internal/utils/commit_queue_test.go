package utils

import (
	"errors"
	"reflect"
	"testing"
)

func TestCommitQueueBlocksReadyValuesBehindPendingSlot(t *testing.T) {
	var queue CommitQueue[string]
	video := queue.Reserve()
	queue.PushReady("audio")

	var output []string
	if err := queue.Drain(func(value string) error {
		output = append(output, value)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(output) != 0 {
		t.Fatalf("output = %v, want none", output)
	}

	if err := queue.Commit(video, "video"); err != nil {
		t.Fatal(err)
	}
	if err := queue.Drain(func(value string) error {
		output = append(output, value)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if want := []string{"video", "audio"}; !reflect.DeepEqual(output, want) {
		t.Fatalf("output = %v, want %v", output, want)
	}
	if queue.Len() != 0 {
		t.Fatalf("queue length = %d, want 0", queue.Len())
	}
}

func TestCommitQueueDrainsCommittedSlotsInReservationOrder(t *testing.T) {
	var queue CommitQueue[int]
	first := queue.Reserve()
	second := queue.Reserve()
	third := queue.Reserve()

	if err := queue.Commit(third, 3); err != nil {
		t.Fatal(err)
	}
	if err := queue.Commit(second, 2); err != nil {
		t.Fatal(err)
	}
	if err := queue.Commit(first, 1); err != nil {
		t.Fatal(err)
	}

	var output []int
	if err := queue.Drain(func(value int) error {
		output = append(output, value)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if want := []int{1, 2, 3}; !reflect.DeepEqual(output, want) {
		t.Fatalf("output = %v, want %v", output, want)
	}
}

func TestCommitQueueKeepsFailedAndLaterSlots(t *testing.T) {
	var queue CommitQueue[int]
	queue.PushReady(1)
	queue.PushReady(2)
	queue.PushReady(3)
	wantErr := errors.New("write failed")

	var output []int
	err := queue.Drain(func(value int) error {
		if value == 2 {
			return wantErr
		}
		output = append(output, value)
		return nil
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want %v", err, wantErr)
	}
	if queue.Len() != 2 {
		t.Fatalf("queue length = %d, want 2", queue.Len())
	}

	if err := queue.Drain(func(value int) error {
		output = append(output, value)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if want := []int{1, 2, 3}; !reflect.DeepEqual(output, want) {
		t.Fatalf("output = %v, want %v", output, want)
	}
}

func TestCommitQueueRejectsInvalidCommit(t *testing.T) {
	var queue CommitQueue[int]
	token := queue.Reserve()
	if err := queue.Commit(token, 1); err != nil {
		t.Fatal(err)
	}
	if err := queue.Commit(token, 2); err == nil {
		t.Fatal("second commit succeeded")
	}
	if err := queue.Drain(func(int) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := queue.Commit(token, 3); err == nil {
		t.Fatal("commit after drain succeeded")
	}
}

func TestCommitQueueReserveWithPreservesPendingValue(t *testing.T) {
	var queue CommitQueue[string]
	token := queue.ReserveWith("meta")
	got, err := queue.Peek(token)
	if err != nil {
		t.Fatal(err)
	}
	if got != "meta" {
		t.Fatalf("peek = %q, want meta", got)
	}
	if err := queue.Commit(token, "ready"); err != nil {
		t.Fatal(err)
	}
	if _, err := queue.Peek(token); err == nil {
		t.Fatal("peek after commit succeeded")
	}
}
