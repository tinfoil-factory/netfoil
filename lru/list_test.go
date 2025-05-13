package lru

import "testing"

func TestPushBack(t *testing.T) {
	l := List[string]{}

	if l.Size() != 0 {
		t.Error("list size should be 0")
	}

	l.PushBack("a")

	if l.Size() != 1 {
		t.Error("list size should be 1")
	}

	if l.Head().Value() != "a" {
		t.Error("list head should be a")
	}

	if l.Tail().Value() != "a" {
		t.Error("list head should be a")
	}

	l.PushBack("b")

	if l.Size() != 2 {
		t.Error("list size should be 2")
	}

	if l.Head().Value() != "a" {
		t.Error("list head should be a")
	}

	if l.Tail().Value() != "b" {
		t.Error("list tail should be b")
	}
}

func TestPushFront(t *testing.T) {
	l := List[string]{}
	l.PushFront("b")

	if l.Size() != 1 {
		t.Error("list size should be 1")
	}

	if l.Head().Value() != "b" {
		t.Error("list head should be a")
	}

	if l.Tail().Value() != "b" {
		t.Error("list head should be a")
	}

	l.PushFront("a")

	if l.Size() != 2 {
		t.Error("list size should be 2")
	}

	if l.Head().Value() != "a" {
		t.Error("list head should be a")
	}

	if l.Tail().Value() != "b" {
		t.Error("list tail should be b")
	}
}

func TestRemoveEmpty(t *testing.T) {
	l := List[string]{}
	e := &ListElement[string]{}
	l.Remove(e)
}

func TestRemoveSingle(t *testing.T) {
	l := List[string]{}
	e := l.PushBack("a")
	l.Remove(e)

	if l.Head() != nil {
		t.Error("head should be nil")
	}

	if l.Tail() != nil {
		t.Error("tail should be nil")
	}

	if l.Size() != 0 {
		t.Error("size should be 0")
	}
}

func TestRemoveDouble(t *testing.T) {
	l := List[string]{}
	e1 := l.PushBack("a")
	e2 := l.PushBack("b")
	l.Remove(e1)

	if l.Head() != e2 {
		t.Error("wrong head")
	}

	if l.Tail() != e2 {
		t.Error("wrong tail")
	}

	if l.Size() != 1 {
		t.Error("size should be 1")
	}

	e3 := l.PushBack("c")
	l.Remove(e3)

	if l.Head() != e2 {
		t.Error("wrong head")
	}

	if l.Tail() != e2 {
		t.Error("wrong tail")
	}

	if l.Size() != 1 {
		t.Error("size should be 1")
	}
}

func TestRemoveMiddle(t *testing.T) {
	l := List[string]{}
	e1 := l.PushBack("a")
	e2 := l.PushBack("b")
	e3 := l.PushBack("c")
	l.Remove(e2)

	if l.Head() != e1 {
		t.Error("wrong head")
	}

	if l.Tail() != e3 {
		t.Error("wrong tail")
	}

	if l.Size() != 2 {
		t.Error("size should be 2")
	}
}

func TestMoveToFrontSingle(t *testing.T) {
	l := List[string]{}
	e1 := l.PushBack("a")
	l.MoveToFront(e1)

	if l.Head() != e1 {
		t.Error("wrong head")
	}

	if l.Tail() != e1 {
		t.Error("wrong tail")
	}

	if l.Size() != 1 {
		t.Error("size should be 1")
	}
}

func TestMoveToFrontDouble(t *testing.T) {
	l := List[string]{}
	e1 := l.PushBack("a")
	e2 := l.PushBack("b")
	l.MoveToFront(e1)

	if l.Head() != e1 {
		t.Error("wrong head")
	}

	if l.Tail() != e2 {
		t.Error("wrong tail")
	}

	if l.Size() != 2 {
		t.Error("size should be 2")
	}

	l.MoveToFront(e2)

	if l.Head() != e2 {
		t.Error("wrong head")
	}

	if l.Tail() != e1 {
		t.Error("wrong tail")
	}

	if l.Size() != 2 {
		t.Error("size should be 1")
	}
}

func TestMoveToFrontMiddle(t *testing.T) {
	l := List[string]{}
	e1 := l.PushBack("a")
	e2 := l.PushBack("b")
	e3 := l.PushBack("c")
	l.MoveToFront(e2)

	if l.Head() != e2 {
		t.Error("wrong head")
	}

	if l.Tail() != e3 {
		t.Error("wrong tail")
	}

	if l.Head().Next() != e1 {
		t.Error("wrong middle")
	}

	if l.Size() != 3 {
		t.Error("size should be 2")
	}
}
