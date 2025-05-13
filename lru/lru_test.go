package lru

import (
	"testing"
)

func TestLRU(t *testing.T) {
	lru := NewCache[string](2)

	if lru.Capacity() != 2 {
		t.Error("LRU capacity should be 2")
	}

	if lru.Size() != 0 {
		t.Error("LRU size should be 0")
	}

	i1 := "1"
	lru.Set("a", &i1)

	if lru.Size() != 1 {
		t.Errorf("LRU size should be 2, got %d", lru.Size())
	}

	v1, ok := lru.Get("a")
	if !ok {
		t.Error("LRU should contain a")
	}
	if *v1 != "1" {
		t.Errorf("expected 1, got %s", *v1)
	}

	i2 := "2"
	lru.Set("b", &i2)

	if lru.Size() != 2 {
		t.Errorf("LRU size should be 2, got %d", lru.Size())
	}

	v2, ok := lru.Get("b")
	if !ok {
		t.Error("LRU should contain a")
	}
	if *v2 != "2" {
		t.Errorf("expected 2, got %s", *v2)
	}

	i3 := "3"
	lru.Set("a", &i3)
	if lru.Size() != 2 {
		t.Errorf("LRU size should be 2, got %d", lru.Size())
	}

	v1, ok = lru.Get("a")
	if !ok {
		t.Error("LRU should contain a")
	}
	if *v1 != "3" {
		t.Errorf("expected 3, got %s", *v2)
	}

	i4 := "4"
	lru.Set("c", &i4)
	if lru.Size() != 2 {
		t.Errorf("LRU size should be 2, got %d", lru.Size())
	}

	v1, ok = lru.Get("a")
	if !ok {
		t.Error("LRU should contain a")
	}

	v1, ok = lru.Get("b")
	if ok {
		t.Error("LRU should not contain b")
	}

	v3, ok := lru.Get("c")
	if !ok {
		t.Error("LRU should contain c")
	}

	if *v3 != "4" {
		t.Errorf("expected 4, got %s", *v3)
	}
}
