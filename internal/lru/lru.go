package lru

import (
	"sync"
	"sync/atomic"
)

type Cache[T any] struct {
	list     *List[KeyValue[T]]
	m        map[string]*ListElement[KeyValue[T]]
	capacity atomic.Int64
	size     atomic.Int64
	mutex    sync.Mutex
}

type KeyValue[T any] struct {
	key   string
	value *T
}

func NewCache[T any](capacity int64) *Cache[T] {
	cache := &Cache[T]{
		list: &List[KeyValue[T]]{},
		m:    make(map[string]*ListElement[KeyValue[T]]),
	}
	cache.capacity.Store(capacity)
	cache.size.Store(0)

	return cache
}

func (c *Cache[T]) Get(key string) (result *T, found bool) {
	c.mutex.Lock()

	e, ok := c.m[key]

	if ok {
		c.list.MoveToFront(e)

		result = e.Value().value
		found = true
	}

	c.mutex.Unlock()

	return result, found
}

func (c *Cache[T]) Set(key string, value *T) {
	c.mutex.Lock()

	e, ok := c.m[key]

	if ok {
		nv := e.Value()
		nv.value = value
		e.SetValue(nv)
		c.list.MoveToFront(e)
	} else {
		nv := KeyValue[T]{key, value}
		n := c.list.PushFront(nv)
		c.m[key] = n
		c.size.Add(1)
	}

	if c.size.Load() > c.capacity.Load() {
		tail := c.list.Tail()

		delete(c.m, tail.Value().key)
		c.list.Remove(tail)
		c.size.Add(-1)
	}

	c.mutex.Unlock()
}

func (c *Cache[T]) Size() int64 {
	return c.size.Load()
}

func (c *Cache[T]) Capacity() int64 {
	return c.capacity.Load()
}
