package lru

type ListElement[T comparable] struct {
	next     *ListElement[T]
	previous *ListElement[T]
	value    T
}

func (e *ListElement[T]) Next() *ListElement[T] {
	return e.next
}

func (e *ListElement[T]) Value() T {
	return e.value
}

func (e *ListElement[T]) SetValue(value T) {
	e.value = value
}

func (e *ListElement[T]) Previous() *ListElement[T] {
	return e.previous
}

type List[T comparable] struct {
	head *ListElement[T]
	tail *ListElement[T]
	size int
}

func (l *List[T]) Head() *ListElement[T] {
	return l.head
}

func (l *List[T]) PushFront(value T) *ListElement[T] {
	newElement := &ListElement[T]{
		next:     nil,
		previous: nil,
		value:    value,
	}

	if l.head == nil {
		l.head = newElement
		l.tail = newElement
	} else {
		newElement.next = l.head
		l.head.previous = newElement

		l.head = newElement
	}

	l.size++
	return newElement
}

func (l *List[T]) PushBack(value T) *ListElement[T] {
	newElement := &ListElement[T]{
		next:     nil,
		previous: nil,
		value:    value,
	}

	if l.head == nil {
		l.head = newElement
		l.tail = newElement
	} else {
		newElement.previous = l.tail
		l.tail.next = newElement

		l.tail = newElement
	}

	l.size++
	return newElement
}

func (l *List[T]) Remove(e *ListElement[T]) {
	if l.size == 0 {
		return
	}

	if l.head == e {
		l.head = e.next

		if l.head == nil {
			l.tail = nil
		}
	} else if l.tail == e {
		l.tail = l.tail.previous

		if l.tail == nil {
			l.head = nil
		}
	} else {
		a := e.previous
		b := e.next
		a.next = b
		b.previous = a

	}
	l.size--
}

func (l *List[T]) MoveToFront(e *ListElement[T]) {
	// FIXME this is unsafe to call in general
	if l.size == 0 {
		panic("list is empty")
	}

	if l.head == e {
		// already at front
	} else {
		if l.tail == e {
			l.tail = l.tail.previous
		} else {
			a := e.previous
			b := e.next
			a.next = b
			b.previous = a
		}
		e.next = l.head
		l.head.previous = e

		l.head = e
	}
}

func (l *List[T]) Tail() *ListElement[T] {
	return l.tail
}

func (l *List[T]) Size() int {
	return l.size
}
