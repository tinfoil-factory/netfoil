package suffixtrie

import "fmt"

type Node struct {
	match bool
	next  [128]*Node
}

func (st *Node) InsertMultiple(words []string) error {
	for _, word := range words {
		err := st.Insert([]byte(word))
		if err != nil {
			return err
		}
	}

	return nil
}

func (st *Node) Insert(word []byte) error {
	if len(word) == 0 {
		return fmt.Errorf("empty word")
	}

	current := st
	for i := len(word) - 1; i > 0; i-- {
		c := word[i]
		if c > 127 {
			return fmt.Errorf("invalid character: %d", c)
		}

		if current.next[c] == nil {
			current.next[c] = &Node{}
		}

		current = current.next[c]
	}

	current.match = true

	return nil
}

func (st *Node) MatchExact(word []byte) bool {
	if len(word) == 0 {
		return false
	}

	current := st
	for i := len(word) - 1; i > 0; i-- {
		c := word[i]
		if c > 127 {
			return false
		}

		if current.next[c] == nil {
			return false
		}
		current = current.next[c]
	}

	return current.match
}

func (st *Node) MatchSuffix(word []byte) bool {
	if len(word) == 0 {
		return true
	}

	current := st
	for i := len(word) - 1; i > 0; i-- {
		c := word[i]
		if c > 127 {
			return false
		}

		if current.next[c] == nil {
			return false
		}
		current = current.next[c]

		if current.match {
			return true
		}
	}

	return false
}
