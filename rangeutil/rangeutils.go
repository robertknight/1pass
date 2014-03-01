// Package rangeutil provides some utility functions to remove
// some of the boilerplate required to perform common
// operations on slices or arrays in Go.
package rangeutil

import (
	"sort"
)

type rangeSorter struct {
	min      int
	max      int
	lessThan func(i, k int) bool
	swap     func(i, k int)
}

func (s rangeSorter) Len() int {
	return s.max - s.min
}

func (s rangeSorter) Less(i, j int) bool {
	return s.lessThan(i+s.min, j+s.min)
}

func (s rangeSorter) Swap(i, j int) {
	s.swap(i+s.min, j+s.min)
}

// IndexIn iterates over a range [min, max) and returns the
// first index for which pred(i) returns true.
func IndexIn(min, max int, pred func(i int) bool) int {
	for i := min; i < max; i++ {
		if pred(i) {
			return i
		}
	}
	return -1
}

// Contains iterates over a range [min, max) and returns
// true if pred(i) returns true for any value of i
func Contains(min, max int, pred func(i int) bool) bool {
	return IndexIn(min, max, pred) != -1
}

// Sort sorts entries in a range [min, max), calling lessFunc(i, k) to
// perform a pairwise comparison of items and swapFunc(i, k) to actually
// swap two values
func Sort(min, max int, lessFunc func(i, k int) bool, swapFunc func(i, k int)) {
	sorter := rangeSorter{
		min:      min,
		max:      max,
		lessThan: lessFunc,
		swap:     swapFunc,
	}
	sort.Sort(sorter)
}
