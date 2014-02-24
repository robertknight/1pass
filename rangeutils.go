package main

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

func indexInRange(min, max int, pred func(i int) bool) int {
	for i := min; i < max; i++ {
		if pred(i) {
			return i
		}
	}
	return -1
}

func rangeContains(min, max int, pred func(i int) bool) bool {
	return indexInRange(min, max, pred) != -1
}

func sortRange(min, max int, lessFunc func(i, k int) bool, swapFunc func(i, k int)) {
	sorter := rangeSorter{
		min:      min,
		max:      max,
		lessThan: lessFunc,
		swap:     swapFunc,
	}
	sort.Sort(sorter)
}
