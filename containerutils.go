package main

import (
	"reflect"
	"sort"
)

func sliceTypeCheck(slice interface{}, value interface{}) {
	sliceVal := reflect.ValueOf(slice)
	if sliceVal.Kind() != reflect.Array &&
		sliceVal.Kind() != reflect.Slice {
		panic("Container is not a slice or array")
	}

	if reflect.TypeOf(slice).Elem() != reflect.TypeOf(value) {
		panic("Slice element type and value type do not match")
	}
}

func sliceContains(slice interface{}, value interface{}) bool {
	return sliceIndexOf(slice, value) != -1
}

func sliceIndexOf(slice interface{}, value interface{}) int {
	sliceTypeCheck(slice, value)
	sliceVal := reflect.ValueOf(slice)
	for i := 0; i < sliceVal.Len(); i++ {
		if reflect.DeepEqual(sliceVal.Index(i).Interface(), value) {
			return i
		}
	}
	return -1
}

type sortable struct {
	slice    reflect.Value
	lessThan func(a, b interface{}) bool
}

func (s sortable) Len() int {
	return s.slice.Len()
}

func (s sortable) Less(i, j int) bool {
	return s.lessThan(s.slice.Index(i).Interface(), s.slice.Index(j).Interface())
}

func (s sortable) Swap(i, j int) {
	tmp := s.slice.Index(i).Interface()
	s.slice.Index(i).Set(s.slice.Index(j))
	s.slice.Index(j).Set(reflect.ValueOf(tmp))
}

func sortSlice(slice interface{}, lessThan func(a, b interface{}) bool) {
	s := sortable{slice: reflect.ValueOf(slice), lessThan: lessThan}
	sort.Sort(s)
}
