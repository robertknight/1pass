package main

import "reflect"

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


