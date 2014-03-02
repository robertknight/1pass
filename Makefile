all: 1pass

.PHONY: test
DEPS=*.go onepass/*.go jsonutil/*.go plist/*.go rangeutil/*.go cmdmodes/*.go

1pass: $(DEPS)
	go build
	go test ./...

test: 1pass
	go test ./...
	python ./client_test.py

