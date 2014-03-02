all: 1pass test

.PHONY: test
DEPS=*.go onepass/*.go jsonutil/*.go plist/*.go rangeutil/*.go cmdmodes/*.go

1pass: $(DEPS)
	go get -d
	go build

test: 1pass
	go test ./...
	pip install --quiet --requirement requirements.txt
	python ./client_test.py

