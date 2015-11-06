build:
	go build

install:
	go install

run: build install
	aws-scanner
