MODULE := pam_ussh

module: test
	go build -buildmode=c-shared -o ${MODULE}.so

test: *.go
	go test -coverprofile=coverage.txt

clean:
	go clean
	-rm -f ${MODULE}.so ${MODULE}.h

.PHONY: test module clean
