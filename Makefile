test:
	go test --race

cover:
	rm -f *.coverprofile
	go test -coverprofile=crypto.coverprofile
	go tool cover -html=crypto.coverprofile
	rm -f *.coverprofile

.PHONY: test cover
