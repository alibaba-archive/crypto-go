test:
	go test --race
	go test --race ./pbkdf2

cover:
	rm -f *.coverprofile
	go test -coverprofile=crypto.coverprofile
	go test -coverprofile=pbkdf2.coverprofile ./pbkdf2
	gover
	go tool cover -html=gover.coverprofile
	rm -f *.coverprofile

.PHONY: test cover
