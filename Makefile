test:
	go test --race
	go test --race ./cipher
	go test --race ./password
	go test --race ./signature
	go test --race ./state

cover:
	rm -f *.coverprofile
	go test -coverprofile=crypto.coverprofile
	go test -coverprofile=cipher.coverprofile ./cipher
	go test -coverprofile=password.coverprofile ./password
	go test -coverprofile=signature.coverprofile ./signature
	go test -coverprofile=state.coverprofile ./state
	gover
	go tool cover -html=gover.coverprofile
	rm -f *.coverprofile

.PHONY: test cover
