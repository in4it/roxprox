build:
	CGO_ENABLED=0 GOOS=linux go build \
		-a --ldflags '-extldflags "-static"' -tags netgo -installsuffix netgo \
		-o build/als server.go

docker: build
	docker build -t als .

.PHONY: clean
clean:
	rm -fr build
