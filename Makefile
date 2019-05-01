RELEASES=bin/alexproxy-darwin-amd64 \
	 bin/alexproxy-linux-amd64 \
	 bin/alexproxy-linux-386 \
	 bin/alexproxy-linux-arm \
	 bin/alexproxy-windows-amd64.exe \
	 bin/alexproxy-windows-386.exe \
	 bin/alexproxy-solaris-amd64 

all: $(RELEASES)

bin/alexproxy-%: GOOS=$(firstword $(subst -, ,$*))
bin/alexproxy-%: GOARCH=$(subst .exe,,$(word 2,$(subst -, ,$*)))
bin/alexproxy-%: $(wildcard *.go)
	GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=0 go build \
	     -ldflags "-X main.osarch=$(GOOS)/$(GOARCH) -X main.version=`git rev-parse --short HEAD``date -u +.%Y%m%d.%H%M%S` -s -w" \
	     -buildmode=exe \
	     -tags release \
	     -o $@

clean:
	rm -rf bin