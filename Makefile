.PHONY: tools build package test

tools:
	go install github.com/aws/aws-lambda-go/cmd/build-lambda-zip@latest

build: tools
	mkdir -p aws/tf/files gcp/tf/files
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -tags lambda.norpc -o aws/tf/files/bootstrap ./aws/
	go build ./gcp/

package: build
	cd aws/tf && build-lambda-zip --output files/vault-admin.zip files/bootstrap
	go mod vendor
	cp gcp/main.go main.go
	rm -f gcp/tf/files/vault-admin.zip
	zip -r gcp/tf/files/vault-admin.zip go.mod go.sum main.go admin/handle.go vendor
	rm -f main.go

test:
	go test ./...
