MAIN := ./cmd/main.go

run:
	go run $(MAIN)

templ:
	templ generate view/

build:
	templ generate view/; go build -o ./tmp/main cmd/main.go
