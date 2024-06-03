MAIN := ./cmd/main.go

run:
	go run $(MAIN)

templ:
	templ generate view/
