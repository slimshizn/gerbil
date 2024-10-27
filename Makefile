
all: build push

build:
	docker build -t fossorial/gerbil:latest .

push:
	docker push fossorial/gerbil:latest

test:
	docker run -it -p 3002:3002 -v ./config_example.json:/config/config.json --cap-add=NET_ADMIN --cap-add=SYS_MODULE gerbil --config /config/config.json

local: 
	 CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o gerbil

clean:
	rm gerbil