FROM golang:1.21.5-alpine AS build

# Set the working directory inside the container
WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download all dependencies
RUN go mod download

# Copy the source code into the container
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o /gerbil

# Start a new stage from scratch
FROM ubuntu:22:04  

RUN RUN apt-get update && apt-get install -y nftables && apt-get clean

WORKDIR /root/

# Copy the pre-built binary file from the previous stage
COPY --from=build /gerbil .

# Command to run the executable
CMD ["./gerbil"]
