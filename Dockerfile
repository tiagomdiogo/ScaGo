# Start from the latest Golang image
FROM golang:latest

# Update the package list and install git
RUN apt-get update && apt-get install -y git
RUN apt-get update && apt-get install -y libpcap-dev

# Set the Current Working Directory inside the container
WORKDIR /app

# Copy everything from the current directory to the Working Directory inside the container
COPY . .

# Download all the dependencies
RUN go get -d -v ./...

# Install the package
RUN go install -v ./...

# Build the Go app
RUN go build -o main .

# This docker image will start with this command line
CMD ["/bin/bash"]
