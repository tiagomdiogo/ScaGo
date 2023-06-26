# Start from the latest golang base image
FROM golang:latest
# Set the Current Working Directory inside the container
WORKDIR /app

# Copy go.mod and go.sum files to the workspace
COPY go.mod go.sum ./

# Download all dependencies. Dependencies will be cached if the go.mod and go.sum files are not changed
RUN go mod download

# Copy the source from the current directory to the Working Directory inside the container
COPY . .

# Install nano
RUN apt-get update && apt-get install -y nano

# Set the entrypoint to be the bash shell
ENTRYPOINT ["/bin/bash"]
