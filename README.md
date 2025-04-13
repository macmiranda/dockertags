# Docker Tags CLI

A command-line tool to list Docker tags from a registry using authentication from dockerconfig.json.

## Features

- List all available tags for a Docker image
- Support for both public and private registries
- Automatic authentication using Docker credentials
- Support for Docker Hub and custom registries

## Installation

```bash
go install github.com/macmiranda/dockertags@latest
```

## Usage

```bash
dockertags --registry <registry-url> <repository>
```

### Examples

List tags from Docker Hub:

```bash
# List tags for the official Nginx image
dockertags --registry docker.io library/nginx

# List tags for a user repository
dockertags --registry docker.io username/repository
```

List tags from a private registry:

```bash
# List tags from a private registry
dockertags --registry registry.example.com my-org/my-image

# List tags from Google Container Registry
dockertags --registry gcr.io my-project/my-image

# List tags from Amazon ECR
dockertags --registry <aws-account>.dkr.ecr.<region>.amazonaws.com my-image
```

## Authentication

The tool uses the authentication credentials from your Docker config file (`~/.docker/config.json`). Make sure you're logged in to the registry before using the tool:

```bash
# Log in to Docker Hub
docker login

# Log in to a private registry
docker login <registry-url>

# Log in to Google Container Registry
docker login gcr.io

# Log in to Amazon ECR
aws ecr get-login-password | docker login --username AWS --password-stdin <aws-account>.dkr.ecr.<region>.amazonaws.com
```

## Development

### Building

```bash
go build -o dockertags
```

### Testing

```bash
go test -v ./...
```

## License

MIT
