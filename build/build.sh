#!/bin/bash
# build.sh V.1.1
# Description: Build Docker image based on Dockerfile and tags it.

# Source configuration
if ! source ./BUILD_CONFIG; then
    echo "Failed to source BUILD_CONFIG. Please check the file."
    exit 1
fi

# Build Docker image
cd ../ || { echo "Failed to change directory. Exiting."; exit 1; }

# Build the Docker image using the Dockerfile in the build directory
docker build -f build/Dockerfile -t ${DOCKER_IMAGE} .

# Check if the build was successful
if [ $? -eq 0 ]; then
    echo "Docker image '${DOCKER_IMAGE}' built successfully!"
else
    echo "Failed to build Docker image."
    exit 1
fi
