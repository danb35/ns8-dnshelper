#!/bin/bash

#
# Copyright (C) 2023 Nethesis S.r.l.
# SPDX-License-Identifier: GPL-3.0-or-later
#

# Terminate on error
set -e

# Prepare variables for later use
images=()
# The image will be pushed to GitHub container registry
repobase="${REPOBASE:-ghcr.io/nethserver}"
# Configure the image name
reponame="dnshelper"

# Create a new empty container image
container=$(buildah from scratch)

# Reuse existing nodebuilder-dnshelper container, to speed up builds
if ! buildah containers --format "{{.ContainerName}}" | grep -q nodebuilder-dnshelper; then
    echo "Pulling NodeJS runtime..."
    buildah from --name nodebuilder-dnshelper -v "${PWD}:/usr/src:Z" docker.io/library/node:lts
fi

echo "Build static UI files with node..."
buildah run \
    --workingdir=/usr/src/ui \
    --env="NODE_OPTIONS=--openssl-legacy-provider" \
    nodebuilder-dnshelper \
    sh -c "corepack enable && yarn install && yarn build"

# Reuse existing gobuilder-dnshelper container, to speed up builds
if ! buildah containers --format "{{.ContainerName}}" | grep -q gobuilder-dnshelper; then
    echo "Pulling Go toolchain..."
    buildah from --name gobuilder-dnshelper -v "${PWD}:/usr/src:Z" docker.io/library/golang:1.27.1-alpine
fi

echo "Test and build the static dnshelper binary..."
buildah run \
    --workingdir=/usr/src/helper \
    --env="CGO_ENABLED=0" \
    gobuilder-dnshelper \
    sh -c 'go test ./... && go build -trimpath -ldflags="-s -w" -o /usr/src/imageroot/bin/dnshelper ./cmd/dnshelper'

# Add imageroot directory to the container image
buildah add "${container}" imageroot /imageroot
buildah add "${container}" ui/dist /ui

buildah config --entrypoint=/ \
    --label="org.nethserver.rootfull=0" \
    --label="org.nethserver.min-core=3.20.1" \
    "${container}"
# Commit the image
buildah commit "${container}" "${repobase}/${reponame}"

# Append the image URL to the images array
images+=("${repobase}/${reponame}")

#
# NOTICE:
#
# It is possible to build and publish multiple images.
#
# 1. create another buildah container
# 2. add things to it and commit it
# 3. append the image url to the images array
#

#
# Setup CI when pushing to Github. 
# Warning! docker::// protocol expects lowercase letters (,,)
if [[ -n "${CI}" ]]; then
    # Set output value for Github Actions
    printf "images=%s\n" "${images[*],,}" >> "${GITHUB_OUTPUT}"
else
    # Just print info for manual push
    printf "Publish the images with:\n\n"
    for image in "${images[@],,}"; do printf "  buildah push %s docker://%s:%s\n" "${image}" "${image}" "${IMAGETAG:-latest}" ; done
    printf "\n"
fi
