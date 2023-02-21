#!/bin/bash
set -eo pipefail

# print and run a command
function ee()
{
    echo "$ $*"
    eval "$@"
}

# install dependencies for self-hosted runners
ee export DEBIAN_FRONTEND='noninteractive'
ee export HUNTER_JOBS_NUMBER="$(nproc)"
ee export NUMBER_OF_LOGICAL_CORES="$(nproc)"
ee apt-get update -q
ee apt-get install -yqq build-essential cmake gcc-10 g++-10 git
ee git config --global --add safe.directory '*' # silence all safe.directory git warnings inside container (causing "fatal: detected dubious ownership in repository")

# debug code
echo "CC='${CC}'"
echo "CXX='${CXX}'"
echo "HUNTER_JOBS_NUMBER='${HUNTER_JOBS_NUMBER}'"
echo "NUMBER_OF_LOGICAL_CORES='${NUMBER_OF_LOGICAL_CORES}'"
ee cmake --version
ee nproc
ee free -h
ee lscpu

# build
ee mkdir build
ee pushd build
ee cmake ..
ee make -j "$(nproc)"

# pack
ee popd
ee 'tar -czf build.tar.gz build/*'

echo "Done! - ${0##*/}"
