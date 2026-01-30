#!/bin/bash

mkdir -p build
cd build
cmake .. --log-level=ERROR
make

