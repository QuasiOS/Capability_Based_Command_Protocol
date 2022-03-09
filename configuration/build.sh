#!/usr/bin/env bash

set -e

USE_CPP=0

if [ $USE_CPP -eq 1 ]; then
	CC=g++
	STANDARD=c++11
else
	CC=gcc
	STANDARD=c99
fi

CFLAGS="
	-std=$STANDARD
	-I../
	-ggdb
	-O0
	-Wall
	-Wextra
	-Wcast-align
	-Werror
	-pedantic
	-ftabstop=1
	-Wno-unused-function
	-Wno-error=unused-parameter
	-DCBCP_LITTLE_ENDIAN
	-DCBCP_DEBUG_PRINT_WHEN_SERIALIZING__OFF
"

LDFLAGS="
"

COMPILATION_UNITS="
	cbcp_config.c
"

$CC $CFLAGS -o cbcp_config.prog $COMPILATION_UNITS -lcrypto -lpthread
