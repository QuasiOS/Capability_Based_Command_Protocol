#!/usr/bin/env bash

CBCP_DIR=../..

set -e

# Build config program
# pushd $CBCP_DIR/configuration/; bash ./build.sh; popd

$CBCP_DIR/configuration/cbcp_config.prog network.cbcp-config > /dev/null 2>&1

USE_CPP=0

if [ $USE_CPP -eq 1 ]; then
	COMPILER=g++
	STANDARD=c++98
else
	COMPILER=gcc
	STANDARD=c99
fi

CFLAGS="
	-std=$STANDARD
	-I$CBCP_DIR
	-ggdb
	-O0
	-Wall
	-Wextra
	-Wcast-align
	-Wno-unused-function
	-pedantic
	-ftabstop=1
	-DCBCP_LITTLE_ENDIAN
	-DCBCP_DEBUG_PRINT_WHEN_SERIALIZING__NOT
"


PROGS=(
	"manager"
	"mobile_robot"
	"robot_arm"
)

for PROG in "${PROGS[@]}"; do
	COMPILATION_UNITS="
		$PROG.c
		$CBCP_DIR/cbcp.c
	"

	echo "Compiling: $PROG"
	$COMPILER $CFLAGS -o $PROG.prog $COMPILATION_UNITS -lpthread -lcrypto
done

# for HOST in "1" "2" "3"; do
# 	xterm -e "./host.prog $HOST.cbcpdb" &
# done