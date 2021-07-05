#!/bin/bash

target/universal/stage/bin/ghidra2cpg -J-Dlog4j.configurationFile=config/log4j-ghidra.xml "$@"
