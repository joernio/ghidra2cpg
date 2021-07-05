
# Ghidra2cpg

This is a [CPG](https://docs.joern.io/code-property-graph/) frontend based on [Ghidra](https://ghidra-sre.org/). 
## Status

![Tests](https://github.com/joernio/ghidra2cpg/workflows/SBT%20tests/badge.svg)

## Setup

Requirements:
 - At least java 11 (open jdk)
 - sbt (https://www.scala-sbt.org/)

### Quickstart

1. Clone the project
2. Build the project `sbt stage`
3. Create a CPG `./ghidra2cpg.sh /path/to/your/binary /path/to/cpg.bin`
4. Download joern with
   ```
   wget https://github.com/joernio/joern/releases/download/v1.1.164/joern-cli.zip
   unzip joern-cli.zip
   ```
5. Copy `cpg.bin` into the joern directory
6. Start joern with `./joern.sh`
7. Import the cpg with `importCpg("cpg.bin")`
8. Now you can query the CPG 

### Known issues
varags are not handled properly: https://github.com/NationalSecurityAgency/ghidra/issues/234

