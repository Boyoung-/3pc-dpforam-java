#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
java -cp "${DIR}/../bin:${DIR}/../lib/*" ui.CLI charlie -eddie_ip 54.70.122.155 -debbie_ip 34.210.191.225 "$@"