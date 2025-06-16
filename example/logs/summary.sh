#!/bin/bash

LOG_FILES=$(find -maxdepth 1 -type f -name "*log*")

for FILE in ${LOG_FILES[@]}; do
    echo "LOG FILE: ${FILE}"
    cat ${FILE} | grep -A12 "Summary"
    echo
done


