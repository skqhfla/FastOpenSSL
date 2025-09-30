#!/usr/bin/bash

# LOOP_COUNT=(1 10 100 1000 10000)
LOOP_COUNT=(1 10)

for LOOP in ${LOOP_COUNT[@]};do
    echo "---------- Change Loop Count: ${LOOP}"
    sed -i -e "s/LOOP_COUNT.*/LOOP_COUNT ${LOOP}/g" test_common.h
    echo "Build Samples..."
    make clean -s; make -s 2>/dev/null
    echo "Done"
    # ./do.sh
    ./auto_run.py | grep -A12 "Summary"
    echo
done
