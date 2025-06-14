#!/bin/bash

LOOP_CNT=50
CNT=1
FILE_NAME="auto_log.65500"

for IDX in `seq 1 ${LOOP_CNT}`;
do 
    RESULT="./logs/${FILE_NAME}.${IDX}"
    echo "#### LOOP ${IDX}"
    echo "Log File: ${RESULT}"
    ./auto_run.py > ${RESULT}
    echo "Done"
    echo
done

