#!/bin/bash

FILE=$1

echo "#ifndef _CTRIP_VERSION_H_" > $1
echo "#define _CTRIP_VERSION_H_" >> $1

cd `dirname $0`
BRANCH=`git branch | sed -n '/\* /s///p'`
COMMIT=`git log | grep commit | head -n 1 | awk '{print $2}'`
cd -
#echo $BRANCH
DATE=`date '+%d-%m-%Y %H:%M:%S %z'`

echo "#define CTRIP_BUILD_DATE \""$DATE"\"" >> $1
echo "#define CTRIP_BUILD_BRANCH \""$BRANCH"\"" >> $1
echo "#define CTRIP_BUILD_COMMIT \""$COMMIT"\"" >> $1

echo "#endif //_CTRIP_VERSION_H_" >> $1
echo "" >> $1
