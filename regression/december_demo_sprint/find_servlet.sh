#!/bin/sh

echo "This script extracts some parts of java files that could be "
echo "interesting for security analysis"
echo "usage ./test.sh DIRECTORY"
DIR=$1
echo "analysing directory " $DIR
echo "############################################################"
#echo "------ Interesting function calls in java file ------"
for i in $(find $DIR -name *.java)
do
    grep -n -H -e "extends HttpServlet" $i;
    #grep -H -n -e addIntHeader -e addHeader -e addDateHeader -e addCookie -e setHeader -e getWriter -e getOutputStream $i;
done

