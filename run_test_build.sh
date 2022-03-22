#!/bin/bash
FILE=./EFS.java
if [ ! -f "$FILE" ]; 
then
    echo "$FILE not found. Please place your EFS.java in this directory."
else
    cp $FILE ./TestBuildEnv/EFS.java
    cd ./TestBuildEnv
    javac @sources.txt
    java TestBuild
    find . -name "*.class" -exec rm -rf {} \;
fi
