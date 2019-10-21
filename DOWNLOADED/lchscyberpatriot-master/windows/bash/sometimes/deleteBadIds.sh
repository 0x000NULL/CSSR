#!/bin/bash

cat badids.txt|xargs -I {} net user {} /del
