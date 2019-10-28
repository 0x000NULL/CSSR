#!/bin/bash

cat services-to-disable.txt | xargs -I {} bash -c "net stop {}; sc config {} start= disabled"
