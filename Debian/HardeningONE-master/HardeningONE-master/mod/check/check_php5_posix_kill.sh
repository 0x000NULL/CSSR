# HardeningOne - A hardening tool for Linux
# Copyright (C) 2010 Author
# Seg 18 Out 2010 09:49:01 BRST 
# São Paulo-SP
# Brazil
# Author:
#   * Mauro Risonho de Paula Assumpção aka firebits <firebits at backtrack dot com dot br>
#   
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 2 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program; if not, write to the Free Software
#   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
#

#!/bin/bash
echo " "
echo "-------------------------------------------------------------------------">>/root/ho/v.0.0.1/hardeningone/tmp/report.txt
date>>/root/ho/v.0.0.1/hardeningone/tmp/report.txt
echo "-------------------------------------------------------------------------">>/root/ho/v.0.0.1/hardeningone/tmp/report.txt
echo "Scanning no PHP5 por funcao posix_kill">>/root/ho/v.0.0.1/hardeningone/tmp/report.txt
echo "-------------------------------------------------------------------------">>/root/ho/v.0.0.1/hardeningone/tmp/report.txt
cat /etc/php5/apache2/php.ini|grep posix_kill>>/root/ho/v.0.0.1/hardeningone/tmp/report.txt
