#!/bin/bash
if [ -e /etc/X11/xdm/Xservers ]; then
     cd /etc/X11/xdm
     awk '( $1 !~ /^#/ && $3 == "/usr/X11R6/bin/X" ) { $3 = $3 " -nolisten tcp" };
     { print }' Xservers-preCIS > Xservers
     chown root:root Xservers
     chmod 0444      Xservers
     echo "diff Xservers-preCIS Xservers"
           diff Xservers-preCIS Xservers
     cd $cishome
else
     echo "No /etc/X11/xdm/Xservers file to secure."
fi
if [ -d /etc/X11/xinit ]; then
     cd /etc/X11/xinit
     if [ -e xserverrc ]; then
          echo "Fixing /etc/X11/xinit/xserverrc"
          awk '/X/ && !/^#/ { print $0 " :0 -nolisten tcp \$@"; next }; \
          { print }' xserverrc-preCIS > xserverrc
     else
          cat <<END_SCRIPT > xserverrc
#!/bin/bash
exec X :0 -nolisten tcp \$@
END_SCRIPT
     fi
     chown root:root xserverrc
     chmod 0755      xserverrc
     [ -e xserverrc-preCIS ] && echo "diff xserverrc-preCIS xserverrc"
     [ -e xserverrc-preCIS ] &&        diff xserverrc-preCIS xserverrc
     cd $cishome
else
     echo "No /etc/X11/xinit file to secure."
fi
