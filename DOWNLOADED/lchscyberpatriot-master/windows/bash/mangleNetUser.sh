#!/bash/bin

net user | grep -v The\ command|grep -v User\ accounts|grep -v -- "-"|awk '{print $0}' RS=' '|grep -v -e '^$'
