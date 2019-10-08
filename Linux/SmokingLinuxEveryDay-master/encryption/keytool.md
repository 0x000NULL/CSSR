## Java keytool notes

### Detect/Set Java_HOME

```
JAVA_HOME=$(readlink -f /usr/bin/java | sed "s:bin/java::")
```

---

### Dump/List cacerts contents

* default password: changeit

```
keytool -list -keystore $JAVA_HOME/lib/security/cacerts -v
```

---

### Add a certificate

```
keytool -importcert -file mycert.crt -alias myalias -keystore $JAVA_HOME/lib/security/cacerts
```

---
