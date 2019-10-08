### Asymmetrical file encryption

* Encrypt

```bash
gpg --output doc.gpg --encrypt --recipient blake@cyb.org doc
```

* Decrypt

```bash
gpg --output doc --decrypt doc.gpg
```

### Symmetrical file encryption

```bash
gpg --output doc.gpg --symmetric doc
```

