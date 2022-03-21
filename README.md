# Sbsevery

Secure boot sign every(thing)

Recursively sign files for secureboot (helpful when dualbooting Windows with custom SB keys)

## Usage

quietly sign all files
```
sbsevery /efi -k /etc/efi-keys/DB.key -c /etc/efi-keys/DB.crt
```

verbosley sign all files
```
sbsevery /efi -k /etc/efi-keys/DB.key -c /etc/efi-keys/DB.crt -d
```
