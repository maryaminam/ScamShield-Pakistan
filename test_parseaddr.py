import email.utils

hdr = "Microsoft account team ,_<no-reply@access-accsecurity.com>"
dn, addr = email.utils.parseaddr(hdr)
print(repr(dn))
print(repr(addr))
