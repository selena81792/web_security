# Web Security writeup
by Ka Po Chau

# ssti
By following [this guide](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection), I was able to check the ssti injection and confirmed that it is python jinja2.
> {{7*'7'}} = 7777777
> 
> {{foobar}} Nothing

## ssti1
