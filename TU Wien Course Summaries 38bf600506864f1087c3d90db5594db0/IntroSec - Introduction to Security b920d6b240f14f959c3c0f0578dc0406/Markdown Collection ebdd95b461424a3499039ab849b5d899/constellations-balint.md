**Name:** Balint

**Points:** Not yet graded

<hr>

Constellations
==============

Overview
--------
This webpage intends to print a list of Star-Constellations and some information about it.
Like: Name, Abbreviation, Origin, Brightest Star

With the "find" button an sql query is generated and it filters the table content for a constellation with the entered abbreviation.

If nothing is found then an empty output is returned.



Vulnerability
-------------
The input-form for the abbreviation search is vulnerable to sqli. This means that one can generate arbitary sql queries (wrapped in the intended query), which the database will process and return the results.


Exploitation
------------
Finding the vulnerability was the first step.
Since it is obvious that there has to be one (otherwise it would not be a challenge), I started by searching.



1) Applying some tools

There are many tools which are meant for these type of recon, so I applied 2 with the hope they reveals some vulnerabilities.

The first was ``burpsuite``, which can send payloads and encrype the data into different types like utf-8, hex,...
With this i tried a bit but it didn't lead to anything useful.

The second was ``sqlmap``, this tool is designed to scan all kind (different programing languages at the backend) of websites. It was not abled to print out propper results but it showed that there is probably some vulnerability in ``constellations``, which later turns out to be the table schema. And that the database might be using ``MySQL``

This didn't bring me much further in the exploit, just confirming that there is a vulnerability in the website. And it probably is not exploitable by sending different queries in the url. Since we can see that there is not much in the url and sqlmap does a bunch of testing for this, so it probably would have found it.



2) Try and error

Next I tried to find the vulnerability by manually trying different kinds of input in the input-forms. Since the password-input box is does not really give out any propper results I tried more extensively with the Abbreviation search form. Since here I can also generate output with the "Show all constellations". Like this I can tell more about the table and how it has to look like (for later queries).

By inputting different characters and sequences like " ", "100*(A)", ".", "#", "'" I could generate an Error Message, which in this case reveals a lot about the query. We can see that there is a LIMIT at the end of the query and it takes some string input. Which leads to the next step.



3) Depict the original query

So I can imagine how the query works on the database I try to wirte down the query that could be behind the input-form, using all the information i have.

Here the query obviously selects some data from a table where the Abbreviation (string) has a match in the table, with a LIMIT of 1.

Writing the query, it must look something like:
```
SELECT ? FROM ? WHERE ? = ? LIMIT 1
```

Now filling in all the info we know it could look like:
```
SELECT * FROM constellations.? WHERE Abbreviation = 'userinput' LIMIT 1
```
where userinput (without the quotation marks!!!) is the input from the input-box.



4) Generate some dummy output

Before I start generating the query which delivers some "valuable" infromation I try to bring the database to give me some output, so I know on which malicious query i can build my exploit on.

In this process ``dual`` helps a lot. In MySQL (which I know from the sqlmap tool) dual can be used as a table when one wants to select something from something (a table) that does not exist (or at least we don't know the name).

So I know that if i search for an Abbreviation there wil be an output produced of ``4 columns``. I have to maintain this schema, else the query will fail, since the output wouldn't match (with the "nothing" it finds).

Therefor I want to generate a query that looks something like this:
```
SELECT 1,2,3,4 FROM dual
```
This would output nothing relevant, just a confirmation that the malicios query works...

So I wrap it inside the original query to avoid sql-server errors:
```
'/**/UnIon/**/SeLect/**/1,2,3,4/**/FrOm/**/dual/**/WhErE/**/'a'='a
```
This query will be accepted by the server and generates an output without any errors. Because the query looks correct to the server.

Here the ``explanation`` of this payload, since this is what I will build everything on:
The first quotation mark ends the input sting of the wanted input in the box. So in this case we search for an empty string in the table, and the chances are low that there will be a Constellation without an Abbreviation (if yes we need to find something that generates NO output because of the LIMIT at the end).
If the empty search would deliver results we could NOT add any other query results, since they would be eliminated by the ``LIMIT 1``, which limits the output to 1.

The complete query will be processed by the database as if it would look like:
```
SELECT * FROM constellation_list WHERE abbreviation = '' UNION SELECT 1,2,3,4 FROM dual WHERE 'a'='a' LIMIT 1
```
*This assumption can be concluded by information gathered later, this is only for understanding purposes.



Then by trying I found out that there some characters are not allowed, like spaces or comments... ('--', ';', '#'). These carrecters instantly generate an error. So there are some remedies which can be found at: ```https://portswigger.net/support/sql-injection-bypassing-common-filters```

For me here the option seemed to work to replace the spaces with '/**/' inline comments.

After that if I try to UNION SELECT (which "puts" more query-results together, where the layout, like same amount of COLUMNS !!!! has to match) I get an error back saying that there is an error in the query. But in the error we can see that the commands I typed are not there anymore, which leads to the conclusion that there are some SQL Injection prevention techniques implemented. Bypassing these is descibed also on the previously mentioned website. I use in my exploit the ``Upper-Lower-Case`` method, since after a bit of trying it seemed to work.

The next obstacle is the quotationmark that is added at the beginning and the end of the userinput. And generates an error where we can see that the marks don't add up. By looking at the error message we can see that there must be one too many. This leads to the solution that I let the server evaluate a simple ``string comparison`` that alwasys evaluates to ``TRUE``. And since I know by now that there will be an ending quotation mark added, I simply leave out the last one (see the payload). Because that one is being closed automatically by the server.

And we get the desired dummy output!!


5) Gathering Information

Now we know what payload we can use to get the server to evaluate our query.
So it's time to gather some Information about the table and its collumns. Which in MySQL is usually stored in ``information_schema ``. Infos about the tables and the columns are to be found in the (self explainatory) information_schema``.tables`` and information_schema``.columns`` .
To experiment and figure out how this information_schema is built I used an online database: ```https://www.w3schools.com/sql/trymysql.asp?filename=trysql_select_limit```. I tried every query here on these pre-built tables and could simply print the information_schema.tables


The information we need first are ``all the tables`` that exist, since we can see from the website that there must be some hidden data, which is probably not in the same table as all the other data we can simply search for or view.

This information is delivered by the payload:
```
'/**/UnIon/**/SeLect/**/1,GROUP_CONCAT(TABLE_NAME),3,4/**/FrOm/**/information_schema.tables/**/WhErE/**/'a'='a
```

I use the ``GROUP_CONCAT `` command to put all the output into that one (in this case 2nd) cell. Because only one output is allowed by the LIMI 1, from the end of the original query.
But as we inspect the results, we can notice that NOT all the tables are printed.
It seems that the result does not fit into the column or is limited. Especially if we print the same info in another webserver or look up in the MySQL documentation what information_schema.tables should contain.

That's why we build another payload, that can simply bypass this problem:
```
'/**/UnIon/**/SeLect/**/1,(SeLect/**/TABLE_NAME/**/FrOm/**/information_schema.tables/**/LIMIT/**/61,1),3,4/**/FrOm/**/dual/**/WhErE/**/'a'='a
```

Here I added another SELECT query into the other UNION SELECT query.
It takes the names of the tables from the information_schema.tables and puts them into the 2nd column. We could do this in any of the 4 columns. The rest we have to fill with dummy data, that is still selected from dual, since it HAS to match the original schema.
But here we add a LIMIT which has an option to add also an ``offset``. That is represented by the first number after the LIMIT command. So here we output onyly one Name of a table at the time. But by inspecting the information_schema.tables (on the website i mentiones above) we can see that the custom tables are at the end. So we can easily find by a few tries where the tables are, by ``changing`` the offset. So after ~5 tries we get the info we are looking for:
```
LIMIT with offset 60 =  INNODB_SYS_TABLESTATS 
LIMIT with offset 61 = 	constellation_list	
LIMIT with offset 62 =  constellation_secrets 
LIMIT with offset 63 = EMPTY
``` 

And here the name of the table already SCREAMS that we should view it's content.
So we want to see the content of the ``constellation_secrets`` (or more precisely: ``constellations.constellation_secrets``)



6) Getting the schema of the constellation_secrets

Since we can not be sure that this table has the same amount of columns as the other table (here: constellation_list), we need to determine it's columns, so we can UNION them propperly, without getting any errors. This information is stored at information_schema.columns

So i use a payload to print the column names:
``` 
'/**/UnIon/**/SeLect/**/1,2,(SeLect/**/GROUP_CONCAT(COLUMN_NAME)/**/FrOm/**/information_schema.columns/**/WhErE/**/TABLE_NAME/**/='constellation_secrets'),4/**/FrOm/**/dual/**/WhErE/**/'a'='a
``` 

!!! If here the problem would arrise that the table would have too many columns to print (or fit in one column), the same approach with LIMIT 'offset',1 would be useful. !!!

Now we get the coluomn names of constellation_secrets concatenated in the 3rd column:


```	
id
constellation_id
secretpaswd
```


And by this we know that we have 3 Columns. Since in the original query we have 4, we need to add 1 dummy column to match the schema. Therefor I decided to keep the SELECT ? FROM dual structure. And printed the content of the columns from constallation_secrets to the columns 1,2,3 by adding sub SELECT statements for each column. And so we can keep the schema of 4 columns i added the dummy 4 outside of the sub SELECTs, which is the outer select, that selcts from dual. So in the 4th column we will only see that 4.

After submiting the ``final payload`` and trying a few offsets for the LIMITs (all 3) we recieve following results: 

```
OFFSETS:
0 = 0, 4, nopeItsNotLupus
1 = 1, 6, EeLe9EiHNs5WDd5hnryw
2 = EMPTY
``` 

And since after the 3rd tried offset there is no data anymore we can assume that we found all the content.


``The final Payload:``

```
'/**/UnIon/**/SeLect/**/(SeLect/**/id/**/FrOm/**/constellation_secrets/**/LIMIT/**/1,1),(SeLect/**/constellation_id/**/FrOm/**/constellation_secrets/**/LIMIT/**/1,1),(SeLect/**/secretpaswd/**/FrOm/**/constellation_secrets/**/LIMIT/**/1,1),4/**/FrOm/**/dual/**/WhErE/**/'a'='a
```

Solution
--------
The solution could be ``prepared statemnts``
These statements don't have any parameters in it, just placeholders which the database checks/validates before processing them.

For the Constellation DB is could look something like:

```
<?php
$stmt = $dbConnection->prepare('SELECT * FROM constellation_list WHERE abbreviation = ? LIMIT 1');

$stmt->bind_param('s', $abbr);

$stmt->execute();

//....
//process the results
//....

?>
```


