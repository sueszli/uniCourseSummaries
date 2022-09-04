-- While the supervisor does her job, buisness goes on...


\echo 'List all relevant accounts and their current balances:'

SELECT no, balance FROM account
	WHERE no = 2 OR no = 4;

\prompt 'Press Enter to start with Szenario 2 (2)', cont


-- new deposits to accounts

 
INSERT INTO deposit VALUES (3,2,100);
UPDATE account SET balance = balance + 100 WHERE no = 2;

\echo 'Adding 100 to account 2'

INSERT INTO deposit VALUES (4,4,400);
UPDATE account SET balance = balance + 400 WHERE no = 4;


\echo 'Adding 400 to account 4'

\prompt 'Press Enter to continue (4)', cont

\echo 'List all relevant accounts and their new balances:'

SELECT no, balance FROM account
	WHERE no = 2 OR no = 4;
