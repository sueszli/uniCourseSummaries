-- Account is doing some analysis on the account balances.
-- To this end, they need to retrieve a consistent set of 
-- datapoints from the current state of database. x

\i create.sql

BEGIN;
SET TRANSACTION ISOLATION LEVEL !!STATE TRANSACTION LEVEL!!;

\prompt 'Press Enter to start with Szenario 3 (2)', cont



\echo 'List of unapproved transactions:'

SELECT id FROM transaction EXCEPT (SELECT * FROM approved);

\prompt 'Press Enter to continue (4)', cont


\echo 'Checking the average amounts of deposits and withdrawals:'
SELECT AVG(amount) FROM deposit; 
SELECT AVG(amount) FROM withdrawal; 

\prompt 'Press Enter to continue (6)', cont


\echo 'Sum of balances of all accounts not yet sending any transactions:'
SELECT SUM(balance) FROM account 
WHERE no NOT IN (SELECT sender FROM transaction);

COMMIT;
