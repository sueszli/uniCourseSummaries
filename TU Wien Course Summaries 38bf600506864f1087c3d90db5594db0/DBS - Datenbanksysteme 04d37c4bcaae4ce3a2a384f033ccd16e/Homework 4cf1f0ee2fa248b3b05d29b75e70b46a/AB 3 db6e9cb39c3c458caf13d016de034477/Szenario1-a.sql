-- The supervisor needs to check the current balance of each 
-- account to determine the fee  that needs to be paid (via a 
-- new entry in the widthdrawal table). She reduces the account 
-- balance and creates a new entry in withdraway with an atomic 
-- transaction, with the ability to do rollbacks. Her task shall 
-- restrict concurrency as little as possible, and inconsistencies
-- that do not relate to account balances do not matter. 

\i create.sql

DROP TABLE IF EXISTS b2, b4;

\prompt 'Press Enter to start with Szenario 2 (1)', cont

BEGIN;
SET TRANSACTION ISOLATION LEVEL !!STATE TRANSACTION LEVEL!!;

\echo 'List all relevant accounts and their fees and the current balance'

SELECT no, fee, balance, balance - fee as expected_new_balance FROM account
	WHERE no = 2 OR no = 4;
SELECT balance, fee INTO b2 FROM account where no = 2;	
SELECT balance, fee INTO b4 FROM account where no = 4;	

\prompt 'Press Enter to continue (3)', cont

\echo 'Update the balances and add new tuples to withdrawal table:'

UPDATE account SET balance = b2.balance - b2.fee FROM  b2 WHERE no = 2;
UPDATE account SET balance = b4.balance - b4.fee FROM b4 WHERE no = 4;

INSERT INTO withdrawal SELECT CURRENT_DATE,2,fee FROM b2;
INSERT INTO withdrawal SELECT CURRENT_DATE,4,fee FROM b4;

\prompt 'Press Enter to continue (5)', cont


\echo 'List all relevant ccounts and their new balances:'

SELECT no, fee, balance FROM account
	WHERE no = 2 OR no = 4;


COMMIT;
