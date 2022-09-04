-- The supervisor checks for new transactions as they arrive, and approves them 
-- and also updates the database to reflect the new account balances

\i create.sql

\prompt 'Press Enter to start with Szenario 2 (1)', cont

BEGIN;
SET TRANSACTION ISOLATION LEVEL !!STATE TRANSACTION LEVEL!!;


\echo 'List of not approved transaction ids:'

(SELECT id FROM transaction) EXCEPT (SELECT * FROM approved);

\prompt 'Press Enter to continue (3)', cont


\echo 'Approve Transaction 2:'

UPDATE account set balance = balance + 200 where no = 2 ; 
UPDATE account set balance = balance - 200 where no = 5 ;

INSERT INTO approved VALUES 
	(2);


\echo 'List of not approved transactions:'

(SELECT id FROM transaction) EXCEPT (SELECT * FROM approved);


\echo 'Approve the new Task 6:'

UPDATE account set balance = balance + 200 where no = 4 ; 
UPDATE account set balance = balance - 200 where no = 3;

INSERT INTO approved VALUES 
	(6);


\prompt 'Press Enter to continue (5)', cont


\echo 'List of not approved transactions:'

(SELECT id FROM transaction) EXCEPT (SELECT * FROM approved);
COMMIT;
