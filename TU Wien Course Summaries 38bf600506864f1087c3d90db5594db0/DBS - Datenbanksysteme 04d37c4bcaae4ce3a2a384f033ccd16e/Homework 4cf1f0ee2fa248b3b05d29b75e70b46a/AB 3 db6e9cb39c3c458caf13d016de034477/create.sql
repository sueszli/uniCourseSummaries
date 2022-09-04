DROP TABLE IF EXISTS account, transaction, deposit, withdrawal, approved CASCADE;

CREATE TABLE account (
	no INTEGER PRIMARY KEY,
	balance INTEGER NOT NULL,
	max_overdraft INTEGER NOT NULL,
	fee INTEGER NOT NULL
);

CREATE TABLE transaction (
	id INTEGER PRIMARY KEY,
	sender INTEGER REFERENCES account,
	recipient INTEGER REFERENCES account,
	amount INTEGER NOT NULL
);

CREATE TABLE approved (
	transaction INTEGER PRIMARY KEY REFERENCES transaction
);


CREATE TABLE deposit (
	id INTEGER PRIMARY KEY,
	to_account INTEGER REFERENCES account,
	amount INTEGER NOT NULL
);

CREATE TABLE withdrawal (
	date DATE,
	from_account INTEGER REFERENCES account,
	amount INTEGER NOT NULL,
	PRIMARY KEY(date,from_account)
);



INSERT INTO account VALUES
 (1, 1240, 1000, 40),
 (2, 2300, 2000, 120),
 (3, 4039, 2000, 220),
 (4, 1603, 1300, 60),
 (5, 3021, 1700, 100),
 (6, 2509, 4000, 200),
 (7, 5002, 3000, 156);



INSERT INTO transaction VALUES
	(1, 1, 2, 300 ),
	(2, 2, 5, 200 ),
	(3, 5, 3, 500),
	(4, 7, 6, 900),
	(5, 6, 4, 200);
	
	
INSERT INTO 	approved VALUES
	(1),
	(3),
	(4),
	(5);	

INSERT INTO deposit VALUES
	(1, 3, 2000 ),
	(2, 6, 1000 );
	

INSERT INTO withdrawal VALUES
	('2021-10-5', 2, 200 ),
	('2021-10-2', 4, 400 );
