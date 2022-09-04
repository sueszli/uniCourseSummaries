-- While acounting is doing some analysis, new transactions come in
-- and other operations continue. 

\prompt 'Press Enter to start with Szenario 3 (1)', cont

INSERT INTO transaction VALUES
	(8,5,1,220);

\prompt 'Press Enter to continue (3)', cont

INSERT INTO deposit VALUES (6,7, 1220 );
INSERT INTO withdrawal VALUES (CURRENT_DATE, 2, 2 );


\prompt 'Press Enter to continue (5)', cont


INSERT INTO transaction VALUES
	(9,4,2,120);
