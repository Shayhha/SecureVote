-- Drop existing database if it exists
DROP DATABASE IF EXISTS SecureVote;

-- Create the database
CREATE DATABASE SecureVote;

-- Use the new database
USE SecureVote;

-- Drop existing tables if they exist
IF OBJECT_ID('Votes', 'U') IS NOT NULL DROP TABLE Votes;
IF OBJECT_ID('Results', 'U') IS NOT NULL DROP TABLE Results;
IF OBJECT_ID('Voters', 'U') IS NOT NULL DROP TABLE Voters;

CREATE TABLE Voters (
    id INT IDENTITY(1,1) UNIQUE NOT NULL,
    voterId VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    firstName VARCHAR(255) NOT NULL,
    lastName VARCHAR(255) NOT NULL,
    address VARCHAR(255) NOT NULL,
    city VARCHAR(255) NOT NULL,
    state VARCHAR(255) NOT NULL
	PRIMARY KEY(id)
);


CREATE TABLE Votes (
    voteId INT IDENTITY(1,1) UNIQUE NOT NULL,
    voterId VARCHAR(255) UNIQUE NOT NULL,
    isVoted INT NOT NULL DEFAULT 0,
    PRIMARY KEY(voteId),
    FOREIGN KEY (voterId) REFERENCES Voters(voterId)
);


CREATE TABLE Results (
    centerId INT IDENTITY(1,1) UNIQUE NOT NULL,
    democratVotes INT NOT NULL DEFAULT 0,        
    republicanVotes INT NOT NULL DEFAULT 0,
    PRIMARY KEY(centerId)
);


-- Insert 3 voting centers
INSERT INTO Results (democratVotes, republicanVotes) 
VALUES (5, 5), (5, 5), (5, 5);


-- Insert 10 voters with random names, addresses, and states
INSERT INTO Voters (voterId, password, firstName, lastName, address, city, state)
VALUES 
('46fa3ff55a23ed2a5a1233b5a14980ba0831b029c270da6b46f6ad3f2afdaecd', '8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92', 'John', 'Smith', '1 Main St', 'Chicago', 'Illinois'),
('acd7e3fb091d8178cd75a97ee755f7cc31e8ff6f6fd024a4d4d51b23d59a0047', '8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92', 'Jane', 'Lee', '2 Oak St', 'Lincoln', 'Nebraska'),
('9c020c3158ebf45b18382b639baff425527f7503329e584ba3298990e39ef716', '8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92', 'James', 'Fox', '3 Pine St', 'Fishers', 'Indiana'),
('823c3d26c9c56fce9b876bfb2b338181cffa2303bdf362682b24b9c718079ccb', '8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92', 'Emily', 'Davis', '4 Birch St', 'Houston', 'Texas'),
('c6817e8b8863043ffd4b2f64a04d8d3ba5c017a08a96bda4d4efb58617957382', '8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92', 'Chris', 'Wilson', '5 Cedar St', 'Phoenix', 'Arizona'),
('0ca2905c2d71de390ec76893ecb890d595e7a67aad48c2478e64d89262d9ffea', '8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92', 'Jess', 'Mart', '6 Spruce St', 'San Diego', 'California'),
('97400605b2039e9739911403f4d9702ec265427331855b7fea9fabac0bf39bab', '8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92', 'Dave', 'Brown', '7 Birch Rd', 'Austin', 'Texas'),
('1a7b3f7a11e0f6c6684a6c686cdcd6457d78f1cddf8ccfc8848e099def5590a1', '8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92', 'Andy', 'Moore', '8 Redwood Ln', 'Dallas', 'Texas'),
('000e89df95e6dc37c8226fa9225e96d57bd8a14248bffd154950843937ddde03', '8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92', 'Dan', 'Taylor', '9 Cypress St', 'Oakland', 'California'),
('0a300bd3217701fa696602d17ff0fa28e08516b04c6f58965cf3c24b2880e216', '8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92', 'Elliot', 'Alderson', '15 Poplar St', 'Cortland', 'New York')


-- Insert initial vote entries for all 10 voters, with isVoted set to 1 (voted)
INSERT INTO Votes (voterId, isVoted) 
VALUES
('46fa3ff55a23ed2a5a1233b5a14980ba0831b029c270da6b46f6ad3f2afdaecd', 1),
('acd7e3fb091d8178cd75a97ee755f7cc31e8ff6f6fd024a4d4d51b23d59a0047', 1),
('9c020c3158ebf45b18382b639baff425527f7503329e584ba3298990e39ef716', 1),
('823c3d26c9c56fce9b876bfb2b338181cffa2303bdf362682b24b9c718079ccb', 1),
('c6817e8b8863043ffd4b2f64a04d8d3ba5c017a08a96bda4d4efb58617957382', 1),
('0ca2905c2d71de390ec76893ecb890d595e7a67aad48c2478e64d89262d9ffea', 1),
('97400605b2039e9739911403f4d9702ec265427331855b7fea9fabac0bf39bab', 1),
('1a7b3f7a11e0f6c6684a6c686cdcd6457d78f1cddf8ccfc8848e099def5590a1', 1),
('000e89df95e6dc37c8226fa9225e96d57bd8a14248bffd154950843937ddde03', 1),
('0a300bd3217701fa696602d17ff0fa28e08516b04c6f58965cf3c24b2880e216', 1)
