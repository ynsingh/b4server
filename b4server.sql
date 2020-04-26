create database b4server;
use b4server;
DROP TABLE IF EXISTS otp;
create table otp ( id int(11) auto_increment, otp VARCHAR(8), emailid varchar(25), ccert blob, primary key (id),unique key(emailid));
DROP TABLE IF EXISTS keystore;
create table keystore (  nodeid blob, emailid varchar(25), privkey blob, pubkey varbinary(10000),  validdays long, organisationalunit varchar(50) , organisation varchar(50) , city varchar(50), state varchar(50), country varchar(50), alias varchar(50), keypass varchar(50), primary  key (emailid));
