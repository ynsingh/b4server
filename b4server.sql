create database b4server;
use b4server;

DROP TABLE IF EXISTS otp;
create table otp ( id int(11) auto_increment, otp VARCHAR(8), emailid varchar(25), ccert blob, primary key (id),unique key(emailid));

DROP TABLE IF EXISTS `crl`;
CREATE TABLE `crl` (
  `id` int(200) NOT NULL auto_increment,
  `email` varchar(2000) NOT NULL,
  `certificate` varchar(2000) NOT NULL,
  `reason` varchar(2000) NOT NULL,
  `expiry_date` varchar(2000) NOT NULL,
  `revocation_date` varchar(2000) NOT NULL,
  `certificate_srno` varchar(1000) NOT NULL,
   primary key (id)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

DROP TABLE IF EXISTS keystore;
CREATE TABLE `keystore` (
  `id` int(200) NOT NULL auto_increment,
  `nodeid` blob DEFAULT NULL,
  `emailid` varchar(25) NOT NULL,
  `privkey` blob DEFAULT NULL,
  `pubkey` varbinary(10000) DEFAULT NULL,
  `validdays` mediumtext DEFAULT NULL,
  `organisationalunit` varchar(50) DEFAULT NULL,
  `organisation` varchar(50) DEFAULT NULL,
  `city` varchar(50) DEFAULT NULL,
  `state` varchar(50) DEFAULT NULL,
  `country` varchar(50) DEFAULT NULL,
  `alias` varchar(50) DEFAULT NULL,
  `keypass` varchar(50) DEFAULT NULL,
  `device_id` blob DEFAULT NULL,
   primary key (id),
   unique key (emailid)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

DROP TABLE IF EXISTS `keystore_recovery`;
CREATE TABLE `keystore_recovery` (
  `id` int(200) NOT NULL auto_increment,
  `emailid` varchar(200) NOT NULL,
  `servercertificate` varchar(2000) NOT NULL,
  `clientcertificate` varchar(2000) NOT NULL,
  `keystore` mediumtext CHARACTER SET utf8 NOT NULL,
  `device_id` varchar(2000) NOT NULL,
  `node_id` varchar(1000) NOT NULL,
  `kr_date` varchar(1000) NOT NULL,
  `last_recovery_date` varchar(1000) NOT NULL,
   primary key (id),
   unique key (emailid)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

DROP TABLE IF EXISTS `multidevice`;
CREATE TABLE `multidevice` (
  `id` int(200) NOT NULL auto_increment,
  `emailid` varchar(1000) NOT NULL,
  `deviceid` varchar(1000) NOT NULL,
  `devicenodeid` blob NOT NULL,
  `lastaccessdate` varchar(2000) NOT NULL,
  `keystoretransferdate` varchar(2000) NOT NULL,
   primary key (id)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;


