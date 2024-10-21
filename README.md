EC2 - Hosting

Install MySQL in EC2 server
----------------------------------
wget https://dev.mysql.com/get/mysql84-community-release-el9-1.noarch.rpm

sudo dnf install mysql84-community-release-el9-1.noarch.rpm

sudo dnf install mysql-community-server

sudo systemctl status mysqld.service

sudo systemctl start mysqld


sudo cat /var/log/mysqld.log | grep 'password' (this command creates a temp. password)

mysql -u root -p (supply the above generated temp. password)

alter user root@localhost identified by 'Admin-123';

Exit
Login with the root user credentials and create another user

mysql -u root -p (Give new password here)
CREATE USER 'admin'@'%' IDENTIFIED BY 'Admin-123';
GRANT ALL ON *.* to 'admin'@'%';

CREATE DATABASE ccituserdb;
USE ccituserdb;
Create table
------------

CREATE TABLE `users` (
		  `Id` int NOT NULL AUTO_INCREMENT,
		  `name` varchar(100) DEFAULT NULL,
		  `email` varchar(100) DEFAULT NULL,
		  `password` varchar(255) DEFAULT NULL,
		  `image_url` varchar(255) DEFAULT NULL,
		  PRIMARY KEY (`Id`)
		);


---------------------------------------------------------------------------

EC2 -  Setup

yum install git python3-pip -y
pip install Flask bcrypt pymysql python-dotenv boto3


git clone https://github.com/Cloudintelugu/OnlineLibrary.git


CD OnlineLibrary


1) Make necessary changes in the "appsettings.env" file
2) Edit port number to 80 in app.py file

Run - python3 app.py

