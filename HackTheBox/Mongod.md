# Mongod - Very Easy

```shell
rustscan -a 10.129.194.168 --range 0-65535 --ulimit 5000 -- -sV

mongo --host 10.129.194.168 --port 27017
#connect remotely

show dbs;

#we can select the database
use sensitive_information;

show collections;

#to print all contents of collection
db.flag.find().pretty();
```

```markdown
Open ports & services:

  * 22 - ssh - OpenSSH 8.2p1 (Ubuntu)
  * 27017 - mongodb - MongoDB 3.6.8

Researching about MongoDB and going through its documentation will help us in enumerating port 27017.

Using documentation, we can connect to remote MongoDB database.

By checking the correct database, we can print the 'flag' collection's contents to get flag.
```

1. How many TCP ports are open on the machine? - 2

2. Which service is running on port 27017 of the remote host? - MongoDB 3.6.8

3. What type of database is MongoDB? - NoSQL

4. What is the command name for the Mongo shell that is installed with the mongodb-clients package? - mongo

5. What is the command used for listing all the databases present on the MongoDB server? - show dbs

6. What is the command used for listing out the collections in a database? - show collections

7. What is the command used for dumping the content of all the documents within the collection named flag in a format that is easy to read?

8. Submit root flag - 1b6e6fb359e7c40241b6d431427ba6ea
