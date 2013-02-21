snort_report
============

Waterloo ISS tools for getting reports from Snort.

Requirements
============

.srrc file, which should look a lot like a .my.cnf file. Sample:

[client]
user = mysql username
password = password for same
host = mysql server name

[mysql]
database = db name

[file]
path = full path to a list of good SIDs

GoodSIDList
===========

sid # comment
sid # comment

It doesn't support more than a single SID per line. Currently it assumes GID = 1.
