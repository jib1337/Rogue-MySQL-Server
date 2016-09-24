Rogue-MySql-Server
==================

~~Edit script and change file to read and server port if you want.~~ Run script and connect to your server for read file from client side.
~~Read mysql.log for readed file content.~~

```
usage: rogue_mysql_server.py [-h] [-p PORT] [-f FILES] [-v]

Rogue MySQL server

optional arguments:
  -h, --help                 show this help message and exit.
  -p PORT, --port PORT
  -f FILES, --files FILES    Path to file with list of files for download.
  -v, --verbose              Print files content in console.
```

All downloaded files will contained in `Download` folder.

## New feature:
Is not necessary restart script and make new query from client for every new file, just start and wait :)
Script will stop when all files will be downloaded or upon 256'th file (protocol restriction)

P.S. Tested on windows mysql client also.



