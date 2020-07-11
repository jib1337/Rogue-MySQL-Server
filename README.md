## Rogue-MySQL-Server

The script starts a MySQL server that requests and retrieves files from clients that connect to it.

### Features
- Single file retrieval or specify a file-list
- Specify a number of attempts to use for each file
- Tested on Windows and Linux

```
usage: RogueSQL.py [-h] [-p PORT] [-f--file SINGLEFILE] [-l FLIST]
                   [-a ATTEMPTS] [-v] [-d]

Rogue MySQL server

optional arguments:
  -h, --help            show this help message and exit
  -p PORT, --port PORT
  -f--file SINGLEFILE   Specify a single filename to retrieve
  -l FLIST, --filelist FLIST
                        Path to file with list of files for download.
  -a ATTEMPTS, --attempts ATTEMPTS
                        How many times to request a file before giving up
  -v, --verbose         Print files content in console.
  -d, --debug           Log debug messages
```

All downloaded files will be contained in `Downloads` folder.





