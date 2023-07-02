# NetRunner

Remote Administration Tool written in python.


## Usage

```
usage: ./netrunner.py [options] 

Remote Administration Tool

options:
  -h, --help        show this help message and exit
  -l, --listen      start server mode, listen on specified port
  -p , --port       specified port
  -t , --target     specified IP
  --max-listeners   specified max listening sessions. default[5]

Examples:
        # start a NetRunner in servermode 
        ./NetRunner.py -t 192.168.0.1 -p 5555 -l 

        # conect to a NetRunner server using NetRunner in client mode
        ./netrunner.py -t 192.168.0.1 -p 5555 

        NetRunnerCommands Engine
        # To use NRC Engine, we should first connect to a NR server using NR client

        # SHOW NRC HELP
        netrunner: #> $NRC HELP   

        # SHOW NRC MODULE HELP
        netrunner: #> $NRC [MODULE_NAME] HELP

https://github.com/mind2hex/

```


