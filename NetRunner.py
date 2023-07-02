#!/usr/bin/env python


import argparse
import socket
import shlex
import subprocess
import base64
import textwrap
import threading
import platform
import os
import re
import psutil
import glob
from random import randint
from time import sleep


CYBERPUNK_SAMURAI_BANNER = """
4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA
4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qKA4qOg4qOk
4qGECuKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKg
gOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKigOKjtOKjv+Kj
v+Kgv+Kgk+KggArioIDioIDioIDioIDioIDioIDioIDioIDioIDioIDioIDioIDioIDioIDioIDi
oIDioIDioIDioIDioIDioIDioIDioIDioIDioIDioIDioIDioIDioIDioIDioIDioIDio7Dio7/i
o7/ioZ/ioIHioIDioIDioIDioIDioIDioIDioIDioIDioIDioIDioIDioIDioIDioIDioIDioYAK
4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA
4qCA4qCA4qOw4qCD4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qO44qO/4qO/4qGf4qCA4qKA4qGG
4qCA4qCA4qCA4qCA4qCA4qCA4qKA4qCACuKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKg
gOKggOKggOKggOKggOKggOKggOKggOKggOKhvOKggOKgheKggOKggOKggOKggOKigOKhhOKggOKg
gOKggOKjv+Kjv+Kjv+Kjl+KjoOKjvuKhh+KggOKggOKggOKggOKioOKghuKggArioIDioIDioIDi
oIDioIDioIDioIDioIDioIDioIDioIDioIDioIDioIDioIDioIDioIDioIDiorjioYfioIDioIDi
oIDioIDioIDioIDiorjio4bioIDioIDiorDio7/io7/io7/io7/io7/io6/ioIDiooDio7TioIbi
oIDioLvioIIK4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA
4qCA4qCA4qG84qO34qCA4qCA4qCA4qCA4qCA4qCA4qK44qO/4qCA4qKA4qO+4qO/4qO/4qO/4qO/
4qO/4qG/4qOl4qO+4qGf4qCACuKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKg
gOKggOKggOKggOKggOKggOKiu+Kjv+KhhuKggOKggOKjgOKjtOKjvuKjv+Kjv+Kjv+Kjv+Kjv+Kj
v+Kjv+Kjv+Kjv+Kjv+Kgj+KiueKjv+KggOKggOKggOKjtOKgg+KggOKjoOKhhuKigArioIDioIDi
oIDioIDioIDioIDioIDioIDioIDioIDioIDioIDioLHio4TioIDioIDioIDioIDioIjio7/ioYfi
oIDiorDio7/io7/io7/io7/io7/io7/io7/io7/io7/io7/io7/iob/ioIPioIDioJjioIHioIDi
oIDio7Dio7/ioIDiorDioJ/ioIDio6QK4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA
4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qKg4qO/4qCA4qCA4qCZ4qO/4qO/4qO/4qO/4qO/4qO/4qO/
4qO/4qO/4qO/4qO/4qCA4qKA4qCB4qCA4qKA4qOw4qO/4qO/4qG/4qCG4qCI4qCA4qOw4qO34qGE
CuKggOKggOKggOKggOKggOKgmOKiv+KjpuKjhOKggOKggOKggOKggOKggOKggOKggOKggOKggOKh
vuKjp+KhnOKggOKjoOKjv+Kjv+Kjv+Kjv+Khv+Kgi+KjueKjv+Kjv+Kjv+Kgn+KiuOKjv+KjpuKj
tOKjv+Kjv+Kjv+Khv+KggeKggOKggOKjvuKjv+Kjv+KggQrioIDioIDioIDioIDiooDioIDioIDi
ornio7/io6fioIDioIDioIDioIDioYDiooDio77iooDio7/io7/io7/io77io7/io7/io7/io7/i
oJvioIHioqDioL/ioJ/ioInioIHioIDiorjio7nio7/io7/ioJvioLvio6/ioIHioIDioIDio4Di
o7/ioL/ioIHioIDioIDioIDio4biorkK4qCA4qCA4qCw4qOE4qC44qO34qGE4qCA4qK/4qOf4qCA
4qCA4qCA4qCA4qO34qGA4qOH4qCA4qO/4qO/4qC/4qO/4qCb4qO/4qCP4qCA4qCA4qGE4qCA4qKA
4qO04qG+4qCB4qCA4qO84qO/4qG/4qCP4qCA4qCQ4qO/4qGE4qCA4qOw4qCL4qCA4qCA4qO64qCA
4qCA4qCA4qK54qOYCuKggOKggOKgoOKjveKjtuKhv+Kgh+KggOKggOKiieKggOKgtuKgkuKggOKg
mOKit+Kjv+KjpeKgiOKgv+KggOKgmOKihuKgmOKggOKioOKjv+KhgeKggOKjvuKjv+Kgg+KggOKj
uOKiv+Kjv+Kjh+KjgOKggOKigOKjv+Khh+KggOKhmOKggOKggOKguOKjv+KggOKggOKggOKiuOKg
gQrioIDioIDioIDioJjioIviooDioIDio4TioIDio4bioIHio77io7/io6fioIDioJjio7/io7/i
o6biorjio6bioIDioIjio6Tio7zio7/io7/io7/io77iob/ioIHioIDioIjio6Dio77io7/io7/i
o7/io7/io7/io7/ioYfiooDio6fioIDioLLio4Dio7/ioYbioIDioJAK4qCA4qCA4qCA4qCA4qG2
4qKg4qO+4qG/4qC34qC/4qK34qO/4qO/4qO/4qCH4qCA4qCL4qK54qO/4qO24qO/4qO34qO24qO/
4qO/4qO/4qCL4qCJ4qO/4qCD4qCA4qKA4qO+4qO/4qO/4qO/4qO/4qG/4qC74qCZ4qC/4qGH4qCI
4qO/4qCB4qCA4qO/4qCP4qCACuKggOKggOKggOKggOKhgOKgmeKhgeKgtuKjv+Khv+KikuKjoOKg
gOKhpOKggOKikOKggOKguOKjv+Kjv+Kjv+Kjv+Kjv+Khn+KgieKiv+KggOKiuOKjv+KhgOKggOKi
uOKjv+Kjv+Kjv+Kgn+KggeKggOKggOKggOKggOKiseKggOKgjuKgoOKglOKggQrioIDioIDio7bi
oIDioYfiooTioJjioLLio6bioLDioJ/ioInioJLioLLioYTioIDioIHiorjio7/ioJ/ioIHiorji
oJ/ioqPioIDioLvioYDioJjior/io7/io7/io7/io7/io7/ioI/ioIDioIDioIDioIDioIDioIDi
oJjioYbioIDio7bioIPio7DioYYK4qCC4qCA4qO/4qOm4qCI4qCI4qCb4qK24qOm4qCA4qG44qGA
4qCA4qCA4qG44qCA4qCA4qCI4qCB4qCA4qCw4qCD4qCA4qK44qOE4qCA4qCY4qCC4qGA4qK74qO/
4qG/4qCf4qCA4qKk4qCA4qCA4qCA4qCA4qCA4qCA4qKw4qCX4qKg4qGv4qKw4qO/4qCBCuKggOKj
vOKjv+Khv+KggeKggOKgiOKigOKjhOKggOKgt+KjrOKjkeKhqOKjtOKhh+KjtOKggOKigOKjhOKj
oOKjpOKjtOKjv+KjvuKjt+KihOKhgOKggOKgiOKggOKggOKgiOKgk+Kgi+KggOKggOKggOKggOKi
gOKjvOKgj+KggOKjuOKhh+KiqOKhjwrioIDioqvio7/ioYPioIDiorDio7/io6bio4XioYDioJvi
oLbioLbioLbioIzioIHioIDioIDioIDioIDioInioInio7/io7nio7/ioInioJnio4zioIDioIDi
oIDioIDioIDioIDioIDioIDioIDiooDio6TioZ7ioIHioIDio7DioqvioYfioIjioIAK4qCA4qCA
4qCI4qCH4qCY4qCY4qK/4qOl4qOA4qCJ4qCb4qO/4qO34qO24qO/4qO/4qGf4qKA4qO04qCC4qCA
4qCA4qCA4qC54qO/4qOn4qGA4qCA4qCZ4qKm4qGA4qCA4qCA4qKm4qOE4qOk4qOo4qOt4qOk4qOg
4qC04qCL4qCA4qC44qCB4qCA4qKm4qGACuKggOKggOKggOKggOKggOKggOKggOKjrOKjmeKhm+Kg
k+KgkuKikuKigOKjpOKggOKjhOKgu+Kjv+KjhOKggOKggOKggOKigOKjv+Kjv+KjveKjpuKhgOKg
gOKggOKgs+KjhOKhgOKggOKgiOKgm+Kgm+Kgm+KggeKggOKhoOKgnuKggeKggOKgu+KjpuKhueKj
puKhkOKihArioIDioIDioIDioIDioIDioIDioIDioIDioInioInioInio7vioJ/io5vio4Pio7ji
o7/ioYfio7nio7/iobfioIDio6DioJ/iorvio7/ior/ioJvioIvioIPioYTioIDioIjior/io7bi
o7bioKbiorbioZbioIbiooHio4TioJDior/io7fio4TioIjioLvio4ziorvio4bioKHioYAK4qCA
4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qKg4qKL4qO84qO/4qO/4qG/4qCZ4qKB4qO+4qO/
4qGH4qCA4qCA4qOg4qO+4qO/4qCA4qCA4qCA4qO04qCD4qCA4qOA4qOA4qGI4qCJ4qCb4qK34qO+
4qCA4qC74qO/4qO34qOE4qCZ4qCb4qOh4qOE4qG54qOn4qC54qGH4qKxCuKggOKggOKggOKggOKg
gOKggOKggOKggOKggOKggOKiuOKgmOKgl+KjoOKjjOKgm+KggOKgueKgv+Kgv+Kjh+KggOKggOKg
u+Kgv+Kgi+KggOKggOKgi+KggeKhlOKgmuKgieKjieKhi+KgkOKggOKggOKin+KggOKggOKgiOKg
u+Kjv+Kgh+KjgOKgiOKgm+Kim+Kjv+Khl+Kig+KhjArioIDioIDioIDioIDioIDioIDioIDioIDi
oIDio6Dio77iopvio7Tio7/io7/io6fioLDio7fiorDioYbio7bioqDioIDioLDio6bio6Tio6Ti
o7TioLbioInioIDiorDio77io7/io7/io6bioIjioIDioIDioIDioIDioIDioIDioKjioZjior/i
o7/io7/io7/io7/ioIfiobwK4qCA4qCA4qCA4qCA4qKA4qOA4qOk4qC24qKf4qOr4qO04qO/4qO/
4qO/4qO/4qCP4qCw4qOk4qGk4qCU4qCA4qCA4qCA4qCA4qCJ4qCJ4qCJ4qCB4qCA4qCA4qCA4qCI
4qC74qO/4qO/4qO/4qO34qOE4qCA4qCA4qCA4qCA4qCA4qCA4qCI4qCS4qCm4qCt4qCt4qCl4qCa
CuKggOKggOKgtOKgnuKjm+KjreKjtOKjvuKjv+Kjv+Kjv+Kjv+Kgv+Kgm+KjoeKiuOKjt+KjjOKg
k+KhgOKggOKggOKggOKggOKggOKggOKggOKggOKggOKgoOKggOKjpuKgkOKjjOKgu+Kiv+Kjv+Kj
v+Kjt+KjpuKjrOKjk+KhkuKgpOKgpArioIDioIDioKTio63io63io63io63io63io63io63io63i
oJDiorbioYPioInioJjioL/ioL/ioIjioYHio6Dio77io7/io7/ior/io7fio7bio4TioZnioILi
or7io7/ioIDioJ/io6Hio6Tio43ioZvioLvior/io7/io7/io7/iob/ioLbiopIK4qCA4qCA4qCA
4qCA4qCA4qCI4qCJ4qCB4qCA4qCA4qCA4qCA4qCI4qK/4qOk4qOA4qOA4qOm4qC/4qCb4qCJ4qKB
4qGA4qCA4qKA4qOA4qGA4qCZ4qC54qC/4qO34qOm4qOk4qOe4qO/4qO/4qCf4qCA4qCY4qCT4qCy
4qC24qC24qCS4qCL4qCBCuKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKg
gOKgiOKgk+Kgi+KjoeKhtOKigeKjtOKjv+Kjv+KjpuKjtuKjv+Kjt+KjhOKggOKituKjpOKjreKg
jeKgm+Kgm+KggQrioIDioIDioIDioIDioIDioIDioIDioIDioIDioIDioIDioIDioIDioIDioIDi
oIDioIDioIjiooHio77io7/io7/io7/io7/io7/io7/io7/io7/io7/ioITioJvioIEK4qCA4qCA
4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCI4qCb
4qC/4qC/4qCf4qC74qC/4qC/4qCf4qCLCg==
"""

def main():
    args = parse_arguments()

    if args.listen:
        nr = NetRunnerServer(args)
    else:
        nr = NetRunnerClient(args)

    
    nr.run()


def parse_arguments():
    """return parsed arguments"""

    parser = argparse.ArgumentParser(
        prog="./netrunner.py",
        usage="./netrunner.py [options] ",
        description="Remote Administration Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""Examples:
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
        """
        )
    )
    parser.add_argument(
        "-l",
        "--listen",
        action="store_true",
        help="start server mode, listen on specified port"
    )
    parser.add_argument(
        "-p",
        "--port",
        metavar="",
        required=True,
        type=int,
        help="specified port",
    )
    parser.add_argument(
        "-t",
        "--target",
        metavar="",
        required=True,
        help="specified IP"
    )
    parser.add_argument(
        "--max-listeners",
        metavar="",
        type=int,
        default=5,
        help="specified max listening sessions. default[5]"
    )    

    args = parser.parse_args()

    args.SERVER_STATUS = True

    return args


def print_cool_text(text, speed=0.03):
    """print_cool_text"""
    text1, text2 = "", ""
    for i, letter in enumerate(text):
        text1 += letter
        text2 = random_string(len(text) - len(text1))
        print(f"\r{text1}{text2}", end="")
        sleep(speed)
    print("")


def random_string(length):
    abc = "abcdefghijklmnopqrstuvwxyz"
    abc += abc.upper()
    abc += "0123456789"
    result = ""
    for i in range(length):
        result += abc[randint(0, len(abc)-1)]

    return result

    
def execute(cmd, shell=False):
    """
    execute(cmd): execute system commands
    returns the output of the command if success
    returns "[X] Error: error_description_message" if fail
    """
    cmd = cmd.strip()
    if not cmd:
        return 
    
    try:
        if shell:
            output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, shell=shell)
        else:
            output = subprocess.check_output(shlex.split(cmd), stderr=subprocess.STDOUT)
            
    except subprocess.CalledProcessError:
        return "[X] Error: returned error code while executing command...\n\n"
    except FileNotFoundError:
        return "[X] Error: File not found...\n\n"
    
    return output.decode()


class AsciiColors:
    TEXT     = "\033[94m"
    LEVEL_3  = "\033[93m"
    LEVEL_2  = "\033[92m"
    LEVEL_1  = "\033[91m"
    ENDC     = "\033[0m"


class NetRunnerServer:
    client_sockets = []

    def __init__(self, args, buffer=None):
        self.args = args
        self.buffer = buffer
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def run(self):
        """run() start NetRunner in the specified mode [server, client]"""
        server_text_banner = """
        ICAgIF8gICBfXyAgICAgX18gIF9fX18KICAgLyB8IC8gL19fICAvIC9fLyBfXyBcX18gIF9fX19f
        XyAgX19fXyAgX19fICBfX19fXwogIC8gIHwvIC8gXyBcLyBfXy8gL18vIC8gLyAvIC8gX18gXC8g
        X18gXC8gXyBcLyBfX18vCiAvIC98ICAvICBfXy8gL18vIF8sIF8vIC9fLyAvIC8gLyAvIC8gLyAv
        ICBfXy8gLwovXy8gfF8vXF9fXy9cX18vXy8gfF98XF9fLF8vXy8gL18vXy8gL18vXF9fXy9fLwog
        ICAgIF9fIF9fX19fX19fX18gXyAgICBfX19fX19fX19fX18gCiAgIF8vIC8vIF9fX18vIF9fIFwg
        fCAgLyAvIF9fX18vIF9fIFwgCiAgLyBfXy8gX18vIC8gL18vIC8gfCAvIC8gX18vIC8gL18vIC8g
        ICAgYXV0aG9yOiBtaW5kMmhleAogKF8gICkgL19fXy8gXywgXy98IHwvIC8gL19fXy8gXywgXy8K
        LyAgXy9fX19fXy9fLyB8X3wgfF9fXy9fX19fXy9fLyB8X3wKL18vCg==
        """
        print(base64.b64decode(CYBERPUNK_SAMURAI_BANNER).decode())
        print(base64.b64decode(server_text_banner).decode())
        print_cool_text("[!] Server mode...")
        self.listen()

    def listen(self):
        """listen() function, used to start listeners in server mode"""
        try:
            self.socket.bind((self.args.target, self.args.port))
            self.socket.listen(self.args.max_listeners)
        except Exception as e:
            print(f"[X] ERROR: {e}")
            exit(0)

        print_cool_text(f"[!] Listener started on {self.args.target}:{self.args.port}")            
        print_cool_text(f"[!]  Total listeners [{self.args.max_listeners}]")

        try:
            while True:  # accepting connection and starting connection threads
                client_socket, _ = self.socket.accept()
                NetRunnerServer.client_sockets.append(client_socket)
                client_thread = threading.Thread(target=self.handle, args=(client_socket,))
                client_thread.start()
        except KeyboardInterrupt:
            print_cool_text("[!] Finishing threads...")
            self.args.SERVER_STATUS = False
            for thread in threading.enumerate()[1:]:
                thread.join()

            print_cool_text("[!] Closing sockets...")
            for s in NetRunnerServer.client_sockets:
                s.close()

    def handle(self, client_socket):
        """handle(), this function handles all connections to the server 
        NetRunnerServer accept the next execution modes:
            # shell mode
            spawn a shell to clients that connects to NetRunnerServer
        """
        client_socket.settimeout(1.0)
        client_addr, client_port = client_socket.getsockname()
        print_cool_text(f"[!] Connection from {client_addr}:{client_port}")

        try:
            self.shell_mode(client_socket)
        except (BrokenPipeError, ConnectionResetError):
            print(f"[!] Connection closed from {client_addr}:{client_port}")
            client_socket.close()

    def shell_mode(self, client_socket):
        client_banner = "-" * 80 + "\n"
        client_banner += "%-20s:\t%s\n" % ("platform", platform.platform())
        client_banner += "%-20s:\t%s\n" % ("node", platform.node())
        client_banner += "%-20s:\t%s\n" % ("python version", platform.python_version())        
        client_banner += "-" * 80 + "\n"

        client_socket.send(client_banner.encode())
        while True:
            cmd_buffer = b''                
            try:
                while '\n' not in cmd_buffer.decode():
                    cmd_buffer += client_socket.recv(64)
                    if not cmd_buffer:  # client disconnected...
                        raise ConnectionResetError
            except socket.timeout:
                if not self.args.SERVER_STATUS:
                    return
                continue
                
            cmd_buffer = cmd_buffer.decode()

            if cmd_buffer.startswith("$NRC"):  # NRC engine commands 
                response = self.nrc_engine(cmd_buffer.rstrip("\n").split(" ")[1:])  
            else:  # executing normal os command
                response = execute(cmd_buffer)

            if response:
                client_socket.send(response.encode())

    def nrc_engine(self, nrc):
        """
        nrc stands for net runner command and is the command used
        in function nrc_engine (net runner command engine)
        """

        if len(nrc) == 0 or nrc[0] == "HELP":
            response = """
            HELP       : print this help message
            UPLOAD     : uploads a file, you have to specify path
            DOWNLOAD   : download a file, you have to specify a path
            ENUMERATE  : perform basic system enumeration
            """

        elif nrc[0] == "UPLOAD":
            """ i dont have idea how to do this... yet"""
            pass
        elif nrc[0] == "DOWNLOAD":
            """ i dont have idea neither"""
            pass
        elif nrc[0] == "ENUMERATE":
            if platform.system() == "Linux":
                # https://book.hacktricks.xyz/linux-hardening/linux-privilege-escalation-checklist
                enumeration_modules = {
                    "SYSTEM":self.nrc_engine_enumerate_Linux_system,
                    "DRIVES":self.nrc_engine_enumerate_Linux_drives,
                    "SOFTWARE":self.nrc_engine_enumerate_Linux_software,
                    "PROCESS":self.nrc_engine_enumerate_Linux_processes,
                    "CRONJOBS":self.nrc_engine_enumerate_Linux_cronjobs,
                    "SERVICES":self.nrc_engine_enumerate_Linux_services,
                    "TIMER":self.nrc_engine_enumerate_Linux_timer,
                    "SOCKETS":self.nrc_engine_enumerate_Linux_sockets,
                    "DBUS":self.nrc_engine_enumerate_Linux_dbus,
                    "NETWORK":self.nrc_engine_enumerate_Linux_network,
                    "USERS":self.nrc_engine_enumerate_Linux_users,
                    "WPATHS":self.nrc_engine_enumerate_Linux_writable_paths,
                    "SUIDGUID":self.nrc_engine_enumerate_Linux_SUID_GUID,
                    "CAPAB":self.nrc_engine_enumerate_Linux_capabilites,
                    "ACLS":self.nrc_engine_enumerate_Linux_acls,
                    "SHELLS":self.nrc_engine_enumerate_Linux_shell_sessions,
                    "SSH":self.nrc_engine_enumerate_Linux_ssh,
                    "INTFILES":self.nrc_engine_enumerate_Linux_interesting_files,
                    "WFILES":self.nrc_engine_enumerate_Linux_writable_files,
                    "ALL":self.nrc_engine_enumerate_Linux
                }
                if len(nrc) > 1:  # linux $NRC ENUMERATE HELP MESSAGE
                    try:
                        response = enumeration_modules[nrc[1]]()
                    except:
                        response =  "$NRC ENUMERATE [SYSTEM|DRIVES |SOFTWARE|PROCESS|CRONJOBS|SERVICES]\n"
                        response += "               [TIMER |SOCKETS|DBUS    |NETWORK|USERS   |WPATHS  |SUIDGUID]\n"
                        response += "               [CAPAB |ACLS   |SHELLS  |SSH    |INTFILES|WFILES  | ALL]\n"
                        response += "               [default ALL]\n"
                else:
                    response = self.nrc_engine_enumerate_Linux()
            elif platform.system() == "Windows":
                # https://book.hacktricks.xyz/windows-hardening/checklist-windows-privilege-escalation
                #response = self.nrc_engine_enumerate_Windows()
                response = "WINDOWS ENUMERATION NOT IMPLEMENTED YET"
        elif nrc[0] == "KEYLOGGER":
            pass
        elif nrc[0] == "LOOT":
            pass
        else:
            response = "INVALID NRC COMMAND, USE $NRC HELP" 

        return response 

    def nrc_engine_enumerate_Linux(self):
        response = self.nrc_engine_enumerate_Linux_system()
        response += self.nrc_engine_enumerate_Linux_drives()
        response += self.nrc_engine_enumerate_Linux_software()
        response += self.nrc_engine_enumerate_Linux_processes()
        response += self.nrc_engine_enumerate_Linux_cronjobs()
        response += self.nrc_engine_enumerate_Linux_services()
        response += self.nrc_engine_enumerate_Linux_timer() 
        """
        response += self.nrc_engine_enumerate_sockets()   + "\n"
        response += self.nrc_engine_enumerate_dbus()      + "\n"
        response += self.nrc_engine_enumerate_network()   + "\n"
        response += self.nrc_engine_enumerate_users()     + "\n"
        response += self.nrc_engine_enumerate_writable_paths() + "\n"
        response += self.nrc_engine_enumerate_SUID_GUID() + "\n"
        response += self.nrc_engine_enumerate_capabilites() + "\n"
        response += self.nrc_engine_enumerate_acls()      + "\n"
        response += self.nrc_engine_enumerate_shell_sessions() + "\n"
        response += self.nrc_engine_enumerate_ssh()       + "\n"
        response += self.nrc_engine_enumerate_interesting_files() + "\n"
        response += self.nrc_engine_enumerate_writable_files() + "\n"
        """
        return response 

    def nrc_engine_enumerate_Linux_system(self):
        """ 
        https://book.hacktricks.xyz/linux-hardening/privilege-escalation#system-information
        nrc_engine_enumerate_system() performs system enumeration
        - architecture and release info
        - writable paths in $PATH
        - kernel exploits
        - sudo enumeration
        - dmesg enumeration
        - more system info (date, system, stats, cpu_info, printers)
        """
        separator = "="*30 + "%30s" + "="*30 + "\n"
        
        response = separator % (f"{AsciiColors.TEXT}SYSTEM INFORMATION{AsciiColors.ENDC}".center(30))
        # OS information https://book.hacktricks.xyz/linux-hardening/privilege-escalation#os-info
        response += "[!] %-25s:  %20s\n" % (f"{AsciiColors.TEXT}OS INFORMATION{AsciiColors.ENDC}", "".join(platform.uname()))

        # searching for writable paths in $PATH  https://book.hacktricks.xyz/linux-hardening/privilege-escalation#path
        response += "\n[!] %-25s:  %20s\n" % (f"{AsciiColors.TEXT}EXECUTABLE PATH{AsciiColors.ENDC}", ":".join(os.get_exec_path()))
        for i, path in enumerate(os.get_exec_path()):  
            if os.access(path, os.W_OK):
                response += f"\t{AsciiColors.LEVEL_1}WRITABLE --> %-20s{AsciiColors.ENDC}\n" % (path)

        # searching for useful info in Env variables https://book.hacktricks.xyz/linux-hardening/privilege-escalation#env-info
        response += "\n[!] %-25s: \n" % (f"{AsciiColors.TEXT}ENV VARIABLES{AsciiColors.ENDC}" )
        for env_var in os.environ:
            response += "\t%-40s %-s\n" % (env_var, os.getenv(env_var))

        # inspect kernel https://book.hacktricks.xyz/linux-hardening/privilege-escalation#kernel-exploits
        response += "\n[!] %-25s:  %20s" % (f"{AsciiColors.TEXT}KERNEL INFORMATION{AsciiColors.ENDC}", execute("cat /proc/version"))

        # inspect sudo https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-version
        response += "\n[!] %-25s:\n" % (f"{AsciiColors.TEXT}SUDO INFORMATION{AsciiColors.ENDC}")
        for row in execute("sudo -V").split("\n"):
            response += f"\t{row}\n"
            
        # checking dmesg signature verification failed https://book.hacktricks.xyz/linux-hardening/privilege-escalation#dmesg-signature-verification-failed
        response += "[!] %-25s:" % (f"{AsciiColors.TEXT}DMESG SIGNATURE{AsciiColors.ENDC}")
        signature_info = re.findall(".*signature.*", execute("dmesg"))
        if len(signature_info) == 0:
            response += " NOT FOUND \n"
        else:
            for signature in signature_info:
                response += f"\t{signature}\n"

        # checking more system information https://book.hacktricks.xyz/linux-hardening/privilege-escalation#more-system-enumeration
        response += "\n[!] %-25s:  %20s\n" % (f"{AsciiColors.TEXT}DATE{AsciiColors.ENDC}", execute("date"))  # date

        response += "[!] %-25s:\n" % (f"{AsciiColors.TEXT}SYSTEM STATS{AsciiColors.ENDC}")  # lsblk
        for row in execute("lsblk").split("\n"):
            response += f"\t{row}\n"

        response += "[!] %-25s:\n" % (f"{AsciiColors.TEXT}CPU INFO{AsciiColors.ENDC}")  # lscpu
        for row in execute("lscpu").split("\n"):
            response += f"\t{row}\n"
        
        # enumerate system defenses https://book.hacktricks.xyz/linux-hardening/privilege-escalation#enumerate-possible-defenses
        response += "[!] %-25s:\n" % (f"{AsciiColors.TEXT}SYSTEM DEFENSES{AsciiColors.ENDC}")   
        for command in [
            "which aa-status", 
            "which apparmor_status", 
            "which paxctl-ng",
            "which paxctl",
            "which sestatus"]: # "APP ARMOR":
            temporal_response = execute(command)
            if temporal_response.startswith("[X] Error"):
                response += "\t%-24s %20s\n" % (command, "NOT ENABLED")
            else:
                response += "\t%-24s %20s\n" % (command, execute(command))

        if re.search("exec-shield", execute("cat /etc/sysctl.conf")):
            response += "\t%-24s %20s\n" % ("EXEC SHIELD", "ENABLED")
        else:
            response += "\t%-24s %20s\n" % ("EXEC SHIELD", "NOT ENABLED")
        
        if not execute("cat /proc/sys/kernel/randomize_va_space").startswith("0"):
            response += "\t%-24s %20s\n" % ("ASLR", "ENABLED")
        else:
            response += "\t%-24s %20s\n" % ("ASLR", "NOT ENABLED")
        
        return response
    
    def nrc_engine_enumerate_Linux_drives(self):
        """
        https://book.hacktricks.xyz/linux-hardening/privilege-escalation#drives
        nrc_engine_enumerate_drives() 
        returns info about mounted and unmounted drvies devices
        """
        separator = "="*30 + "%30s" + "="*30 + "\n"
        response = separator % (f"{AsciiColors.TEXT}DRIVES INFORMATION{AsciiColors.ENDC}".center(30))

        # list mounted drives
        response += "[!] %-25s:\n" % (f"{AsciiColors.TEXT}MOUNTED DRIVES{AsciiColors.ENDC}")   
        for row in execute("df -h").split("\n"):
            response += "\t" + row + "\n" 

        # list unmounted drives
        response += "[!] %-25s:\n" % (f"{AsciiColors.TEXT}UMOUNTED DRIVES{AsciiColors.ENDC}")   
        for row in execute("lsblk").split("\n"):
            response += "\t" + row + "\n" 

        # reading fstab
        response += "[!] %-25s:\n" % (f"{AsciiColors.TEXT}FSTAB{AsciiColors.ENDC}")   
        for row in execute("cat /etc/fstab").split("\n"):
            response += "\t" + row + "\n" 

        return response
    
    def nrc_engine_enumerate_Linux_software(self):
        """
        https://book.hacktricks.xyz/linux-hardening/linux-privilege-escalation-checklist#installed-software
        nrc_engine_enumerate_software()
        returns info about any software useful to a pentesting installed 
        in machine which server is executing on
        """
        separator = "="*30 + "%30s" + "="*30 + "\n"
        response = separator % (f"{AsciiColors.TEXT}SOFTWARE INFORMATION{AsciiColors.ENDC}".center(30))        
        
        # https://book.hacktricks.xyz/linux-hardening/privilege-escalation#useful-software
        response += "[!] %-25s:\n" % (f"{AsciiColors.TEXT}USEFUL TOOLS{AsciiColors.ENDC}")   
        useful_tools = [
            'nmap', 'aws', 'nc', 'ncat', 'netcat', 
            'nc.traditional', 'wget', 'curl', 'ping', 
            'gcc', 'g++', 'make', 'gdb', 'base64', 
            'socat', 'python', 'python2', 'python3', 
            'python2.7', 'python2.6', 'python3.6', 
            'python3.7', 'perl', 'php', 'ruby', 'xterm', 
            'doas', 'sudo', 'fetch', 'docker', 'lxc', 
            'ctr', 'runc', 'rkt', 'kubectl'
        ]
        for i, tool in enumerate(useful_tools):
            tmp_text = execute(f"which {tool}")
            if "[X] Error" in tmp_text:
                tmp_text = "[NOT FOUND]\n"
            response += "\t%-15s %s"%(tool, tmp_text)


        # https://book.hacktricks.xyz/linux-hardening/privilege-escalation#vulnerable-software-installed
        response += "\n[!] %-25s:\n" % (f"{AsciiColors.TEXT}INSTALLED SOFTWARE{AsciiColors.ENDC}")   

        result = execute("dpkg -l")  # trying with dpkg
        if "[X] Error" not in result: 
            package_list = result.split('\n')
            for package in package_list[5:]:  # first 5 lines are metadata to be ignored
                if package:
                    parts = package.split()
                    package_name = parts[1]
                    version = parts[2]
                    response += "\t%-40s %s\n" %(package_name, version)
        
        else:
            result = execute ("rpm -l")  # trying with rpm
            if "[X] Error" not in result:
                package_list = result.split('\n')
                for package in package_list:
                    if package:
                        parts = package.split('-')
                        package_name = '-'.join(parts[:-2])
                        version = '-'.join(parts[-2:])
                        response += "\t%-40s %s\n" %(package_name, version)
            else:
                result = execute ("pacman -Q")  # trying with pacman
                if "[X] Error" not in result:
                    package_list = result.split('\n')
                    for package in package_list:
                        if package:
                            parts = package.split()
                            package_name = parts[0]
                            version = parts[1]
                            response += "\t%-40s %s\n" %(package_name, version)
                else:
                    # What the hell package manager are you using?
                    pass
        
        return response
    
    def nrc_engine_enumerate_Linux_processes(self):
        """
        https://book.hacktricks.xyz/linux-hardening/privilege-escalation#processes
        nrc_engine_enumerate_Linux_processes()
        use psutils to enumerate system process
        """
        separator = "="*30 + "%30s" + "="*30 + "\n"
        response = separator % (f"{AsciiColors.TEXT}PROCESSES{AsciiColors.ENDC}".center(30))                

        # enumerating active processes
        response += "\n[!] %-25s:\n" % (f"{AsciiColors.TEXT}PROCESS MONITOR: (20 secs){AsciiColors.ENDC}")   
        pid_list_log = list()
        for i in range(20):  # 10 iterations equals 10 seconds
            for pid in psutil.pids():
                if pid not in pid_list_log:
                    try:
                        process = psutil.Process(pid)
                    except: 
                        continue
                    pid_list_log.append(pid)
                    response += f"\t{pid} {process.name()} {process.cmdline()}\n"
            sleep(1)        

        return response
    
    def nrc_engine_enumerate_Linux_cronjobs(self):
        """
        https://book.hacktricks.xyz/linux-hardening/privilege-escalation#scheduled-jobs
        """
        separator = "="*30 + "%30s" + "="*30 + "\n"
        response = separator % (f"{AsciiColors.TEXT}CRONJOBS{AsciiColors.ENDC}".center(30))                

        # executing crontab -l for current user
        response += "\n[!] %-25s:\n" % (f"{AsciiColors.TEXT}CRONTAB: {AsciiColors.ENDC}")   
        for row in execute("crontab -l").split("\n"):
            response += f"\t{row}\n"

        # showing /etc/crontab 
        response += "\n[!] %-25s:\n" % (f"{AsciiColors.TEXT}/etc/crontab:{AsciiColors.ENDC}")   
        for row in execute("cat /etc/crontab").split("\n"):
            response += f"\t{row}\n"

        # listing /etc/cron*
        response += "\n[!] %-25s:\n" % (f"{AsciiColors.TEXT}/etc/cron*:{AsciiColors.ENDC}")   
        for row in execute("ls -l /etc/cron*", shell=True).split("\n"):
            response += f"\t{row}\n"

        return response
    
    def nrc_engine_enumerate_Linux_services(self):
        """
        https://book.hacktricks.xyz/linux-hardening/privilege-escalation#services
        """
        separator = "="*30 + "%30s" + "="*30 + "\n"
        response = separator % (f"{AsciiColors.TEXT}SERVICES{AsciiColors.ENDC}".center(30))                

        # searching writable .service files
        response += "\n[!] %-25s:\n" % (f"{AsciiColors.TEXT}WRITABLE SERVICES:{AsciiColors.ENDC}")   
        service_directories = [
            "/lib/systemd/system/",
            "/etc/systemd/system/",
            "/run/systemd/system/"
        ]
        for directory in service_directories:
            for service in glob.glob(f"{directory}/*.service"):
                if os.access(service, os.W_OK):
                    response += f"\t{AsciiColors.LEVEL_1}WRITABLE --> %-20s{AsciiColors.ENDC}\n" % (service)

        # searching writable .service files
        response += "\n[!] %-25s:\n" % (f"{AsciiColors.TEXT}WRITABLE SERVICES EXECs:{AsciiColors.ENDC}")   
        for directory in service_directories:
            for service in glob.glob(f"{directory}/*.service"):
                try:
                    file_content = execute(f"cat {service}", shell=True)
                    result = re.search("ExecStart.*", file_content).group().split("=")[1]
                    if os.access(result, os.W_OK):
                        response += "\n"
                        response += f"\t{AsciiColors.LEVEL_1}WRITABLE SERVICE EXECUTABLE FOUND{AsciiColors.ENDC}\n" 
                        response += f"\tSERVICE -> {service}\n"
                        response += f"\tEXECUTABLE USED BY SERVICE -> {result} \n"
                        response += "\n"
                except:
                    continue

        # searching for writable paths in systemctl PATH
        response += "\n[!] %-25s:\n" % (f"{AsciiColors.TEXT}WRITABLE SYSTEMCTL PATHS:{AsciiColors.ENDC}")   
        try:
            systemctl_paths = re.search("PATH.*", execute("systemctl show-environment")).group()
            systemctl_paths = systemctl_paths.split("=")[1].split(":")

            for path in systemctl_paths:
                if os.access(result, os.W_OK):
                    response += f"\t{AsciiColors.LEVEL_1}WRITABLE --> %-20s{AsciiColors.ENDC}\n" % (path)
        except:
            pass
        
        return response
            
    def nrc_engine_enumerate_Linux_timer(self):
        """
        https://book.hacktricks.xyz/linux-hardening/privilege-escalation#timers
        """
        separator = "="*30 + "%30s" + "="*30 + "\n"
        response = separator % (f"{AsciiColors.TEXT}TIMERS{AsciiColors.ENDC}".center(30))                

        # listing timers
        response += "\n[!] %-25s:\n" % (f"{AsciiColors.TEXT}TIMERS/ACTIVATES:{AsciiColors.ENDC}")   

        for row in execute("systemctl list-timers --all").split("\n"):
            try:
                timer = re.search("[^ ]*timer.*service", row).group().split()
                response += "\t%-30s %-s\n" % (timer[0], timer[1])
            except:
                continue

        return response
            
    def nrc_engine_enumerate_Linux_sockets(self):
        return "nrc_engine_enumerate_sockets NOT IMPLEMENTED YET"
            
    def nrc_engine_enumerate_Linux_dbus(self):
        return "nrc_engine_enumerate_dbus NOT IMPLEMENTED YET"
            
    def nrc_engine_enumerate_Linux_network(self):
        return "nrc_engine_enumerate_network NOT IMPLEMENTED YET"
    
    def nrc_engine_enumerate_Linux_users(self):
        return "nrc_engine_enumerate_users NOT IMPLEMENTED YET"
            
    def nrc_engine_enumerate_Linux_writable_paths(self):
        return "nrc_engine_enumerate_paths NOT IMPLEMENTED YET"
            
    def nrc_engine_enumerate_Linux_SUID_GUID(self):
        return "nrc_engine_enumerate_SUID_GUID NOT IMPLEMENTED YET"
            
    def nrc_engine_enumerate_Linux_capabilites(self):
        return "nrc_engine_enumerate_capabilities NOT IMPLEMENTED YET"
            
    def nrc_engine_enumerate_Linux_acls(self):
        return "nrc_engine_enumerate_acls NOT IMPLEMENTED YET"        
            
    def nrc_engine_enumerate_Linux_shell_sessions(self):
        return "nrc_engine_enumerate_sessions NOT IMPLEMENTED YET"                
            
    def nrc_engine_enumerate_Linux_ssh(self):
        return "nrc_engine_enumerate_ssh NOT IMPLEMENTED YET"                        
            
    def nrc_engine_enumerate_Linux_interesting_files(self):
        return "nrc_engine_enumerate_interesting_files NOT IMPLEMENTED YET"                                
            
    def nrc_engine_enumerate_Linux_writable_files(self):
        return "nrc_engine_enumerate_writable_files NOT IMPLEMENTED YET"                                        


class NetRunnerClient():
    def __init__(self, args, buffer=None):
        self.args = args
        self.buffer = buffer
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def run(self):
        """run() start NetRunner in the specified mode [server, client]"""
        client_text_banner = """
        ICAgIF8gICBfXyAgICAgX18gIF9fX18KICAgLyB8IC8gL19fICAvIC9fLyBfXyBcX18gIF9fX19f
        XyAgX19fXyAgX19fICBfX19fXwogIC8gIHwvIC8gXyBcLyBfXy8gL18vIC8gLyAvIC8gX18gXC8g
        X18gXC8gXyBcLyBfX18vCiAvIC98ICAvICBfXy8gL18vIF8sIF8vIC9fLyAvIC8gLyAvIC8gLyAv
        ICBfXy8gLwovXy8gfF8vXF9fXy9cX18vXy8gfF98XF9fLF8vXy8gL18vXy8gL18vXF9fXy9fLwog
        ICBfX19fX19fX18gICAgICAgICAgICBfXwogIC8gX19fXy8gKF8pX18gIF9fX18gIC8gL18KIC8g
        LyAgIC8gLyAvIF8gXC8gX18gXC8gX18vICAgICBhdXRob3I6IG1pbmQyaGV4Ci8gL19fXy8gLyAv
        ICBfXy8gLyAvIC8gL18KXF9fX18vXy9fL1xfX18vXy8gL18vXF9fLwo=
        """
        print(base64.b64decode(CYBERPUNK_SAMURAI_BANNER).decode())
        print(base64.b64decode(client_text_banner).decode())
        print_cool_text("[!] Client mode...")

        try:  # trying to connect to target on the specified port
            self.connect()
        except ConnectionRefusedError:
            print_cool_text("[X] Connection refused...")
            exit(0)            

    def connect(self):
        self.socket.connect((self.args.target, self.args.port))
        
        try:
            while True:  # start session loop
                recv_len = 1
                response = ""
                while recv_len:
                    data = self.socket.recv(4096)
                    recv_len = len(data)
                    response += data.decode()
                    if recv_len < 4096:
                        break
                    
                if response:
                    print(response)

                    while True: # loop until user introduce a valid command
                        buffer = input("netrunner: #> ")
                        buffer += "\n"

                        if not self.check_command(buffer):  # checking if user introduced a valid command
                            print_cool_text("[!] No command introduced...") 
                            continue

                        break

                    self.socket.send(buffer.encode())
                else:
                    raise ConnectionResetError

        except ConnectionResetError:
            print("\n")
            print_cool_text("[X] Connection finished by server...")
            self.socket.close()

        except KeyboardInterrupt:
            print("\n")
            print_cool_text("[X] Program finished by user...")
            self.socket.close()

    def check_command(self, cmd):
        """ check_command(cmd)  
        validates cmd 
        """

        if len(cmd.replace("\n", "").replace(" ", "")) == 0:  # checking empty commands
            return False
        
        return True


if __name__ == "__main__":
    main()


### FIXME
# FIXME: Cuando se inicia una shell desde NRClient, no se puede navegar entre directorios
# FIXME: Cuando se ejecutan comandos interactivos como una shell o un ping sin final, el programa queda congelado...
# FIXME: Intentar usar librerias estandar para evitar el uso de pip install


### TODO
# TODO: Terminar de implementar la seleccion de enumeracion en la linea 265
# TODO: Implementar el NRC Engine para la ejecucion de custom commands en servidor y cliente
# TODO: Implementar sistema de contrasena para el servidor
# TODO: Implementar debug/verbose
# TODO: Implementar cifrado de datos para el envio de la comunicacion
# TODO: Implementar Persistencia, insertar revshell en el host
# TODO: Implementar LOOTing, descargar archivos con extension especifica

### HACK

# HACK: Mejorar output, mas colorido...
# HACK: Mejorar la documentacion 
