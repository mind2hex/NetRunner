#!/usr/bin/env python


import argparse
import socket
import shlex
import subprocess
import sys
import textwrap
import threading
import platform
import os
from random import randint
from time import sleep


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
        description="python net tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""Examples:
        # start a listener and spawn a shell to clients 
        ./netrunner.py -t 192.168.0.1 -p 5555 -l -s  

        # start a listener and send back to clients the output of the specified command 
        ./netrunner.py -t 192.168.0.1 -p 5555 -l -c "cat /etc/passwd"  

        # connect to a server using client mode                 
        ./netrunner.pt -t 192.168.0.1 -p 5555                                  

        # using NetRunnerCommands Engine
        # To use NRC Engine, a server must be started in shell mode with -s argument
        netrunner: #> $NRC {COMMAND} [OPTIONS]     # BASIC USAGE
        netrunner: #> $NRC FILE_UPLOAD /local/filepath  # FILE UPLOAD
        netrunner: #> $NRC FILE_DOWNLOAD 

        https://github.com/mind2hex/
        """
        )
    )
    parser.add_argument(
        "-s",
        "--shell",
        action="store_true",
        help="spawn command shell to clients [SERVER MODE ONLY]"
    )
    parser.add_argument(
        "-e",
        "--execute",
        metavar="",
        help="execute specified command and send output to clients [SERVER MODE ONLY]"
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

    
def execute(cmd):
    """execute(cmd)
    executes cmd in the operating system and returns its output after execution
    """
    cmd = cmd.strip()
    if not cmd:
        return 
    
    try:
        output = subprocess.check_output(shlex.split(cmd), stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError:
        return "[X] Error executing command...\n\n"
    except FileNotFoundError:
        return "[X] File not found...\n\n"
    
    return output.decode()


class NetRunnerServer:
    client_sockets = []

    def __init__(self, args, buffer=None):
        self.args = args
        self.buffer = buffer
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def run(self):
        """run() start NetRunner in the specified mode [server, client]"""
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

            # command mode
            execute a command and sends the output to the clients that connects to NetRunnerServer
        """
        client_socket.settimeout(1.0)
        client_addr, client_port = client_socket.getsockname()
        print_cool_text(f"[!] Connection from {client_addr}:{client_port}")

        if self.args.execute:  # executes self.args.execute and sends back the output to the client
            self.exec_mode(self, client_socket)            

        elif self.args.shell:  # spawn a custom shell to the client
            try:
                self.shell_mode(client_socket)
            except (BrokenPipeError, ConnectionResetError):
                print(f"[!] Connection closed from {client_addr}:{client_port}")
                client_socket.close()
            

    def exec_mode(self, client_socket):
        output = execute(self.args.execute)
        client_socket.send(output.encode())
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

        if nrc[0] == "HELP":
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
            # https://book.hacktricks.xyz/linux-hardening/linux-privilege-escalation-checklist

            response = self.nrc_engine_enumerate_system()
            response += self.nrc_engine_enumerate_drives()
            response += self.nrc_engine_enumerate_software()
            response += self.nrc_engine_enumerate_processes()
            response += self.nrc_engine_enumerate_cronjobs()
            response += self.nrc_engine_enumerate_services()
            response += self.nrc_engine_enumerate_timer()
            response += self.nrc_engine_enumerate_sockets()
            response += self.nrc_engine_enumerate_dbus()
            response += self.nrc_engine_enumerate_network()
            response += self.nrc_engine_enumerate_users()
            response += self.nrc_engine_enumerate_writable_paths()
            response += self.nrc_engine_enumerate_SUID_GUID()
            response += self.nrc_engine_enumerate_capabilites()
            response += self.nrc_engine_enumerate_acls()
            response += self.nrc_engine_enumerate_shell_sessions()
            response += self.nrc_engine_enumerate_ssh()
            response += self.nrc_engine_enumerate_interesting_files()
            response += self.nrc_engine_enumerate_writable_files()

        else:
            response = "INVALID NRC COMMAND, USE $NRC HELP" 

        return response 

    def nrc_engine_enumerate_system():
        """ nrc_engine_enumerate_system() performs system enumeration
        - architecture and release info
        - writable paths in $PATH
        - kernel exploits
        - sudo enumeration
        - dmesg enumeration
        - more system info (date, system, stats, cpu_info, printers)
        """
        response = "==== SYSTEM INFORMATION ================\n"
        response += "%20s:  %20s\n" % ("UNAME".center(20), "".join(platform.uname()))

        # checking writable paths in $PATH
        response += "%20s:  %20s\n" % ("$PATH".center(20), ":".join(os.get_exec_path()))
        for i, path in enumerate(os.get_exec_path()):  
            if os.access("/home/th3g3ntl3man", os.W_OK):
                response += "\t\t WRITABLE --> %20s\n" % (path)

        # TODO: checking kernel exploits

        # TODO: checking sudo version vulns

        # TODO: checking dmesg signature verification failed

        # TODO: checking more system information (date, system, stats, cpu_info, printers)
        
        return response
    
    def nrc_engine_enumerate_drives():
        raise NotImplementedError
    
    def nrc_engine_enumerate_software():
        raise NotImplementedError
    
    def nrc_engine_enumerate_processes():
        raise NotImplementedError
    
    def nrc_engine_enumerate_cronjobs():
        raise NotImplementedError
    
    def nrc_engine_enumerate_services():
        raise NotImplementedError
            
    def nrc_engine_enumerate_timer():
        raise NotImplementedError
            
    def nrc_engine_enumerate_sockets():
        raise NotImplementedError
            
    def nrc_engine_enumerate_dbus():
        raise NotImplementedError
            
    def nrc_engine_enumerate_network():
        raise NotImplementedError
            
    def nrc_engine_enumerate_users():
        raise NotImplementedError
            
    def nrc_engine_enumerate_writable_paths():
        raise NotImplementedError
            
    def nrc_engine_enumerate_SUID_GUID():
        raise NotImplementedError
            
    def nrc_engine_enumerate_capabilites():
        raise NotImplementedError
            
    def nrc_engine_enumerate_acls():
        raise NotImplementedError
            
    def nrc_engine_enumerate_shell_sessions():
        raise NotImplementedError
            
    def nrc_engine_enumerate_ssh():
        raise NotImplementedError
            
    def nrc_engine_enumerate_interesting_files():
        raise NotImplementedError
            
    def nrc_engine_enumerate_writable_files():
        raise NotImplementedError


class NetRunnerClient(NetRunnerServer):
    def __init__(self, args, buffer=None):
        self.args = args
        self.buffer = buffer
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def run(self):
        """run() start NetRunner in the specified mode [server, client]"""
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
# TODO: Implementar el NRC Engine para la ejecucion de custom commands en servidor y cliente
# TODO: Implementar sistema de contrasena para el servidor
# TODO: Implementar debug/verbose
# TODO: Implementar cifrado de datos para el envio de la comunicacion
# TODO: Implementar 


### HACK
# HACK: Mejorar output, mas colorido...
# HACK: Mejorar la documentacion 
