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
        return "[X] Error: returned error code while executing command...\n\n"
    except FileNotFoundError:
        return "[X] Error: File not found...\n\n"
    
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
        banner = """
        ICAgIF8gICBfXyAgICAgX18gIF9fX18KICAgLyB8IC8gL19fICAvIC9fLyBfXyBcX18gIF9fX19f
        XyAgX19fXyAgX19fICBfX19fXwogIC8gIHwvIC8gXyBcLyBfXy8gL18vIC8gLyAvIC8gX18gXC8g
        X18gXC8gXyBcLyBfX18vCiAvIC98ICAvICBfXy8gL18vIF8sIF8vIC9fLyAvIC8gLyAvIC8gLyAv
        ICBfXy8gLwovXy8gfF8vXF9fXy9cX18vXy8gfF98XF9fLF8vXy8gL18vXy8gL18vXF9fXy9fLwog
        ICAgIF9fIF9fX19fX19fX18gXyAgICBfX19fX19fX19fX18gCiAgIF8vIC8vIF9fX18vIF9fIFwg
        fCAgLyAvIF9fX18vIF9fIFwgCiAgLyBfXy8gX18vIC8gL18vIC8gfCAvIC8gX18vIC8gL18vIC8g
        ICAgYXV0aG9yOiBtaW5kMmhleAogKF8gICkgL19fXy8gXywgXy98IHwvIC8gL19fXy8gXywgXy8K
        LyAgXy9fX19fXy9fLyB8X3wgfF9fXy9fX19fXy9fLyB8X3wKL18vCg==
        """
        print(base64.b64decode(banner).decode())
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
            response = self.nrc_engine_enumerate()

        else:
            response = "INVALID NRC COMMAND, USE $NRC HELP" 

        return response 

    def nrc_engine_enumerate(self):
        operative_system = platform.system()
        response = self.nrc_engine_enumerate_system(operative_system)     + "\n"
        """
        response += self.nrc_engine_enumerate_drives()    + "\n"
        response += self.nrc_engine_enumerate_software()  + "\n"
        response += self.nrc_engine_enumerate_processes() + "\n"
        response += self.nrc_engine_enumerate_cronjobs()  + "\n"
        response += self.nrc_engine_enumerate_services()  + "\n"
        response += self.nrc_engine_enumerate_timer()     + "\n"
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

    def nrc_engine_enumerate_system(self, operative_system):
        """ nrc_engine_enumerate_system() performs system enumeration
        - architecture and release info
        - writable paths in $PATH
        - kernel exploits
        - sudo enumeration
        - dmesg enumeration
        - more system info (date, system, stats, cpu_info, printers)
        """
        separator = "="*30 + "%20s" + "="*30 + "\n"
        if operative_system == "Linux":
            response = separator % ("SYSTEM INFORMATION".center(20))
            # OS information https://book.hacktricks.xyz/linux-hardening/privilege-escalation#os-info
            response += "---> %20s:  %20s\n" % ("OS INFORMATION", "".join(platform.uname()))

            # searching for writable paths in $PATH  https://book.hacktricks.xyz/linux-hardening/privilege-escalation#path
            response += "---> %20s:  %20s\n" % ("EXECUTABLE PATH", ":".join(os.get_exec_path()))
            for i, path in enumerate(os.get_exec_path()):  
                if os.access(path, os.W_OK):
                    response += "\t\t WRITABLE --> %20s\n" % (path)

            # searching for useful info in Env variables https://book.hacktricks.xyz/linux-hardening/privilege-escalation#env-info
            response += "---> %20s: \n" % ("ENVIRONMENT VARIABLES" )
            for env_var in os.environ:
                response += "\t\t%-20s\t%s\n" % (env_var, os.getenv(env_var))

            # inspect kernel https://book.hacktricks.xyz/linux-hardening/privilege-escalation#kernel-exploits
            response += "---> %20s:  %20s" % ("KERNEL INFORMATION", execute("cat /proc/version"))

            # inspect sudo https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-version
            response += "---> %20s:\n" % ("SUDO INFORMATION")
            for row in execute("sudo -V").split("\n"):
                response += f"\t\t{row}\n"

            # checking dmesg signature verification failed https://book.hacktricks.xyz/linux-hardening/privilege-escalation#dmesg-signature-verification-failed
            response += "---> %20s:\n" % ("DMESG SIGNATURE")
            signature_info = re.findall(".*signature.*", execute("dmesg"))
            for signature in signature_info:
                response += f"\t\t{signature}\n"

            # checking more system information https://book.hacktricks.xyz/linux-hardening/privilege-escalation#more-system-enumeration
            response += "---> %20s:  %20s\n" % ("DATE", execute("date"))  # date

            response += "---> %20s:\n" % ("SYSTEM STATS")  # lsblk
            for row in execute("lsblk").split("\n"):
                response += f"\t\t{row}\n"

            response += "---> %20s:\n" % ("CPU INFO")  # lscpu
            for row in execute("lscpu").split("\n"):
                response += f"\t\t{row}\n"
            
            # enumerate system defenses https://book.hacktricks.xyz/linux-hardening/privilege-escalation#enumerate-possible-defenses
            response += "---> %20s:\n" % ("SYSTEM DEFENSES")   
            for command in [
                "which aa-status", 
                "which apparmor_status", 
                "which paxctl-ng",
                "which paxctl",
                "which sestatus"]: # "APP ARMOR":
                temporal_response = execute(command)
                if temporal_response.startswith("[X] Error"):
                    response += "\t\t%-24s %20s\n" % (command, "NOT ENABLED")
                else:
                    response += "\t\t%-24s %20s\n" % (command, execute(command))

            if re.search("exec-shield", execute("cat /etc/sysctl.conf")):
                response += "\t\t%-24s %20s\n" % ("EXEC SHIELD", "ENABLED")
            else:
                response += "\t\t%-24s %20s\n" % ("EXEC SHIELD", "NOT ENABLED")
            
            if not execute("cat /proc/sys/kernel/randomize_va_space").startswith("0"):
                response += "\t\t%-24s %20s\n" % ("ASLR", "ENABLED")
            else:
                response += "\t\t%-24s %20s\n" % ("ASLR", "NOT ENABLED")


        else:
            response = "NOT IMPLEMENTED YET\n"
        
        return response
    
    def nrc_engine_enumerate_drives(self):
        """
        nrc_engine_enumerate_drives() 
        returns info about mounted and unmounted drvies devices
        """
        response = "============ %20s ================\n" % ("DRIVES INFO".center(20))

        # list mounted drives
        response += "%s\n" %(execute("df -h"))

        # list unmounted drives

        # reading fstab

        return response
    
    def nrc_engine_enumerate_software(self):
        """
        nrc_engine_enumerate_software()
        returns info about any software useful to a pentesting installed 
        in machine which server is executing on
        """
        response = "============ %20s ================\n" % ("SOFTWARE INFO".center(20))

        # search useful software (compilers, interpreters, networking tools, etc)
        useful_tools = ["bash", "python"]
        for i, tool in enumerate(useful_tools):
            response += "%s\t%s"%(tool, execute(f"which {tool}"))

        return response
    
    def nrc_engine_enumerate_processes(self):
        """
        nrc_engine_enumerate_processes()
        ...
        """
        response = "============ %20s ================\n" % ("SOFTWARE INFO".center(20))

        # enumerating active processes
        response += "%20s\n" % ("Sudo information".center(20))
        for row in execute("ps aux").split("\n"):
            response += f"\t{row}\n"

        return response
    
    def nrc_engine_enumerate_cronjobs(self):
        return "nrc_engine_enumerate_cronjobs NOT IMPLEMENTED YET"
    
    def nrc_engine_enumerate_services(self):
        return "nrc_engine_enumerate_services NOT IMPLEMENTED YET"
            
    def nrc_engine_enumerate_timer(self):
        return "nrc_engine_enumerate_timer NOT IMPLEMENTED YET"
            
    def nrc_engine_enumerate_sockets(self):
        return "nrc_engine_enumerate_sockets NOT IMPLEMENTED YET"
            
    def nrc_engine_enumerate_dbus(self):
        return "nrc_engine_enumerate_dbus NOT IMPLEMENTED YET"
            
    def nrc_engine_enumerate_network(self):
        return "nrc_engine_enumerate_network NOT IMPLEMENTED YET"
    
    def nrc_engine_enumerate_users(self):
        return "nrc_engine_enumerate_users NOT IMPLEMENTED YET"
            
    def nrc_engine_enumerate_writable_paths(self):
        return "nrc_engine_enumerate_paths NOT IMPLEMENTED YET"
            
    def nrc_engine_enumerate_SUID_GUID(self):
        return "nrc_engine_enumerate_SUID_GUID NOT IMPLEMENTED YET"
            
    def nrc_engine_enumerate_capabilites(self):
        return "nrc_engine_enumerate_capabilities NOT IMPLEMENTED YET"
            
    def nrc_engine_enumerate_acls(self):
        return "nrc_engine_enumerate_acls NOT IMPLEMENTED YET"        
            
    def nrc_engine_enumerate_shell_sessions(self):
        return "nrc_engine_enumerate_sessions NOT IMPLEMENTED YET"                
            
    def nrc_engine_enumerate_ssh(self):
        return "nrc_engine_enumerate_ssh NOT IMPLEMENTED YET"                        
            
    def nrc_engine_enumerate_interesting_files(self):
        return "nrc_engine_enumerate_interesting_files NOT IMPLEMENTED YET"                                
            
    def nrc_engine_enumerate_writable_files(self):
        return "nrc_engine_enumerate_writable_files NOT IMPLEMENTED YET"                                        


class NetRunnerClient():
    def __init__(self, args, buffer=None):
        self.args = args
        self.buffer = buffer
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def run(self):
        """run() start NetRunner in the specified mode [server, client]"""
        banner = """
        ICAgIF8gICBfXyAgICAgX18gIF9fX18KICAgLyB8IC8gL19fICAvIC9fLyBfXyBcX18gIF9fX19f
        XyAgX19fXyAgX19fICBfX19fXwogIC8gIHwvIC8gXyBcLyBfXy8gL18vIC8gLyAvIC8gX18gXC8g
        X18gXC8gXyBcLyBfX18vCiAvIC98ICAvICBfXy8gL18vIF8sIF8vIC9fLyAvIC8gLyAvIC8gLyAv
        ICBfXy8gLwovXy8gfF8vXF9fXy9cX18vXy8gfF98XF9fLF8vXy8gL18vXy8gL18vXF9fXy9fLwog
        ICBfX19fX19fX18gICAgICAgICAgICBfXwogIC8gX19fXy8gKF8pX18gIF9fX18gIC8gL18KIC8g
        LyAgIC8gLyAvIF8gXC8gX18gXC8gX18vICAgICBhdXRob3I6IG1pbmQyaGV4Ci8gL19fXy8gLyAv
        ICBfXy8gLyAvIC8gL18KXF9fX18vXy9fL1xfX18vXy8gL18vXF9fLwo=
        """
        print(base64.b64decode(banner).decode())
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
