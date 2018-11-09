#!/usr/bin/env python2

"""ftpserver.py: Acts as a server for connecting to an FTP client. Adheres to
                 the FTP Protocol defined in RFC 959 and RFC 2428.
   Author: Brian Jopling, November 2018."""

import socket      # Used for network connections.
import sys         # Used for arg parsing.
import datetime    # Used for getting date & time for Logs.
import os          # Used for parsing paths / file names.
import threading   # Used for handling concurrent connections.
import subprocess  # Used for performing `ls -l`


''' GLOBALS '''

IS_DEBUG = False
SERVER_INFO = "UNIX Type: L8"

BUFF_SIZE = 1024

# File containing valid usernames and passwords that can sign into the server.
ACCOUNTS_FILE = "accounts.txt"
# Map that will store the username and passwords contained in ACCOUNTS_FILE.
ACCOUNTS_INFO = {}

# Valid / Supported FTP commands with associated function calls.
# { command_name : [command_help_info, function_to_call] }
VALID_COMMANDS = {
    "USER": ["String identifying the user", "do_user"],
    "PASS": ["Password of the user", "do_pass"],
    "CWD":  ["Change working directory of server", "do_cwd"],
    "CDUP": ["Go up one directory, ie '..'", "do_cdup"],
    "QUIT": ["Terminate the connection", "do_quit"],
    "PASV": ["Have server listen for connections on data channel", "do_pasv"],
    "EPSV": ["Use an Extended Passive connection", "do_epsv"],
    "PORT": ["Have client listen for connections on data channel", "do_port"],
    "EPRT": ["Use an Extended Port connection", "do_eprt"],
    "RETR": ["Retrieve (download) a file from the server", "do_retr"],
    "STOR": ["Store (upload) a file to the server", "do_stor"],
    "PWD":  ["Print working directory of server", "do_pwd"],
    "SYST": ["Get system information about the server", "do_syst"],
    "LIST": ["List files in a directory", "do_list"],
    "HELP": ["Get help", "do_help"]
}

# FTP Server Response Codes directly referenced in this program.
FTP_STATUS_CODES = {
    "SUCCESSFUL_RETR":      "150",
    "SUCCESSFUL_STOR":      "150",
    "INBOUND_DATA":         "150",
    "SUCCESSFUL_PORT":      "200",
    "SUCCESSFUL_HELP":      "214",
    "SUCCESSFUL_SYST":      "215",
    "ACCEPT_QUIT":          "221",
    "SUCCESSFUL_TRANSFER":  "226",
    "SUCCESSFUL_PASV":      "227",
    "SUCCESSFUL_LOGIN":     "230",
    "SUCCESSFUL_LOGOUT":    "231",
    "SUCCESSFUL_CWD":       "250",
    "SUCCESSFUL_PWD":       "257",
    "VALID_USERNAME":       "331",
    "INVALID_COMMAND":      "502",
    "INVALID_LOGIN":        "530",
    "UNSUCCESSFUL_CWD":     "550",
    "UNSUCCESSFUL_RETR":    "550"

}

E_DELIMITER = "|"  # Delimiter used for EPRT and EPSV

# Program Arguments
REQUIRED_NUM_ARGS = 3
MAXIMUM_NUM_ARGS = 3

PROGRAM_ARG_NUM = 0  # ie sys.argv[0]
LOG_ARG_NUM = 1
PORT_ARG_NUM = 2

STARTUP_BANNER = """
  ____       _             _      
 |  _ \     (_)           ( )     
 | |_) |_ __ _  __ _ _ __ |/ ___  
 |  _ <| '__| |/ _` | '_ \  / __| 
 | |_) | |  | | (_| | | | | \__ \ 
 |____/|_|  |_|\__,_|_| |_| |___/ 
  / ____|                         
 | (___   ___ _ ____   _____ _ __ 
  \___ \ / _ \ '__\ \ / / _ \ '__|
  ____) |  __/ |   \ V /  __/ |   
 |_____/ \___|_|    \_/ \___|_|                                   
"""



''' CLASSES '''


class Logger:
    """Performs necessary logging of communication between Client & Server."""
    # Class vars:
    #   * file - File
    def __init__(self, log_file):
        print_debug("Created Logger")
        # Create file
        f = open(log_file, "a")
        self.file = f

    def get_date_time(self):
        """Returns datetime as a string in the format: 9/25/18 22:00:00.0002"""
        now = datetime.datetime.now()
        now_formatted = now.strftime("%m/%d/%Y %H:%M:%S.%f")
        return now_formatted

    def log(self, msg):
        """Writes datetime & message to log."""
        current_datetime = self.get_date_time()
        self.file.write("%s %s\n" % (current_datetime, msg))

    def close_file(self):
        """Simply closes the file."""
        self.file.close()


class ClientConnectedThread(threading.Thread):
    """New thread for every connected client. Each thread
       handles an individual client's requests."""
    # Class vars:
    #   * client_ip - String
    #   * client_port - String
    #   * client_sock - Socket
    #   * logger - Logger
    def __init__(self, ip, port, sock, logger):
        """Initialize args to class variables."""
        threading.Thread.__init__(self)
        self.client_ip = ip
        self.client_port = port
        self.client_sock = sock
        self.logger = logger

    def run(self):
        """Driver for individual thread. Handles client requests."""
        # Initialize an FTP object for each connected client.
        ftp = FTP(self.client_ip, self.client_port, self.client_sock, self.logger)
        # Log that a host connected.
        self.logger.log("Host %s:%s has connected!" % (self.client_ip, self.client_port))
        # Send a greeting to that host and get their next request.
        serv_command = "200 Hello friend.\r\n"
        while True:
            try:
                client_request = ftp.send_and_log(self.client_sock, serv_command)
                cmd_rec = parse_client_request(client_request)
                # If request received is invalid, send invalid status code to client.
                if cmd_rec not in VALID_COMMANDS:
                    print_debug("Received an invalid command: " + cmd_rec)
                    self.client_sock.send(FTP_STATUS_CODES["INVALID_COMMAND"] +
                                          " Invalid command, try again.\r\n")
                # Otherwise, handle the request.
                else:
                    serv_command = self.handle_command(cmd_rec, client_request, ftp)
            except Exception as e:
                print_debug("Encountered error: " + str(e))


    def handle_command(self, cmd_rec, client_request, ftp):
        """Server performs an action corresponding to the received command."""
        client_request = client_request.strip('\r\n')
        function_to_call = VALID_COMMANDS[cmd_rec][1]
        return globals()[function_to_call](cmd_rec, client_request, ftp)


class FTP:
    """Executes defined FTP Client commands and handles Server's responses."""
    # Class vars:
    #   * client_ip        - string
    #   * client_port      - string
    #   * s                - socket
    #   * data_sock        - socket
    #   * is_port          - boolean
    #   * logger           - Logger
    #   * user             - string
    #   * is_authenticated - boolean
    def __init__(self, client_ip, client_port, client_sock, logger):
        self.client_ip = client_ip
        self.client_port = client_port
        self.s = client_sock
        self.data_sock = new_socket()
        self.is_port = False
        self.logger = logger
        self.user = ""
        self.is_authenticated = False

    def ftp_connect(self, sock, host, port):
        """Connects Client to Server."""
        try:
            # Get IP address.
            ip = socket.gethostbyname(host)
        except socket.error:
            print_debug("Invalid or unknown host address!", 400)
        except Exception:
            print_debug("Invalid or unknown host address!", 400)
        try:
            # Connect socket to IP and Port.
            print_debug("PORT: " + str(port))
            port = int(port)
            sock.connect((ip, port))
        except socket.error:
            print_debug("Connection refused, did you specify the correct host and port?", 400)
        except Exception:
            print_debug("Terminating session due to issue in transmission.", 400)

    def send_and_log(self, sock, command):
        """Send response to socket, return client's
           request from command channel."""
        try:
            # Send command to client.
            sock.send(command)
            self.logger.log("Sent to %s:%s: %r" % (self.client_ip, self.client_port, repr(command)))
            # Receive response from client.
            msg_rec = sock.recv(BUFF_SIZE)
            self.logger.log("Received from %s:%s: %r" % (self.client_ip, self.client_port, repr(msg_rec)))
        except socket.error:
            print_debug("Connection error, unable to send command.", 400)
        except Exception:
            print_debug("An unknown error has occurred.", 500)
        return msg_rec

    def get_from_data_channel(self, sock):
        """Return client's response from data channel."""
        msg_rec = b""
        # Continue reading from client until there's nothing left to read.
        while 1:
            buff = sock.recv(BUFF_SIZE)
            msg_rec += buff
            if len(buff) == 0:
                break
        self.logger.log("Received from %s:%s: %r" % (self.client_ip, self.client_port, repr(msg_rec)))
        return msg_rec

    def send_to_data_channel(self, sock, data):
        """Sends data to client via data channel."""
        resp = sock.send(data)
        print_debug(resp)
        print_debug(data)
        self.logger.log("Sent to %s:%s: %r" % (self.client_ip, self.client_port, repr(data)))
        self.logger.log("Received from %s:%s: %r" % (self.client_ip, self.client_port, repr(resp)))
        return resp

    def port_connection(self, sock, port_ip, port_port):
        """Connect port socket to data channel port for data to be read."""
        self.ftp_connect(sock, port_ip, port_port)

    def pasv_connection(self, sock):
        """Bind port socket so client can connect to it."""
        sock.bind(('', 0))  # Bind to OS-assigned available & random port.
        sock.listen(1)

    def parse_port_resp(self, msg_rec):
        """Helper for port_cmd() to parse out IP and Port of data channel."""
        num_ip_bytes = 4
        index_of_port_1 = 4
        index_of_port_2 = 5
        try:
            print_debug(msg_rec)
            # Parse out IP & Port from the parenthesis within the PASV resp.
            if "(" in msg_rec and ")" in msg_rec:
                host_info = msg_rec[msg_rec.index("(") + 1:msg_rec.rindex(")")]
            else:
                host_info = msg_rec
            # Break up IP & Port based on comma separated delimiter.
            host_info_split = host_info.split(',')
            # Put octets together, delimited by periods.
            host_ip_list = [host_info_split[i] for i in range(num_ip_bytes)]
            host_ip = '.'.join(host_ip_list)
            # Get Port as a valid port number.
            host_port = int(host_info_split[index_of_port_1]) * 256 + \
                        int(host_info_split[index_of_port_2])
        except Exception as e:
            print_debug("Error: " + str(e))
            return "", ""
        return host_ip, host_port

    def parse_pasv_req(self, sock):
        """Helper for pasv_cmd() to parse in IP and Port of data channel."""
        try:
            host_ip = self.s.getsockname()[0]  # Get local IPv4 addr of server.
            host_port = sock.getsockname()[1]  # Get opened port of socket.
            # PORT requires parameters split up as:
            # octet1,octet2,octet3,octet4,p1,p2
            list_csv_ip = host_ip.split('.')   # Split octets into a list.
            pasv_params = ""
            for octet in list_csv_ip:
                pasv_params += octet + ","
            # Parse port into PORT command's expected parameter.
            p1 = str((host_port - (host_port % 256)) / 256)
            p2 = str(host_port % 256)
            pasv_params += p1 + "," + p2
        except:
            return "", "", ""
        return pasv_params, host_ip, host_port

    def parse_eprt_req(self, msg_rec):
        """Helper for eprt_cmd() to parse Port of data channel."""
        port_start_ind = 3
        try:
            # Get host port with delimiter.
            host_port_delim = msg_rec
            if "(" in host_port_delim:
                host_port_delim = msg_rec[msg_rec.index("(") + 1:msg_rec.rindex(")")]
            # Split based on delimiter.
            host_port_delim_split = host_port_delim.split(E_DELIMITER)
            # Get port from split list.
            host_port = host_port_delim_split[port_start_ind]
            print_debug("Parsed Port: %s" % host_port)
        except Exception:
            return ""
        return host_port

    def parse_epsv_resp(self, sock, proto="1"):
        """Helper for epsv_cmd() to parse in IP and Port of data channel."""
        try:
            net_prt = proto
            net_addr = self.s.getsockname()[0]  # Get local addr of server.
            tcp_port = sock.getsockname()[1]  # Get opened port of socket.
            # EPRT requires parameters split up as:
            # <d><net-prt><d><net-addr><d><tcp-port><d>
            eprt_params = E_DELIMITER + str(net_prt) + E_DELIMITER + \
                          str(net_addr) + E_DELIMITER + str(tcp_port) + \
                          E_DELIMITER
            print_debug(eprt_params)
        except:
            return "", "", ""
        return eprt_params, net_addr, tcp_port

    def user_cmd(self, username):
        """Handle client's request for USER."""
        print_debug("Executing USER")
        # Ensure user exists.
        if username in ACCOUNTS_INFO:
            print_debug("User %s exists" % username)
            self.user = username
            # Send an OK
            resp = FTP_STATUS_CODES["VALID_USERNAME"]
        else:
            print_debug("User %s does NOT exist" % username)
            # User does not exist, send a fail.
            resp = FTP_STATUS_CODES["INVALID_LOGIN"]
        return resp + "\r\n"

    def pass_cmd(self, password):
        """Handle client's request for PASS."""
        print_debug("Executing PASS")
        # Ensure USER was entered and valid password corresponds to that user.
        if self.user and password in ACCOUNTS_INFO[self.user]:
            self.is_authenticated = True
            # Send OK
            resp = FTP_STATUS_CODES["SUCCESSFUL_LOGIN"]
        else:
            # Send fail.
            resp = FTP_STATUS_CODES["INVALID_LOGIN"]
        return resp + "\r\n"

    def cwd_cmd(self, new_dir):
        """Handle client's request for CWD."""
        if not self.is_authenticated:
            return FTP_STATUS_CODES["INVALID_LOGIN"] + "\r\n"
        print_debug("Executing CWD")
        # Ensure directory exists.
        if os.path.exists(new_dir):
            os.chdir(new_dir)
            resp = "%s Changed to %s" % (FTP_STATUS_CODES["SUCCESSFUL_CWD"], os.getcwd())
        else:
            resp = FTP_STATUS_CODES["UNSUCCESSFUL_CWD"]
        return resp + "\r\n"

    def pwd_cmd(self):
        """Handle client's request for PWD."""
        if not self.is_authenticated:
            return FTP_STATUS_CODES["INVALID_LOGIN"] + "\r\n"
        print_debug("Executing PWD")
        resp = "%s %s" % (FTP_STATUS_CODES["SUCCESSFUL_PWD"], os.getcwd())
        return resp + "\r\n"

    def cdup_cmd(self):
        """Handle client's request for CDUP."""
        if not self.is_authenticated:
            return FTP_STATUS_CODES["INVALID_LOGIN"] + "\r\n"
        print_debug("Executing CDUP")
        # Ensure '..' exists and (not so obviously) that we have permission.
        if os.path.exists('..'):
            os.chdir('..')
            resp = "%s Changed to %s" % (FTP_STATUS_CODES["SUCCESSFUL_CWD"], os.getcwd())
        else:
            resp = FTP_STATUS_CODES["UNSUCCESSFUL_CWD"]
        return resp + "\r\n"

    def quit_cmd(self):
        """Handle client's request for QUIT."""
        if not self.is_authenticated:
            return FTP_STATUS_CODES["INVALID_LOGIN"] + "\r\n"
        print_debug("Executing QUIT")
        resp = FTP_STATUS_CODES["ACCEPT_QUIT"]
        return resp + "\r\n"

    def port_cmd(self, msg):
        """Handle client's request for PORT."""
        if not self.is_authenticated:
            return FTP_STATUS_CODES["INVALID_LOGIN"] + "\r\n"
        print_debug("Executing PORT")
        # PORT has client listen for server's connection.
        self.is_port = True
        self.data_sock = new_socket()
        client_port_ip, client_port_port = self.parse_port_resp(msg)
        self.port_connection(self.data_sock, client_port_ip, client_port_port)
        resp = "%s" % FTP_STATUS_CODES["SUCCESSFUL_PORT"]
        return resp + "\r\n"

    def pasv_cmd(self):
        """Handle client's request for PASV."""
        if not self.is_authenticated:
            return FTP_STATUS_CODES["INVALID_LOGIN"] + "\r\n"
        print_debug("Executing PASV")
        # PASV has server listen for client's connection.
        self.is_port = False
        self.data_sock = new_socket()
        self.pasv_connection(self.data_sock)
        # Get required parameters for PASV command.
        pasv_params, host_ip, host_port = self.parse_pasv_req(self.data_sock)
        print_debug("PARAMS: " + pasv_params)
        resp = "%s (%s)" % (FTP_STATUS_CODES["SUCCESSFUL_PASV"], pasv_params)
        return resp + "\r\n"

    def eprt_cmd(self, msg):
        """Handle client's request for EPRT."""
        if not self.is_authenticated:
            return FTP_STATUS_CODES["INVALID_LOGIN"] + "\r\n"
        print_debug("Executing EPRT")
        # EPRT creates a new connection between client and server.
        self.is_port = True
        self.data_sock = new_socket()
        # Get client ip from Command Channel socket.
        client_port_ip = self.s.getpeername()[0]
        # Get client port from Command Channel socket.
        client_port_port = self.parse_eprt_req(msg)
        # Create connection using acquired ip and port.
        self.port_connection(self.data_sock, client_port_ip, client_port_port)
        resp = "%s" % FTP_STATUS_CODES["SUCCESSFUL_PORT"]
        return resp + "\r\n"

    def epsv_cmd(self):
        """Handle client's request for EPSV."""
        if not self.is_authenticated:
            return FTP_STATUS_CODES["INVALID_LOGIN"] + "\r\n"
        print_debug("Executing EPSV")
        sock = new_socket()
        self.is_port = False
        self.data_sock = new_socket()
        self.pasv_connection(self.data_sock)
        # Get required parameters for EPSV command.
        pasv_params, host_ip, host_port = self.parse_epsv_resp(self.data_sock)
        print_debug("PARAMS: " + pasv_params)
        resp = "%s (%s)" % (FTP_STATUS_CODES["SUCCESSFUL_PASV"], pasv_params)
        return resp + "\r\n"

    def retr_cmd(self, path):
        """Handle client's request for RETR."""
        if not self.is_authenticated:
            return FTP_STATUS_CODES["INVALID_LOGIN"] + "\r\n"
        print_debug("Executing RETR")
        if not path or not os.path.exists(path):
            return FTP_STATUS_CODES["INVALID_COMMAND"] + "\r\n"
        # Inform client on Command Channel that data is coming on Data Channel.
        init_data = FTP_STATUS_CODES["INBOUND_DATA"] + "\r\n"
        init_resp = self.s.send(init_data)
        self.logger.log("Sent to %s:%s: %r" % (self.client_ip, self.client_port, repr(init_data)))
        self.logger.log("Received from %s:%s: %r" % (self.client_ip, self.client_port, repr(init_resp)))
        with open(path, "rb") as f:
            data = f.read()
        # Are we doing PORT or EPRT?
        if self.is_port:
            data_sent = self.send_to_data_channel(self.data_sock, data)
            self.close_socket(self.data_sock)
        # Are we doing PASV or EPSV?
        else:
            conn, sockaddr = self.data_sock.accept()
            # Have server send data across data channel for client.
            self.send_to_data_channel(conn, data)
            self.close_socket(conn)
        resp = FTP_STATUS_CODES["SUCCESSFUL_TRANSFER"]
        return resp + "\r\n"

    def stor_cmd(self, path):
        """Handle client's request for STOR."""
        if not self.is_authenticated:
            return FTP_STATUS_CODES["INVALID_LOGIN"] + "\r\n"
        print_debug("Executing STOR")
        # Inform client on Command Channel that data is coming on Data Channel.
        init_data = FTP_STATUS_CODES["INBOUND_DATA"] + "\r\n"
        init_resp = self.s.send(init_data)
        self.logger.log("Sent to %s:%s: %r" % (self.client_ip, self.client_port, repr(init_data)))
        self.logger.log("Received from %s:%s: %r" % (self.client_ip, self.client_port, repr(init_resp)))
        # Are we doing PORT or EPRT?
        if self.is_port:
            data_get = self.get_from_data_channel(self.data_sock)
            self.close_socket(self.data_sock)
        # Are we doing PASV or EPSV?
        else:
            conn, sockaddr = self.data_sock.accept()
            # Have server send data across data channel for client.
            data_get = self.get_from_data_channel(conn)
            self.close_socket(conn)
        write_to_local(path, data_get)
        resp = FTP_STATUS_CODES["SUCCESSFUL_TRANSFER"]
        return resp + "\r\n"

    def syst_cmd(self):
        """Handle client's request for SYST."""
        if not self.is_authenticated:
            return FTP_STATUS_CODES["INVALID_LOGIN"] + "\r\n"
        print_debug("Executing SYST")
        resp = "%s %s" % (FTP_STATUS_CODES["SUCCESSFUL_SYST"], SERVER_INFO)
        return resp + "\r\n"

    def help_cmd(self, cmd=None):
        """Handle client's request for HELP."""
        if not self.is_authenticated:
            return FTP_STATUS_CODES["INVALID_LOGIN"] + "\r\n"
        print_debug("Executing HELP")
        help_msg = "FTP Server Help: \n"
        if cmd and cmd.upper() in VALID_COMMANDS:
            help_msg += "%s: %s" % (cmd.upper(), VALID_COMMANDS[cmd.upper()][0])
        else:
            for key in VALID_COMMANDS:
                help_msg += key + " "
        resp = "%s %s" % (FTP_STATUS_CODES["SUCCESSFUL_HELP"], help_msg)
        return resp + "\r\n"

    def list_cmd(self, path=None):
        """Handle client's request for LIST."""
        if not self.is_authenticated:
            return FTP_STATUS_CODES["INVALID_LOGIN"] + "\r\n"
        print_debug("Executing LIST")
        if path:
            # List everything in specified path.
            data = subprocess.check_output(['ls', '-l', path]).replace("\n", "\r\n")
        else:
            # List everything in current path.
            data = subprocess.check_output(['ls', '-l']).replace("\n", "\r\n")
        init_data = FTP_STATUS_CODES["INBOUND_DATA"] + "\r\n"
        init_resp = self.s.send(init_data)
        self.logger.log("Sent to %s:%s: %r" % (self.client_ip, self.client_port, repr(init_data)))
        self.logger.log("Received from %s:%s: %r" % (self.client_ip, self.client_port, repr(init_resp)))
        if self.is_port:
            data_sent = self.send_to_data_channel(self.data_sock, data)
            self.close_socket(self.data_sock)
        else:
            conn, sockaddr = self.data_sock.accept()
            # Have server send data across data channel for client.
            self.send_to_data_channel(conn, data)
            self.close_socket(conn)
        resp = FTP_STATUS_CODES["SUCCESSFUL_TRANSFER"]
        return resp + "\r\n"

    def close_socket(self, sock):
        """Close socket passed as arg."""
        print_debug("Closing socket.")
        try:
            sock.close()
            # If data socket being closed, print debug message.
            if sock != self.s:
                print_debug("Socket closed.")
        except socket.error:
            print_debug("Error closing socket!", 500)
        except Exception:
            print_debug("An unknown error occurred while closing the socket!", 500)


''' FUNCTIONS '''


def usage():
    """Prints the usage/help message for this program."""
    program_name = sys.argv[PROGRAM_ARG_NUM]
    print("Usage:")
    print("%s LOGFILE PORT" % program_name)
    print("  LOGFILE : Name of file containing FTP Client log details.")
    print("  PORT : Port used to connect to FTP Server.")


def error_quit(msg, code):
    """Prints out an error message, the program usage, and terminates with an
       error code of `code`."""
    print("[!] %s" % msg)
    usage()
    exit(code)


def parse_args():
    """Gets and returns provided arguments."""
    if len(sys.argv) < REQUIRED_NUM_ARGS or len(sys.argv) > MAXIMUM_NUM_ARGS:
        error_quit("Incorrect number of arguments!", 400)
    # port = portarg.
    port = sys.argv[PORT_ARG_NUM]
    port = validate_port(port)
    # Get logfile name from args.
    log_file = sys.argv[LOG_ARG_NUM]
    return log_file, port


def validate_port(port):
    """Cast port to an int and ensure it is between 0 and 65535."""
    try:
        port = int(port)
        # Is port a valid port number?
        if port > 65535 or port < 0:
            raise ValueError('Port is not between 0 and 65535!')
    except ValueError:
        error_quit("Port is not between 0 and 65535!", 400)
    except Exception:
        error_quit("Invalid port!", 400)
    return port


def new_socket():
    """Return a new socket."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    return s


def do_port(cmd_rec, client_request, ftp):
    """Try to handle PORT request."""
    # IP and Port corresponding to client's accepting data channel.
    msg = client_request.split(" ")[1]
    print_debug(client_request)
    try:
        resp = ftp.port_cmd(msg)
    except Exception as e:
        resp = FTP_STATUS_CODES["INVALID_COMMAND"] + "\r\n"
        print("Encountered error: " + str(e))
    return resp


def do_pasv(cmd_rec, client_request, ftp):
    """Try to handle PASV request."""
    try:
        resp = ftp.pasv_cmd()
    except Exception as e:
        resp = FTP_STATUS_CODES["INVALID_COMMAND"] + "\r\n"
        print("Encountered error: " + str(e))
    return resp


def do_eprt(cmd_rec, client_request, ftp):
    """Try to handle EPRT request."""
    # IP and Port corresponding to client's accepting data channel.
    try:
        resp = ftp.eprt_cmd(client_request)
    except Exception as e:
        resp = FTP_STATUS_CODES["INVALID_COMMAND"] + "\r\n"
        print("Encountered error: " + str(e))
    return resp


def do_epsv(cmd_rec, client_request, ftp):
    """Try to handle EPSV request."""
    try:
        resp = ftp.epsv_cmd()
    except Exception as e:
        resp = FTP_STATUS_CODES["INVALID_COMMAND"] + "\r\n"
        print("Encountered error: " + str(e))
    return resp


def do_retr(cmd_rec, client_request, ftp):
    """Try to handle RETR request."""
    split_req = client_request.split(" ")
    try:
        if len(split_req) > 1:
            # Path specified
            resp = ftp.retr_cmd(split_req[1])
        else:
            resp = ftp.retr_cmd()
    except Exception as e:
        resp = FTP_STATUS_CODES["INVALID_COMMAND"] + "\r\n"
        print("Encountered error: " + str(e))
    return resp


def write_to_local(path, data_rec):
    """Writes content of data_rec to a file in path."""
    path, filename = os.path.split(path)
    with open(filename, 'wb') as f:
        f.write(data_rec)
    f.close()


def do_user(cmd_rec, client_request, ftp):
    "Handle inputted USER."
    username = client_request.split(" ")[1]
    try:
        resp = ftp.user_cmd(username)
    except Exception as e:
        resp = FTP_STATUS_CODES["INVALID_COMMAND"] + "\r\n"
        print("Encountered error: " + str(e))
    return resp


def do_pass(cmd_rec, client_request, ftp):
    """Handle inputted PASS."""
    password = client_request.split(" ")[1]
    try:
        resp = ftp.pass_cmd(password)
    except Exception as e:
        resp = FTP_STATUS_CODES["INVALID_COMMAND"] + "\r\n"
        print("Encountered error: " + str(e))
    return resp


def do_stor(cmd_rec, client_request, ftp):
    """Write client's file to server."""
    split_req = client_request.split(" ")
    try:
        if len(split_req) > 1:
            # Path specified
            resp = ftp.stor_cmd(split_req[1])
        else:
            resp = ftp.stor_cmd()
    except Exception as e:
        resp = FTP_STATUS_CODES["INVALID_COMMAND"] + "\r\n"
        print("Encountered error: " + str(e))
    return resp


def do_list(cmd_rec, client_request, ftp):
    """Break up client's request, which may contain a path, and perform list function."""
    split_req = client_request.split(" ")
    try:
        if len(split_req) > 1:
            # Path specified
            resp = ftp.list_cmd(split_req[1])
        else:
            resp = ftp.list_cmd()
    except Exception as e:
        resp = FTP_STATUS_CODES["INVALID_COMMAND"] + "\r\n"
        print("Encountered error: " + str(e))
    return resp


def do_cwd(cmd_rec, client_request, ftp):
    """Break up client's request, which should contain a path, and perform cwd function."""
    path = client_request.split(" ")[1]
    try:
        resp = ftp.cwd_cmd(path)
    except Exception as e:
        resp = FTP_STATUS_CODES["INVALID_COMMAND"] + "\r\n"
        print("Encountered error: " + str(e))
    return resp


def do_cdup(cmd_rec, client_request, ftp):
    """Go up a directory."""
    try:
        resp = ftp.cdup_cmd()
    except Exception as e:
        resp = FTP_STATUS_CODES["INVALID_COMMAND"] + "\r\n"
        print("Encountered error: " + str(e))
    return resp


def do_pwd(cmd_rec, client_request, ftp):
    """Display the working directory."""
    try:
        resp = ftp.pwd_cmd()
    except Exception as e:
        resp = FTP_STATUS_CODES["INVALID_COMMAND"] + "\r\n"
        print("Encountered error: " + str(e))
    return resp


def do_syst(cmd_rec, client_request, ftp):
    """Display server info."""
    try:
        resp = ftp.syst_cmd()
    except Exception as e:
        resp = FTP_STATUS_CODES["INVALID_COMMAND"] + "\r\n"
        print("Encountered error: " + str(e))
    return resp


def do_help(cmd_rec, client_request, ftp):
    """Display the server's help info."""
    split_req = client_request.split(" ")
    try:
        if len(split_req) > 1:
            # Path specified
            resp = ftp.help_cmd(split_req[1])
        else:
            resp = ftp.help_cmd()
    except Exception as e:
        resp = FTP_STATUS_CODES["INVALID_COMMAND"] + "\r\n"
        print("Encountered error: " + str(e))
    return resp


def do_quit(cmd_rec, client_request, ftp):
    """Disconnect from client."""
    try:
        return ftp.quit_cmd()
    except Exception as e:
        print("An error has occurred: " + str(e))
        return FTP_STATUS_CODES["INVALID_COMMAND"] + "\r\n"


def parse_client_request(client_request):
    """Returns command contained in client's request."""
    # The first "word" (delimited by a space) is the command.
    command = client_request.split(" ")[0].strip('\r\n')
    return command


def load_accounts():
    """Appends the usernames and passwords in ACCOUNTS_FILE into a map."""
    # Ensure file exists.
    if not os.path.exists(ACCOUNTS_FILE):
        error_quit("Missing accounts file. %s is invalid." % ACCOUNTS_FILE, 400)
    # Read each line of ACCOUNTS_FILE.
    with open(ACCOUNTS_FILE) as f:
        for line in f:
            line = line.strip('\n')
            print_debug(line)
            # Split each line into a tuple based on delimiter ":".
            try:
                (username, password) = line.split(":")
            except ValueError as e:
                error_quit("%s is formatted improperly! " % ACCOUNTS_FILE +
                           "Should be username:password with each pair on " +
                           "a different line.", 400)
            ACCOUNTS_INFO[username] = password


def do_ftp(logger, server_port):
    """Driver that creates a socket and handles connections."""
    # Initialize logger.
    logger.log("Starting server.")
    try:
        # Create socket, connect to host and port.
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(('', server_port))  # Bind to OS-assigned available & random port.
        s.listen(1)
        print("Server running.")
        while 1:
            try:
                conn, addr = s.accept()
                ip = addr[0]
                port = addr[1]
                client = ClientConnectedThread(ip, port, conn, logger)
                client.start()
            except Exception as e:
                print("Encountered error: " + str(e))
    except socket.error as e:
        print("Unable to connect due to " + str(e))


''' DEBUG '''


def print_debug(msg):
    """Prints if we are in debug mode."""
    if IS_DEBUG:
        print(msg)


''' MAIN '''


def main():
    """Main driver that parses args, creates our Logger & FTP objects,
       and starts the do_ftp driver."""
    print(STARTUP_BANNER)
    print("Starting server...")
    log_file, port = parse_args()
    logger = Logger(log_file)
    load_accounts()
    print_debug(ACCOUNTS_INFO)
    do_ftp(logger, port)


''' PROCESS '''
if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("Stopping server...")
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)
