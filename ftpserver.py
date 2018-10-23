#!/usr/bin/env python2

"""ftpserver.py: Acts as a server for connecting to an FTP client. Adheres to
                 the FTP Protocol defined in RFC 959 and RFC 2428.
   Author: Brian Jopling, October 2018."""

import socket    # Used for network connections.
import sys       # Used for arg parsing.
import datetime  # Used for getting date & time for Logs.
import getpass   # Used for hiding inputted password.
import os        # Used for parsing paths / file names.

''' GLOBALS '''

IS_DEBUG = False
DEFAULT_FTP_PORT = 21

BUFF_SIZE = 1024

# FTP Server Response Codes directly referenced in this program.
FTP_STATUS_CODES = {
    "SUCCESSFUL_RETR":     "150",
    "SUCCESSFUL_STOR":     "150",
    "SUCCESSFUL_TRANSFER": "226",
    "SUCCESSFUL_LOGIN":    "230",
    "SUCCESSFUL_LOGOUT":   "231",
    "SUCCESSFUL_CWD":      "250"
}

# Actions User can make when at the Main Menu.
# Adheres to the format:
# { choice_number : [display_msg, function_to_call] }
MAIN_MENU_SELECTIONS = {
    "1": ["Download a file.", "do_download"],
    "2": ["Upload a file.", "do_upload"],
    "3": ["List files.", "do_list"],
    "4": ["Change directory.", "do_cwd"],
    "5": ["Print working directory.", "do_pwd"],
    "6": ["Get server info.", "do_syst"],
    "7": ["Get help.", "do_help"],
    "8": ["Quit.", "do_quit"]
}

# Transfer Types from which the user will be prompted to select from.
TRANSFER_MENU_SELECTIONS = {
    "1": "Active  (PORT)",
    "2": "Passive (PASV)",
    "3": "Extended Active  (EPRT)",
    "4": "Extended Passive (EPSV)"
}

E_DELIMITER = "|"  # Delimiter used for EPRT and EPSV

# Program Arguments
REQUIRED_NUM_ARGS = 3
MAXIMUM_NUM_ARGS = 4

PROGRAM_ARG_NUM = 0  # ie sys.argv[0]
HOST_ARG_NUM = 1
LOG_ARG_NUM = 2
PORT_ARG_NUM = 3


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


class FTP:
    """Executes defined FTP Client commands and handles Server's responses."""
    # Class vars:
    #   * logger - Logger
    #   * s      - socket
    def __init__(self, host, logger, port):
        """Create socket and invoke connection."""
        # Initialize logger.
        self.logger = logger
        self.logger.log("Connecting to %s" % host)
        try:
            # Create socket, connect to host and port.
            self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.ftp_connect(self.s, host, port)
            # Get response from initial connection.
            msg_rec = repr(self.s.recv(BUFF_SIZE))
        except socket.error as e:
            error_quit("Unable to connect due to: %s" % e, 500)
        self.logger.log("Received: %s" % msg_rec)
        print_debug(msg_rec)
        # Did not receive an acknowledgement to the connection, so terminate.
        if not msg_rec:
            self.close_socket(self.s)

    def ftp_connect(self, sock, host, port):
        """Connects Client to Server."""
        try:
            # Get IP address.
            ip = socket.gethostbyname(host)
        except socket.error:
            error_quit("Invalid or unknown host address!", 400)
        except Exception:
            error_quit("Invalid or unknown host address!", 400)
        try:
            # Connect socket to IP and Port.
            print_debug("PORT: " + str(port))
            port = int(port)
            sock.connect((ip, port))
        except socket.error:
            error_quit("Connection refused, did you specify the correct host and port?", 400)
        except Exception:
            error_quit("Terminating session due to issue in transmission.", 400)

    def send_and_log(self, sock, command):
        """Send command to socket, return server's
           response from command channel."""
        try:
            # Send command to server.
            sock.send(command)
            self.logger.log("Sent: %r" % command)
            # Receive response from server.
            msg_rec = repr(sock.recv(BUFF_SIZE))
            self.logger.log("Received: %s" % msg_rec)
        except socket.error:
            error_quit("Connection error, unable to send command.", 400)
        except Exception:
            error_quit("An unknown error has occurred.", 500)
        return msg_rec

    def get_from_data_channel(self, sock):
        """Return server's response from data channel."""
        msg_rec = b""
        # Continue reading from server until there's nothing left to read.
        while 1:
            buff = sock.recv(BUFF_SIZE)
            msg_rec += buff
            if len(buff) == 0:
                break
        self.logger.log("Received: %s" % msg_rec)
        return msg_rec

    def send_to_data_channel(self, sock, data):
        """Sends data to server via data channel."""
        resp = sock.send(data)
        print_debug(resp)
        self.logger.log("Sent: %s" % data)
        return resp

    def pasv_connection(self, sock, pasv_ip, pasv_port):
        """Connect pasv socket to data channel port for data to be read."""
        self.ftp_connect(sock, pasv_ip, pasv_port)

    def port_connection(self, sock):
        """Bind port socket so server can connect to it."""
        sock.bind(('', 0))  # Bind to OS-assigned available & random port.
        sock.listen(1)

    def parse_pasv_resp(self, msg_rec):
        """Helper for pasv_cmd() to parse out IP and Port of data channel."""
        num_ip_bytes = 4
        index_of_port_1 = 4
        index_of_port_2 = 5
        try:
            print_debug(msg_rec)
            # Parse out IP & Port from the parenthesis within the PASV resp.
            host_info = msg_rec[msg_rec.index("(") + 1:msg_rec.rindex(")")]
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

    def parse_port_req(self, sock):
        """Helper for port_cmd() to parse in IP and Port of data channel."""
        try:
            host_ip = self.s.getsockname()[0]  # Get local IPv4 addr of client.
            host_port = sock.getsockname()[1]  # Get opened port of socket.
            # PORT requires parameters split up as:
            # octet1,octet2,octet3,octet4,p1,p2
            list_csv_ip = host_ip.split('.')   # Split octets into a list.
            port_params = ""
            for octet in list_csv_ip:
                port_params += octet + ","
            # Parse port into PORT command's expected parameter.
            p1 = str((host_port - (host_port % 256)) / 256)
            p2 = str(host_port % 256)
            port_params += p1 + "," + p2
        except:
            return "", "", ""
        return port_params, host_ip, host_port

    def parse_epsv_resp(self, msg_rec):
        """Helper for epsv_cmd() to parse Port of data channel."""
        port_start_ind = 3
        try:
            # Get host port with delimiter from server's response.
            host_port_delim = msg_rec[msg_rec.index("(") + 1:msg_rec.rindex(")")]
            # Split based on delimiter.
            host_port_delim_split = host_port_delim.split(E_DELIMITER)
            # Get port from split list.
            host_port = host_port_delim_split[port_start_ind]
            print_debug("Parsed Port: %s" % host_port)
        except Exception:
            return ""
        return host_port

    def parse_eprt_req(self, sock, proto):
        """Helper for eprt_cmd() to parse in IP and Port of data channel."""
        try:
            net_prt = proto
            net_addr = self.s.getsockname()[0]  # Get local addr of client.
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
        """Send USER command to server."""
        print_debug("Executing USER")
        command = "USER %s\r\n" % username
        msg_rec = self.send_and_log(self.s, command)
        return msg_rec

    def pass_cmd(self, password):
        """Send PASS command to server."""
        print_debug("Executing PASS")
        command = "PASS %s\r\n" % password
        msg_rec = self.send_and_log(self.s, command)
        return msg_rec

    def cwd_cmd(self, new_dir):
        """Send CWD command to server."""
        print_debug("Executing CWD")
        command = "CWD %s\r\n" % new_dir
        msg_rec = self.send_and_log(self.s, command)
        return msg_rec

    def quit_cmd(self):
        """Send QUIT command to server."""
        print_debug("Executing QUIT")
        command = "QUIT\r\n"
        msg_rec = self.send_and_log(self.s, command)
        self.close_socket(self.s) # Close socket since we're done.
        return msg_rec

    def pasv_cmd(self):
        """Send PASV command to server."""
        print_debug("Executing PASV")
        command = "PASV\r\n"
        msg_rec = self.send_and_log(self.s, command)
        print_debug(msg_rec)
        # PASV creates a new connection from client to server.
        sock = new_socket()
        pasv_ip, pasv_port = self.parse_pasv_resp(msg_rec)
        self.pasv_connection(sock, pasv_ip, pasv_port)
        return msg_rec, sock

    def port_cmd(self):
        """Send PORT command to server."""
        print_debug("Executing PORT")
        # PORT creates a new connection from server to client.
        sock = new_socket()
        self.port_connection(sock)
        # Get required parameters for PORT command.
        port_params, host_ip, host_port = self.parse_port_req(sock)
        print_debug("PARAMS: " + port_params)
        command = "PORT %s\r\n" % port_params
        msg_rec = self.send_and_log(self.s, command)
        print_debug(msg_rec)
        return msg_rec, sock

    def epsv_cmd(self, proto="1"):
        """Send EPSV command to server."""
        print_debug("Executing EPSV")
        net_prt = proto
        command = "EPSV %s\r\n" % net_prt
        msg_rec = self.send_and_log(self.s, command)
        print_debug(msg_rec)
        # EPSV creates a new connection from client to server.
        sock = new_socket()
        # Get client port from Command Channel socket.
        epsv_port = self.parse_epsv_resp(msg_rec)
        # Get client ip from Command Channel socket.
        epsv_ip = self.s.getpeername()[0]
        # Create passive connection using acquired ip and port.
        self.pasv_connection(sock, epsv_ip, epsv_port)
        return msg_rec, sock

    def eprt_cmd(self, proto="1"):
        """Send EPRT command to server."""
        print_debug("Executing EPRT")
        sock = new_socket()
        # Create port connection using extended info.
        self.port_connection(sock)
        net_prt = proto
        # Get required parameters for EPRT command.
        eprt_params, net_addr, tcp_port = self.parse_eprt_req(sock, net_prt)
        print_debug("PARAMS: " + eprt_params)
        command = "EPRT %s\r\n" % eprt_params
        msg_rec = self.send_and_log(self.s, command)
        print_debug(msg_rec)
        return msg_rec, sock

    def retr_cmd(self, sock, path, transfer_type):
        """Send RETR command to server."""
        print_debug("Executing RETR")
        command = "RETR %s\r\n" % path
        msg_rec = self.send_and_log(self.s, command)
        print_debug(msg_rec)
        # Ensure we got a success message from the FTP server.
        if get_ftp_server_code(msg_rec) == FTP_STATUS_CODES["SUCCESSFUL_RETR"]:
            # Are we doing PORT or EPRT?
            if transfer_type == "1" or transfer_type == "3":
                # Have client accept data from server.
                conn, sockaddr = sock.accept()
                # Have client get data from server.
                data_rec = self.get_from_data_channel(conn)
                self.close_socket(conn)
            # Are we doing PASV or EPSV?
            else:
                # Have client get data from server.
                data_rec = self.get_from_data_channel(sock)
                self.close_socket(sock)
            # Get Transfer success / failed message.
            msg_cmd_rec = self.s.recv(BUFF_SIZE)
            print_debug("Transfer Status: " + str(msg_cmd_rec))
            if get_ftp_server_code(msg_cmd_rec) == FTP_STATUS_CODES["SUCCESSFUL_TRANSFER"]:
                print("Download successful.\n")
            else:
                print("Something went wrong when downloading. Try again.")
            return msg_rec, data_rec
        else:
            return "File not found or inaccessible.", None

    def stor_cmd(self, sock, local_file, remote_path, transfer_type):
        """Send STOR command to server."""
        print_debug("Executing STOR")
        command = "STOR %s\r\n" % remote_path
        msg_rec = self.send_and_log(self.s, command)
        print_debug(msg_rec)
        # Ensure we got a success message from the FTP server.
        if get_ftp_server_code(msg_rec) == FTP_STATUS_CODES["SUCCESSFUL_STOR"]:
            # Open file to upload and read it into variable "data"
            with open(local_file, "rb") as f:
                data = f.read()
            # Are we doing PORT or EPRT?
            if transfer_type == "1" or transfer_type == "3":
                # Have client accept data from server.
                conn, sockaddr = sock.accept()
                # Have client get data from server.
                data_rec = self.send_to_data_channel(conn, data)
                self.close_socket(conn)
            # Are we doing PASV or EPSV?
            else:
                # Have client get data from server.
                data_rec = self.send_to_data_channel(sock, data)
                self.close_socket(sock)
            # Get Transfer success / failed message.
            msg_cmd_rec = self.s.recv(BUFF_SIZE)
            print_debug("Transfer Status: " + str(msg_cmd_rec))
            if get_ftp_server_code(msg_cmd_rec) == FTP_STATUS_CODES["SUCCESSFUL_TRANSFER"]:
                print("Upload successful.\n")
            else:
                print("Something went wrong when uploading. Try again.")
            return msg_rec, data_rec
        else:
            return "File not found or inaccessible.", None

    def pwd_cmd(self):
        """Send PWD command to server."""
        print_debug("Executing PWD")
        command = "PWD\r\n"
        msg_rec = self.send_and_log(self.s, command)
        return msg_rec

    def syst_cmd(self):
        """Send SYST command to server."""
        print_debug("Executing SYST")
        command = "SYST\r\n"
        msg_rec = self.send_and_log(self.s, command)
        return msg_rec

    def help_cmd(self, cmd=None):
        """Send HELP command to server. Note: This is broken!"""
        print_debug("Executing HELP")
        # If we're looking up the HELP of a specific command...
        if cmd:
            # Send HELP COMMAND to the server.
            command = "HELP %s\r\n" % cmd
        # If we're just calling HELP...
        else:
            # Send HELP to the server.
            command = "HELP\r\n"
        self.s.send(command)
        self.logger.log("Sent: %r" % command)
        msg_rec = b""
        # Continue reading from server until there's nothing left to read.
        self.s.settimeout(1.5)
        while 1:
            try:
                buff = self.s.recv(BUFF_SIZE)
            except socket.timeout:
                break
            msg_rec += buff
            if len(buff) == 0:
                break
        self.s.settimeout(socket.getdefaulttimeout())
        self.logger.log("Received: %s" % msg_rec)
        return msg_rec

    def list_cmd(self, sock, transfer_type, path=None):
        """Send LIST command to server."""
        print_debug("Executing LIST")
        if path:
            # Send LIST command including the PATH to get info on that file
            # or directory.
            command = "LIST %s\r\n" % path
        else:
            # Send LIST command to list all files and directories in the
            # current directory.
            command = "LIST\r\n"
        msg_rec = self.send_and_log(self.s, command)
        # Are we doing PORT or EPRT?
        if transfer_type == "1" or transfer_type == "3":
            # Have client accept data from server.
            conn, sockaddr = sock.accept()
            # Have client get data from server.
            data_rec = self.get_from_data_channel(conn).decode('string_escape')[1:-1]
            self.close_socket(conn)
        # Are we doing PASV or EPSV?
        else:
            # Have client get data from server.
            data_rec = self.get_from_data_channel(sock).decode('string_escape')[1:-1]
            self.close_socket(sock)
        # Get Transfer success / failed message.
        msg_cmd_rec = self.s.recv(BUFF_SIZE)
        print_debug(data_rec)
        return data_rec

    def close_socket(self, sock):
        """Close socket passed as arg."""
        print_debug("Closing socket.")
        try:
            sock.close()
            # If data socket being closed, print status message.
            if sock != self.s:
                print_debug("Socket closed.")
        except socket.error:
            error_quit("Error closing socket!", 500)
        except Exception:
            error_quit("An unknown error occurred while closing the socket!", 500)


''' FUNCTIONS '''


def usage():
    """Prints the usage/help message for this program."""
    program_name = sys.argv[PROGRAM_ARG_NUM]
    print("Usage:")
    print("%s IP LOGFILE [PORT]" % program_name)
    print("  IP : IP address of host running the desired FTP Server.")
    print("  LOGFILE : Name of file containing FTP Client log details.")
    print("  PORT (optional) : Port used to connect to FTP Server. Default is"\
          " 21.")


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
    # Set port to DEFAULT if not specified as an arg. Otherwise, port = portarg.
    port = sys.argv[PORT_ARG_NUM] if len(sys.argv) == MAXIMUM_NUM_ARGS else DEFAULT_FTP_PORT
    port = validate_port(port)
    # Get host address and logfile name from args.
    host, log_file = sys.argv[HOST_ARG_NUM], sys.argv[LOG_ARG_NUM]
    return host, log_file, port


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


def prompt_username():
    """Prompt user for Username."""
    msg = "Enter Username: "
    username = raw_input(msg)
    return username


def prompt_pass():
    """Prompt user for Password. Hide input (make stdin invisible)."""
    msg = "Enter Password: "
    password = getpass.getpass(msg)
    return password


def get_ftp_server_code(resp_msg):
    """Returns the error code (a three-digit string) of an FTP server response."""
    if resp_msg.startswith("'"):
        print_debug(resp_msg[1:4])
        return resp_msg[1:4]
    else:
        print_debug(resp_msg[0:3])
        return resp_msg[0:3]


def login(ftp):
    """Prompt user for Username & Password, authenticate with FTP server."""
    # Get username
    username = prompt_username()
    ftp.user_cmd(username)
    # Get password
    password = prompt_pass()
    pass_data = ftp.pass_cmd(password)
    # Retry inputs if unsuccessful authentication.
    while get_ftp_server_code(pass_data) != FTP_STATUS_CODES["SUCCESSFUL_LOGIN"]:
        print_debug("Login incorrect, try again.")
        username = prompt_username()
        ftp.user_cmd(username)
        password = prompt_pass()
        pass_data = ftp.pass_cmd(password)


def new_socket():
    """Return a new socket."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    return s


def transfer_menu():
    """Displays Download Menu and prompts user to select an action."""
    print("What type of transfer do you want to use?")
    for key in sorted(TRANSFER_MENU_SELECTIONS):
        print("[%s] %s" % (key, TRANSFER_MENU_SELECTIONS[key]))
    choice = raw_input("> ")
    while choice not in list(TRANSFER_MENU_SELECTIONS.keys()):
        choice = raw_input("> ")
    return choice


def do_download(ftp):
    """Prompt for what to download, then call the appropriate FTP command."""
    # Active (PORT), Passive (PASV), ExtActive (EPRT), or ExtPassive (EPSV)?
    output, sock, transfer_type = get_transfer_output_and_socket(ftp)
    print_debug(output + "\n")

    # What file to download?
    path = raw_input("What file do you want to download?\n> ")
    while not path:
        path = raw_input("What file do you want to download?\n> ")
    try:
        msg_rec, data_rec = ftp.retr_cmd(sock, path, transfer_type)
        print_debug(str(msg_rec))
    except Exception as e:
        print("An error has occurred: " + str(e) + "\nPlease try again.")
        return main_menu(ftp)

    # Download file.
    if data_rec:
        print_debug(str(data_rec))
        try:
            write_to_local(path, data_rec)
        except Exception as e:
            print("An error has occurred: " + str(e) + "\nPlease try again.")
            return main_menu(ftp)
    main_menu(ftp)


def write_to_local(path, data_rec):
    """Writes content of data_rec to a file in path."""
    path, filename = os.path.split(path)
    with open(filename, 'wb') as f:
        f.write(data_rec)
    f.close()


def get_transfer_output_and_socket(ftp):
    """Gets transfer type from user, calls appropriate FTP command."""
    try:
        transfer_type = transfer_menu()
        if transfer_type == "1":
            output, sock = ftp.port_cmd()
        elif transfer_type == "2":
            output, sock = ftp.pasv_cmd()
        elif transfer_type == "3":
            output, sock = ftp.eprt_cmd("1") # Only worry about IPv4
        elif transfer_type == "4":
            output, sock = ftp.epsv_cmd("1") # Only worry about IPv4
    except Exception as e:
        print("An error has occurred: " + str(e) + "\nPlease try again.")
        return main_menu(ftp)
    return output, sock, transfer_type


def do_upload(ftp):
    """Prompt for what to upload, then call the appropriate FTP command."""
    # Active (PORT), Passive (PASV), ExtActive (EPRT), or ExtPassive (EPSV)?
    output, sock, transfer_type = get_transfer_output_and_socket(ftp)
    print_debug(output + "\n")

    # What file to upload?
    local_file = raw_input("What local file do you want to upload?\n> ")
    is_file = os.path.isfile(local_file)
    while not local_file or not is_file:
        if not is_file:
            print("File not found.")
        local_file = raw_input("What local file do you want to upload?\n> ")
        is_file = os.path.isfile(local_file)
    # What to save file as?
    remote_path = raw_input("What do you want to name the remote file?\n> ")
    while not remote_path:
        remote_path = raw_input("What do you want to name the remote file?\n> ")
    try:
        msg_rec, data_rec = ftp.stor_cmd(sock, local_file, remote_path, transfer_type)
        print_debug(str(data_rec))
    except Exception as e:
        print("An error has occurred: " + str(e) + "\nPlease try again.")
        return main_menu(ftp)
    main_menu(ftp)


def do_list(ftp):
    """Prompt for what to list, then call the appropriate FTP command."""
    # Active (PORT), Passive (PASV), ExtActive (EPRT), or ExtPassive (EPSV)?
    output, sock, transfer_type = get_transfer_output_and_socket(ftp)
    print_debug(output + "\n")

    path = raw_input("What directory or file do you want to list (blank=current)?\n> ")
    try:
        if path:
            output = ftp.list_cmd(sock, transfer_type, path)
        else:
            output = ftp.list_cmd(sock, transfer_type)
        print("%s" % output)
    except Exception as e:
        print("An error has occurred: " + str(e) + "\nPlease try again.")
        return main_menu(ftp)
    main_menu(ftp)


def do_cwd(ftp):
    """Prompt for what dir to change to; call the appropriate FTP command."""
    new_dir = raw_input("What directory do you want to change to?\n> ")
    try:
        output = ftp.cwd_cmd(new_dir)
        if get_ftp_server_code(output) == FTP_STATUS_CODES["SUCCESSFUL_CWD"]:
            print("Successfully changed directory\n")
        else:
            print("Invalid directory or insufficient permissions.\n")
    except Exception as e:
        print("An error has occurred: " + str(e) + "\nPlease try again.")
        return main_menu(ftp)
    main_menu(ftp)


def do_pwd(ftp):
    """Call the appropriate FTP command to display the working directory."""
    try:
        output = ftp.pwd_cmd()
        output = parse_server_response(output)
        print("%s\n" % output)
    except Exception as e:
        print("An error has occurred: " + str(e) + "\nPlease try again.")
        return main_menu(ftp)
    main_menu(ftp)


def do_syst(ftp):
    """Call the appropriate FTP command to display server info."""
    try:
        output = ftp.syst_cmd()
        output = parse_server_response(output)
        print("%s\n" % output)
    except Exception as e:
        print("An error has occurred: " + str(e) + "\nPlease try again.")
        return main_menu(ftp)
    main_menu(ftp)


def do_help(ftp):
    """Call the appropriate FTP command to display the server's help info."""
    try:
        cmd = raw_input("What command do you need help with (blank=general)?\n> ")
        if cmd:
            output = ftp.help_cmd(cmd)
        else:
            output = ftp.help_cmd()
        output = parse_server_response(output)
        print("%s\n" % output)
    except Exception as e:
        print("An error has occurred: " + str(e) + "\nPlease try again.")
        return main_menu(ftp)
    main_menu(ftp)


def do_quit(ftp):
    """Call the appropriate FTP command to disconnect from server."""
    try:
        ftp.quit_cmd()
    except Exception as e:
        print("An error has occurred: " + str(e) + "\nPlease try again.")
        return main_menu(ftp)


def parse_server_response(msg):
    """Return server response without server tags and status codes."""
    if msg.startswith("'"):
        print_debug(msg[5:-5])
        return msg[5:-5]
    else:
        print_debug(msg)
        return msg


def handle_main_menu_choice(choice, ftp):
    """Calls function associated with user's Main Menu choice."""
    function_to_call = MAIN_MENU_SELECTIONS[choice][1]
    globals()[function_to_call](ftp)  # Call the function.


def main_menu(ftp):
    """Displays Main Menu and prompts user to select an action."""
    print("What would you like to do?")
    for key in sorted(MAIN_MENU_SELECTIONS):
        print("[%s] %s" % (key, MAIN_MENU_SELECTIONS[key][0]))
    choice = raw_input("> ")
    while choice not in list(MAIN_MENU_SELECTIONS.keys()):
        choice = raw_input("> ")
    handle_main_menu_choice(choice, ftp)


def do_ftp(ftp):
    """Driver that prompts for login, then displays the main menu."""
    login(ftp)
    main_menu(ftp)


''' DEBUG '''


def print_debug(msg):
    """Prints if we are in debug mode."""
    if IS_DEBUG:
        print(msg)


''' MAIN '''


def main():
    """Main driver that parses args, creates our Logger & FTP objects,
       and starts the do_ftp driver."""
    print_debug("Starting...")
    host, log_file, port = parse_args()
    logger = Logger(log_file)
    ftp = FTP(host, logger, port)
    do_ftp(ftp)


''' PROCESS '''
if __name__ == '__main__':
    main()
