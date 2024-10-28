###############################################################################################
#  
#  Created by: Jonathan Tan (jona1115@iastate.edu)
#  Date      : 1/25/2024
#  
###########################################################################################
#  
#  SshConnector.py: This class is used to connect to a remote server via ssh. After successfully
#                   connecting to ssh, the class will also be used to send commands via the opened
#                   ssh connection.
#  
#  Revision 1 (x/x/xxxx):
#  
###############################################################################################

# Library imports
import threading
import time
from loguru import logger
import paramiko
from scp import SCPClient

# Project imports


# Start of code
class SshConnector:
    # Constructor
    def __init__(self, givennSSHhost, givenSSHusername, givenSSHpassword):
        # Yes, very secure I know :)
        self.sshHost = givennSSHhost
        self.sshUsername = givenSSHusername
        self.sshPassword = givenSSHpassword
        self.sshConnected = False
    
    ######################## Methods ########################
    def connect(self):
        """
        This function will do the initial ssh sonnection stuff.

        This method/function is partially written by, or written with the aid of, ChatGPT.
        """
        # Initialize SSH client
        self.ssh_client = paramiko.SSHClient()
        self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # Connect to the server
        try:
            # Connect to the server
            self.ssh_client.connect( hostname=self.sshHost,
                                username=self.sshUsername,
                                password=self.sshPassword)
            # If connection is successful
            self.sshConnected = True
        except paramiko.AuthenticationException:
            logger.error("Authentication failed, please verify your credentials.")
            self.sshConnected = False
        except paramiko.SSHException as sshException:
            logger.error(f"Could not establish SSH connection: {sshException}")
            self.sshConnected = False
        
    def disconnect(self):
        """
        Disconnects the current SSH connection.

        This method/function is partially written by, or written with the aid of, ChatGPT.
        """
        if self.sshConnected:
            self.ssh_client.close()
            self.sshConnected = False
            logger.info("SSH connection closed.")
        else:
            logger.warning("No active SSH connection to close.")

    def reset_connection(self):
        """
        Resets the SSH connection by disconnecting and then reconnecting.

        This method/function is partially written by, or written with the aid of, ChatGPT.
        """
        self.disconnect()
        self.connect()
        
    def execute_command(self, command, wantPrint=True):
        """
        Executes a command on the remote server and return & prints (wantPrint) the output.

        This method/function is partially written by, or written with the aid of, ChatGPT.
        """
        if self.sshConnected:
            logger.info(f"Executing non-sudo command: {command}...")
            
            # Execute the command
            stdin, stdout, stderr = self.ssh_client.exec_command(command)
            
            # Wait for the command to complete
            stdout.channel.recv_exit_status()
            
            # Read the output from stdout and stderr
            output = stdout.read().decode()
            error = stderr.read().decode()
            
            if error:
                if wantPrint:
                    logger.error("ERROR:")
                    print(error)
                else:
                    logger.error("An error occur on server, it could also be a warning.")
                return (-1, error) # Return -1 for error
            if output:
                if wantPrint:
                    logger.info("OUTPUT:")
                    print(output)
                return (0, output) # Return 0 for no error
        else:
            bad = "Connection not established. Please connect first."
            logger.error(bad)
            return (-2, bad) # Return -2 for error

    def execute_sudo_command_blocking_live(self, command, sudo_password, timeout=10, wantPrint=True):
        """
        Executes a sudo command on the remote server and prints the output as it arrives.
        The sudo password is required.

        When it is ready to shutdown, this function will ctrl-c + exit to kill running process
        and the ssh connection.

        This is a blocking function.

        This method/function is partially written by, or written with the aid of, ChatGPT.
        """
        if self.sshConnected:
            logger.info(f"Executing sudo command: {command}...")
            
            channel = self.ssh_client.get_transport().open_session()
            channel.get_pty()
            channel.invoke_shell()

            # Function to continuously fetch and print output
            def print_output():
                while True and wantPrint:
                    if channel.recv_ready():
                        print(channel.recv(1024).decode('utf-8'), end='', flush=True)
                    if channel.recv_stderr_ready():
                        print(channel.recv_stderr(1024).decode('utf-8'), end='', flush=True)
                    if channel.exit_status_ready():  # If command is done, exit the loop
                        break

            # Send the sudo command
            channel.send(f'echo {sudo_password} | sudo -S -p "" {command}\n')

            # Start a thread to print the command output
            output_thread = threading.Thread(target=print_output)
            output_thread.start()

            # Let the command run for a certain period (timeout)
            time.sleep(timeout)

            # Send Ctrl+C to stop the perf command
            channel.send('\x03')
            time.sleep(1)  # Give some time to process Ctrl+C

            # Send 'exit' to close the shell session
            channel.send('exit\n')
            time.sleep(1)  # Give some time to process the exit command

            # Wait for the output thread to finish
            output_thread.join()

            # Close the channel
            channel.close()
        else:
            logger.error("Connection not established. Please connect first.")

    def execute_sudo_command_blocking_nonlive(self, command, sudo_password, timeout=10, wantPrint=True):
        """
        Executes a sudo command on the remote server and prints the output after timeout.
        The sudo password is required.

        This is a blocking function.

        This method/function is partially written by, or written with the aid of, ChatGPT.
        """
        if self.sshConnected:
            logger.info(f"Executing sudo command: {command}...")
            
            channel = self.ssh_client.get_transport().open_session()
            channel.get_pty()
            channel.invoke_shell()
            
            # Send the sudo command
            channel.send(f'echo {sudo_password} | sudo -S -p "" {command}\n')
            
            # Buffer to receive data
            output_buffer = ""
            error_buffer = ""
            
            # Give some time for the command to start
            time.sleep(1)
            
            # Capture the output for a certain period
            end_time = time.time() + timeout
            while time.time() < end_time:
                if channel.recv_ready():
                    output_buffer += channel.recv(1024).decode('utf-8')
                if channel.recv_stderr_ready():
                    error_buffer += channel.recv_stderr(1024).decode('utf-8')
                time.sleep(0.5)  # Prevent tight loop
            
            # Send Ctrl+C to stop the perf command
            channel.send('\x03')
            time.sleep(1)  # Give some time to process Ctrl+C
            
            # Read any remaining data in the buffer
            if channel.recv_ready():
                output_buffer += channel.recv(1024).decode('utf-8')
            if channel.recv_stderr_ready():
                error_buffer += channel.recv_stderr(1024).decode('utf-8')
            
            # Close the channel
            channel.close()

            # Print output and errors
            if output_buffer:
                if wantPrint:
                    logger.info("OUTPUT:")
                    print(output_buffer)
            if error_buffer:
                logger.error("ERROR:")
                print(error_buffer)
        else:
            logger.error("Connection not established. Please connect first.")

    # Untested
    def execute_sudo_command_nonblocking_live(self, command, sudo_password, timeout=10):
        if self.sshConnected:
            logger.info(f"Executing sudo command (non-blocking, live): {command} with a timeout of {timeout} seconds...")

            channel = self.ssh_client.get_transport().open_session()
            channel.get_pty()
            channel.invoke_shell()

            def print_output_nonblocking():
                end_time = time.time() + timeout
                while time.time() < end_time:
                    if channel.recv_ready():
                        print(channel.recv(1024).decode('utf-8'), end='', flush=True)
                    if channel.recv_stderr_ready():
                        print(channel.recv_stderr(1024).decode('utf-8'), end='', flush=True)
                    if channel.exit_status_ready():
                        break
                    time.sleep(0.5)

                # Close the channel after the timeout
                channel.close()

            # Start thread for non-blocking output printing
            thread = threading.Thread(target=print_output_nonblocking)
            thread.start()

            # Send the sudo command
            channel.send(f'echo {sudo_password} | sudo -S -p "" {command}\n')

            # Wait for the thread to finish
            thread.join(timeout)
            if thread.is_alive():
                logger.info("Command execution reached timeout.")
                thread.join()  # Ensure the thread has finished
        else:
            logger.error("Connection not established. Please connect first.")

    def execute_sudo_command_nonblocking_nonlive(self, command, sudo_password, timeout=10):
        """
        This is just like execute_sudo_command_blocking_nonlive but this is nonblocking. Meaning
        you can call another ssh command immediately after this line and the 2nd command will
        execute.

        This is a nonblocking function.

        This method/function is partially written by, or written with the aid of, ChatGPT.
        """
        if self.sshConnected:
            logger.info(f"Executing sudo command (non-blocking, non-live): {command}...")

            channel = self.ssh_client.get_transport().open_session()
            channel.get_pty()
            channel.invoke_shell()

            # Send the sudo command
            channel.send(f'echo {sudo_password} | sudo -S -p "" {command}\n')

            # Use a timer to handle the timeout
            def handle_timeout():
                if not channel.exit_status_ready():
                    # If timeout is reached and command is still running, you can choose to kill it or leave it running
                    logger.info("Command execution reached timeout.")
                    # Example: channel.send('\x03') # Send Ctrl+C

            timer = threading.Timer(timeout, handle_timeout)
            timer.start()
        else:
            logger.error("Connection not established. Please connect first.")

    def scp_get(self, remote_path, local_path):
        """
        This method will copy a file from the remote path to the local path using SCP.

        This method/function is partially written by, or written with the aid of, ChatGPT.
        """
        if self.sshConnected:
            CE_counter = 0
            while True:
                try:
                    with SCPClient(self.ssh_client.get_transport()) as scp:
                        scp.get(remote_path, local_path)
                        logger.info(f"File copied successfully from {remote_path} to {local_path}")
                        break
                except paramiko.ChannelException as ce:
                    if (CE_counter <= 1): # When fail, reset, but if fail more than once in a row, raise exception
                        self.reset_connection()
                        CE_counter += 1
                        continue
                    else:
                        raise paramiko.ChannelException(ce.code, ce.text)
                except Exception as e:
                    logger.error(f"Failed to copy file: {e}")
                    break
        else:
            logger.error("SSH Connection not established.")

    def scp_send(self, local_path, remote_path):
        """
        This method will copy a file from the local path to the remote path using SCP.

        This method/function is partially written by, or written with the aid of, ChatGPT.
        """
        if self.sshConnected:
            try:
                with SCPClient(self.ssh_client.get_transport()) as scp:
                    scp.put(local_path, remote_path)
                    logger.info(f"File sent successfully from {local_path} to {remote_path}")
            except Exception as e:
                logger.error(f"Failed to send file: {e}")
        else:
            logger.error("SSH Connection not established.")

    
    ######################## Getters&Setters ########################
    def getSshConnectionStatus(self):
        return self.sshConnected

