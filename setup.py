#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# quick script for installing tap
#
##
import base64
import getpass
import os
import re
import shutil
import stat
import subprocess
import sys
from argparse import ArgumentParser
from dataclasses import dataclass
from pathlib import Path

from src.core.tapcore import motd, set_background, ssh_keygen

try:
    import pexpect
except ImportError as e:
    print("Error importing pexpect. Install pexpect from requirements.txt then rerun setup.")
    raise(e)
try:
    from Crypto.Cipher import AES
except ImportError as e:
    print(f"Error importing AES. Install cryptodome from requirements.txt then rerun setup.")
    raise(e)

# print("[*] Installing some base packages...")
# subprocess.Popen("apt-get -y install htop dbus-x11", shell=True).wait()

def kill_tap(dry_run : bool = False):
    proc = subprocess.Popen("ps -au | grep tap", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    # print proc.stdout.read()
    print(proc.stdout.read())
    for line in proc.stdout:
        try:
            match = re.search("tap.py", line)
            if match:
                print("[*] Killing running version of TAP..")
                line = line.split(" ")
                pid = line[6]
                custom_shell("kill %s" % (pid), stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, dry_run=dry_run)
                print("[*] Killed the TAP process: " + pid)

        except: pass

        try:
            # kill the heartbeat health check
            match = re.search("heartbeat.py", line)
            if match:
                print("[*] Killing running version of TAP HEARTBEAT..")
                line = line.split(" ")
                pid = line[6]
                custom_shell("kill %s" % (pid), stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, dry_run=dry_run)
                print("[*] Killed the Heartbeat TAP process: " + pid)
        except: pass

# # here we encrypt via aes, will return encrypted string based on secret key which is random
# def encryptAES(data):
#     # the character used for padding--with a block cipher such as AES, the value
#     # you encrypt must be a multiple of BLOCK_SIZE in length.  This character is
#     # used to ensure that your value is always a multiple of BLOCK_SIZE
#     PADDING = '{'
#     BLOCK_SIZE = 32
#     # one-liner to sufficiently pad the text to be encrypted
#     pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING
#     # random value here to randomize builds
#     a = 50 * 5
#     # one-liners to encrypt/encode and decrypt/decode a string
#     # encrypt with AES, encode with base64
#     EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
#     DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)
#     secret = os.urandom(BLOCK_SIZE)
#     cipher = AES.new(secret)
#     secret = base64.b64encode(secret)
#     aes = EncodeAES(cipher, data)
#     return aes.decode("utf-8") + "::::" + secret.decode("utf-8")

# print (r"""
                                                                      
# TTTTTTTTTTTTTTTTTTTTTTT         AAA               PPPPPPPPPPPPPPPPP   
# T:::::::::::::::::::::T        A:::A              P::::::::::::::::P  
# T:::::::::::::::::::::T       A:::::A             P::::::PPPPPP:::::P 
# T:::::TT:::::::TT:::::T      A:::::::A            PP:::::P     P:::::P
# TTTTTT  T:::::T  TTTTTT     A:::::::::A             P::::P     P:::::P
#         T:::::T            A:::::A:::::A            P::::P     P:::::P
#         T:::::T           A:::::A A:::::A           P::::PPPPPP:::::P 
#         T:::::T          A:::::A   A:::::A          P:::::::::::::PP  
#         T:::::T         A:::::A     A:::::A         P::::PPPPPPPPP    
#         T:::::T        A:::::AAAAAAAAA:::::A        P::::P            
#         T:::::T       A:::::::::::::::::::::A       P::::P            
#         T:::::T      A:::::AAAAAAAAAAAAA:::::A      P::::P            
#       TT:::::::TT   A:::::A             A:::::A   PP::::::PP          
#       T:::::::::T  A:::::A               A:::::A  P::::::::P          
#       T:::::::::T A:::::A                 A:::::A P::::::::P          
#       TTTTTTTTTTTAAAAAAA                   AAAAAAAPPPPPPPPPP          
                                                                    
#         The TrustedSec Attack Platform
#         Written by: Dave Kennedy (@HackingDave)

#         https://github.com/trustedsec/tap

#        The self contained-deployable penetration testing kit
# """)

# print(""" 
# Welcome to the TAP installer. TAP is a remote connection setup tool that will install a remote
# pentest platform for you and automatically reverse SSH out back to home.
#  """)

def custom_shell(command : str, dry_run : bool = False, kwargs : dict = {}):
    if dry_run:
        print(f"[DRY RUN] {command}")
    else:
        subprocess.Popen(command, shell=True, **kwargs).wait()

@dataclass
class Config:
    # runtime options
    debug: bool = False # TODO: use to set logging level
    dry_run: bool = False
    # service options
    install: bool = None
    uninstall: bool = None
    update_programs: bool = None
    auto_update: bool = None
    install_programs: bool = None
    # authentication options
    use_ssh_keys: bool = None
    use_password: bool = None
    password: str = None
    username: str = None
    existing_key: bool = None
    ssh_key: Path = None
    keys_on_remote: bool = None
    new_key_name: str = None

    # ssh options
    local_port: int = None
    socks_port: int = None
    remote_host: str = None
    remote_port: int = None
    # misc options
    background: bool = None
    update_tap: bool = None
    git_url: str = None
    log_everything: bool = None

    def wizard(self):
        """Check for required options and prompt user for missing ones
        This is interactive and modifies the state of self
        """
        def prompt_user(self, attr, question, responses):
            while getattr(self, attr) is None:
                resp = input(question)
                resp = resp[0].lower() if resp else ''
                if resp in responses:
                    setattr(self, attr, responses[resp])
                else:
                    print("Invalid response. Please enter one of " + "/".join(responses.keys()))

        if self.install is None and self.uninstall is None:
            while True:
                resp = input("Do you want to install or uninstall TAP: [i/u]: ")
                if resp[0].lower() == "i":
                    self.install = True
                    break
                elif resp[0].lower() == "u":
                    self.uninstall = True
                    break
                else:
                    print("Invalid response. Please enter 'i' or 'u'")
        prompt_user(self, "update_programs", "Do you want to update all programs: [y/n]: ", {"y": True, "n": False})
        prompt_user(self, "update_tap", "Do you want to update TAP: [y/n]: ", {"y": True, "n": False})
        prompt_user(self, "install_programs", "Do you want to install all programs: [y/n]: ", {"y": True, "n": False})
        prompt_user(self, "use_ssh_keys", "Do you want to use SSH keys for authentication: [y/n]: ", {"y": True, "n": False})
        prompt_user(self, "log_everything", "Do you want to log everything: [y/n]: ", {"y": True, "n": False})
        prompt_user(self, "keys_on_remote", "Are the SSH keys on the remote server: [y/n]: ", {"y": True, "n": False})
        prompt_user(self, "start_tap", "Do you want to start TAP on successful installation: [y/n]: ", {"y": True, "n": False})
        if self.use_ssh_keys:
            # Determine if they want to create new keys or use old keys
            prompt_user(self, "existing_key", "Do you want to use existing SSH keys: [y/n]: ", {"y": True, "n": False})
            if self.existing_key:
                while True:
                    ssh_key = input("Enter path to SSH public key: ")
                    if os.path.isfile(ssh_key):
                        self.ssh_key = Path(ssh_key)
                        break
                    else:
                        print("Invalid path. Please try again.")
            else: # Writing a new key
                while True:
                    new_key_path = input("Enter path for new SSH keypair (don't include .pub): ") # Should be full path to file
                    # check if path is valid
                    if os.path.isfile(new_key_path):
                        print("File already exists. Please try again.")
                        continue
                    # check if path is valid
                    if os.path.isdir(os.path.dirname(new_key_path)):
                        self.ssh_key = Path(new_key_path)
                        break
                    else:
                        print("Invalid name. Please try again.")
        # Create new keys later
        if not self.use_ssh_keys:
            prompt_user(self, "use_password", "Do you want to use a password for authentication (only option - declined SSH keys): [y/n]: ", {"y": True})
            if self.use_password:
                while True:
                    pw1 = getpass.getpass("Enter password for SSH connection: ")
                    pw2 = getpass.getpass("Confirm password for SSH connection: ")
                    if pw1 == pw2:
                        self.password = pw1
                        break
                    print("Passwords do not match. Please try again.")
        if self.username is None:
            self.username = input("Enter username for SSH connection: ").strip()
        if self.local_port is None:
            self.local_port = int(input("Enter local port for SSH connection on the REMOTE MACHINE: ").strip())
        if self.socks_port is None:
            self.socks_port = int(input("Enter local port for SOCKS proxy on the REMOTE MACHINE: ").strip())
        if self.remote_host is None:
            self.remote_host = input("Enter remote host for SSH connection: ").strip()
        if self.remote_port is None:
            self.remote_port = int(input("Enter remote port for SSH connection: ").strip())



def parse_args() -> Config:
    print("Entered parse_args")
    parser = ArgumentParser(
        description="TAP Installer Options. Any options not specified will be prompted for in the wizard. "
            "If you want to run the wizard, run the installer with no arguments. "
            "The bare-minimum required options for installing automatically depend on the authentication method."
            "For all methods, you must specify --remote-host --remote-port --local-port --socks-port --username --install ."
            "For SSH keys, you must specify --use-ssh-keys --keys-on-remote True|False [--ssh-key]."
            "For password, you must specify --use-password [--password] (--password is optional if the TAP_PASSWORD environment variable is set).")
    runtime_options = parser.add_argument_group("Runtime", description="Runtime options")
    runtime_options.add_argument("--debug", action="store_true", help="Enable debug mode", default=False)
    runtime_options.add_argument("--dry-run", action="store_true", help="Dry run", default=False)

    service_group = parser.add_argument_group("Service", description="Service options")
    install_group = service_group.add_mutually_exclusive_group()
    install_group.add_argument("-i", "--install", action="store_true", help="Install TAP", default=None)
    install_group.add_argument("-u", "--uninstall", action="store_true", help="Uninstall TAP", default=None)
    service_group.add_argument("--update-programs", action="store_true", help="Update all required programs", default=None)
    service_group.add_argument("--update-tap", action="store_true", help="Update TAP", default=None)
    service_group.add_argument("--install-programs", action="store_true", help="Install all required programs", default=None)
    service_group.add_argument("--start-tap", action="store_true", help="Start TAP", default=None)

    auth_group = parser.add_argument_group("Authentication", description="Authentication options")
    auth_type_group = auth_group.add_mutually_exclusive_group()
    auth_type_group.add_argument("--use-ssh-keys", action="store_true", help="Use SSH keys for authentication", default=None)
    auth_type_group.add_argument("--use-password", action="store_true", help="Use password for authentication", default=None)
    auth_group.add_argument("--password", help="Password for SSH connection, can also read from the environment variable TAP_PASSWORD", default=os.environ.get("TAP_PASSWORD", None))
    auth_group.add_argument("--username", help="Username for SSH connection", default=None)
    auth_group.add_argument("--ssh-key", help="SSH public key for SSH connection", default=None, type=Path)
    auth_group.add_argument("--keys-on-remote", help="If the public key exists on the remote server", default=None, type=bool)
    # auth_group.add_argument("--existing-key", action="store_true", help="Use existing SSH key", default=None)

    ssh_group = parser.add_argument_group("SSH", description="SSH options")
    ssh_group.add_argument("--local-port", help="Local port for SSH connection on the REMOTE MACHINE", default=None)
    ssh_group.add_argument("--socks-port", help="Local port for SOCKS proxy on the REMOTE MACHINE", default=None)
    ssh_group.add_argument("--remote-host", help="Remote host for SSH connection", default=None)
    ssh_group.add_argument("--remote-port", help="Remote port for SSH connection", default=None)

    misc_group = parser.add_argument_group("Misc", description="Misc options")
    misc_group.add_argument("--auto-update", action="store_true", help="Automatically update TAP", default=None)
    misc_group.add_argument("--background", action="store_true", help="Set background", default=None)
    misc_group.add_argument("--git-url", help="URL to git repo to clone", default="https://github.com/trustedsec/tap.git")
    misc_group.add_argument("--log-everything", action="store_true", help="TAP has the ability to log every command "
        "used via SSH. This is useful for clients who want log files of the pentest. All logs are saved in /var/log/messages"
        , default=None)

    args = parser.parse_args()
    return Config(**vars(args))

def install_tap(config: Config):
    # if directories aren't there then create them
    if not os.path.isdir("/usr/share/tap"):
        custom_shell("mkdir /usr/share/tap", dry_run=config.dry_run)
    # install to rc.local
    print("[*] Adding TAP into startup through init scripts..")
    if os.path.isdir("/etc/init.d"):
        # remove old startup
        if os.path.isfile("/etc/init.d/tap"): os.remove("/etc/init.d/tap")
        # can just copy since there's no templating
        custom_shell("cp src/core/startup_tap /etc/init.d/tap", dry_run=config.dry_run)
        custom_shell("chmod +x /etc/init.d/tap", dry_run=config.dry_run)
        custom_shell("update-rc.d tap defaults", dry_run=config.dry_run)
    # installing programs is handled in the top level - don't need to here
    # Get tap files to /usr/share/tap
    # first, clean the directory
    custom_shell("rm -rf /usr/share/tap", dry_run=config.dry_run)
    if config.auto_update:
        print("[*] Checking out latest TAP to /usr/share/tap")
        custom_shell(f"git clone {config.git_url} /usr/share/tap/", dry_run=config.dry_run)
        print("[*] Finished. If you want to update tap go to /usr/share/tap and type 'git pull'")
    else:
        print("[*] Copying setup files over...")
        custom_shell("cp -rf * /usr/share/tap/", dry_run=config.dry_run)
    # logging everything is handled in the top level - don't need to here
    # Connect to the remote SSH server and setup the reverse SSH connection
    if config.use_ssh_keys:
        # Check if ssh keys exist - if not, make one
        if not config.existing_key:
            # make a key
            print("[*] Generating a new SSH keypair...")
            custom_shell(f"ssh-keygen -q -c 'TAP Keypair' -t rsa -b 4096 -f {str(config.ssh_key.absolute().resolve())}", dry_run=config.dry_run)
            custom_shell("ssh-add %s" % (str(config.ssh_key.absolute().resolve())), dry_run=config.dry_run)
        # At this point, a key is guaranteed to exist
        if config.keys_on_remote:
            child = pexpect.spawn("ssh %s@%s -p %s" % (config.username,config.host,config.remote_port))
            i = child.expect(['The authenticity of host', 'password', 'Connection refused', 'Permission denied, please try again.', 'Last login:'])
            if i < 4:
                print("[*] Error: Could not connect to remote server. Either the SSH Key is incorrectly configured or no SSH Key has been configured")
                sys.exit()
            if i == 4:
                print("[*] Successfully logged into the system, good to go from here!")
        else: # Need to put keys on the remote device
            print("[*] We need to upload the public key to the remote server, enter the password for the remote server (once) to upload when prompted.")
            # clearing known hosts
            if os.path.isfile("/root/.ssh/known_hosts"):
                print("[!] Removing old known_hosts files..")                    
                os.remove("/root/.ssh/known_hosts")

            # pull public key into memory

            fileopen = open(f"{str(config.ssh_key)}.pub", "r")
            pub = fileopen.read()
            # spawn pexpect to add key
            child = pexpect.spawn("ssh %s@%s -p %s" % (config.username,config.host,config.remote_port))
            i = child.expect(['The authenticity of host', 'password', 'Connection refused'])
            if i == 0:
                child.sendline("yes")
                child.expect("password")
                child.sendline(config.password)

            if i == 1:
                child.sendline(config.password)

            if i ==2:
                print ("Cannot connect to server - connection refused. Please check the port and try again.")
                sys.exit()

            # here we need to verify that we actually log in with the right password
            i = child.expect(['Permission denied, please try again.', 'Last login:'])
            if i == 0:
                print("[!] ERROR!!!! You typed in the wrong password.")
                # password_onetime = getpass.getpass("Lets try this again. Enter your SSH password: ")
                child.sendline(config.password)
                # second time fat fingering, no dice bro
                i = child.expect(['Permission denied, please try again.'])
                if i == 0:
                    print("[!] Sorry boss, still denied. Figure out the password and run setup again.")
                    print("[!] Exiting TAP setup...")
                    # exit TAP here
                    sys.exit()
                # successfully logged in
                else:
                    print("[*] Successfully logged into the system, good to go from here!")

            if i == 1:
                print("[*] Successfully logged into the system, good to go from here!")

            # next we grab the hostname so we can enter it in the authorized keys for a description
            fileopen = open("/etc/hostname", "r")
            hostname = fileopen.read()
            # add a space
            child.sendline("echo '' >> ~/.ssh/authorized_keys")
            # comment code for authorized list
            child.sendline("echo '# TAP box for hostname: %s' >> ~/.ssh/authorized_keys" % (hostname))
            # actual ssh key
            child.sendline("echo '%s' >> ~/.ssh/authorized_keys" % (pub))
            print("[*] Key for %s added to the external box: %s" % (hostname, config.host))
        # Check if ssh keys already installed
    else: # This is password auth
        # Encrypt the password
        print("[*] Encrypting the password now...")
        tmp = encryptAES(config.password)
        password = tmp.split("::::")[0]
        key = tmp.split("::::")[1]
        if not os.path.isdir("/root/.tap"):
            os.makedirs("/root/.tap")
        filewrite = open("/root/.tap/key", "w")
        filewrite.write(key)
        filewrite.close()
    # Write out the config
    filewrite = open("/usr/share/tap/config", "w")
    filewrite.write("# tap config options\n\n")
    filewrite.write("# The username for the ssh connection\nUSERNAME=%s\n# The password for the reverse ssh connection\nPASSWORD=%s\n# The reverse ssh ipaddr or hostname\nIPADDR=%s\n# The port for the reverse connect\nPORT=%s\n" % (config.username, password,config.host,config.local_port))
    filewrite.write("# SSH check is in seconds\nSSH_CHECK_INTERVAL=60\n")
    filewrite.write("# The local SSH port on the reverse SSH host\nLOCAL_PORT=%s\n" % (config.local_port))
    filewrite.write("# Where to pull updates from\nUPDATE_SERVER=%s\n" % ("EMPTY - UPDATES"))
    filewrite.write("# URL for command updates - ENSURE THAT THE FIRST LINE OF TEXT FILE HAS: 'EXECUTE COMMANDS' or it will not execute anything!\nCOMMAND_UPDATES=%s\n" % ("EMPTY - COMMANDS"))
    filewrite.write("# SPECIFY IF TAP WILL AUTOMATICALLY UPDATE OR NOT\nAUTO_UPDATE=%s\n" % (config.auto_update))
    filewrite.write("# SPECIFY IF SSH KEYS ARE IN USE OR NOT\nSSH_KEYS=%s\n" % ("ON" if config.use_ssh_keys else "OFF"))
    filewrite.write("# LOG EVERY COMMAND VIA SSH? YES OR NO - ALL LOGS GO TO /var/log/messages\nLOG_EVERYTHING=%s\n" % ("YES" if config.log_everything else "NO"))
    filewrite.write("# THIS IS USED TO TUNNEL SOCKS HTTP TRAFFIC FOR LINUX UPDATES\nSOCKS_PROXY_PORT=%s\n" % (config.socks_port))
    filewrite.close()

    # Now we need to configure the local SSH server to allow logins
    print("[*] Configuring the local SSH server...")
    data = open("/etc/ssh/sshd_config", "r").read()
    filewrite = open("/etc/ssh/sshd_config", "w")
    # This should honestly just be a template since the other SSH stuff can trash ssh
    data = data.replace("PermitRootLogin without-password", "PermitRootLogin yes")
    filewrite.write(data)
    filewrite.close()
    print("[*] Restarting the SSH service after changes.")
    subprocess.Popen("service ssh restart", shell=True).wait()
    print("[*] Installation complete. Edit /usr/share/tap/config in order to config tap to your liking..")

    # setting background
    if config.background:
        print("[*] Setting background..")
        # set_background()

    # start tap
    if config.start_tap:
        print("[*] Starting TAP...")
        custom_shell("/etc/init.d/tap start", dry_run=config.dry_run)


def uninstall_tap(config : Config):
    if not os.path.isfile("/etc/init.d/tap"):
        print("[!] TAP is not installed. Exiting.")
        sys.exit()
    custom_shell("update-rc.d tap remove", dry_run=config.dry_run)
    custom_shell("rm -rf /usr/share/tap", dry_run=config.dry_run)
    custom_shell("rm -rf /etc/init.d/tap", dry_run=config.dry_run)
    print("[*] Checking to see if tap is currently running...")
    kill_tap(dry_run=config.dry_run)
    print("[*] TAP has been uninstalled. Manually kill the process if it is still running.")

def main():
    config = parse_args()
    print(config)
    # run through a wizard to modify the config
    config.wizard()
    print(config)
    if config.update_programs:
        print("[*] Updating all programs...")
        custom_shell("apt-get update && apt-get --force-yes -y upgrade && apt-get --force-yes -y dist-upgrade", dry_run=config.dry_run)
    if config.install_programs:
        print("[*] Installing required programs...")
        custom_shell("apt-get --force-yes -y install git openssh-server net-tools htop dbus-x11", dry_run=config.dry_run)
        # check for proxychains-ng
        if not os.path.isfile("/usr/bin/proxychains4"):
            print("[*] Installing proxychains-ng...")
            custom_shell("git clone https://github.com/rofl0r/proxychains-ng proxy;cd proxy;./configure && make && make install;cd ..;rm -rf proxy", dry_run=config.dry_run)
    if config.install:
        print("[*] Installing TAP...")
        kill_tap(dry_run=config.dry_run)
        install_tap(config)
    elif config.uninstall:
        print("[*] Uninstalling TAP...")
        uninstall_tap(config)
    
if __name__ == "__main__":
    main()

def old_main():
    # if os.path.isfile("/etc/init.d/tap"):
    #     answer = input("TAP detected. Do you want to uninstall [y/n:] ")
    #     if answer.lower() == "yes" or answer.lower() == "y":
    #         answer = "uninstall"

    # if not os.path.isfile("/etc/init.d/tap"):
    #     answer = input("Do you want to start the installation of TAP: [y/n]: ")

    # if they said yes
    if answer.lower() == "y" or answer.lower() == "yes":
            print("[*] Checking to see if TAP is currently running...")

            # kill running processes
            kill_tap()

            print("[*] Beginning installation. This should only take a moment.")
            # if directories aren't there then create them
            if not os.path.isdir("/usr/share/tap"):
                    os.makedirs("/usr/share/tap")


            # install to rc.local
            print("[*] Adding TAP into startup through init scripts..")
            if os.path.isdir("/etc/init.d"):
                # remove old startup
                if os.path.isfile("/etc/init.d/tap"): os.remove("/etc/init.d/tap")

                # startup script here
                fileopen = open("src/core/startup_tap", "r")
                config = fileopen.read()
                filewrite = open("/etc/init.d/tap", "w")
                filewrite.write(config)
                filewrite.close()
                print("[*] Triggering update-rc.d on TAP to automatic start...")
                subprocess.Popen("chmod +x /etc/init.d/tap", shell=True).wait()
                subprocess.Popen("update-rc.d tap defaults", shell=True).wait()

            # setting background
            print("[*] Setting background..")
            set_background()
                    
            # install git and update everything
            install_updates = True
            update_check = input("Would you like to verify installed programs and update everything before progressing? [y/n]: ")
            if update_check[0].lower() == 'n':
                install_updates = False
            if install_updates:
                print("[*] Updating everything beforehand...")
                subprocess.Popen("apt-get update && apt-get --force-yes -y upgrade && apt-get --force-yes -y dist-upgrade", shell=True).wait()
                subprocess.Popen("apt-get --force-yes -y install git openssh-server net-tools", shell=True).wait()
            choice = input("Do you want to keep TAP updated? (requires internet) [y/n]: ")
            if choice == "y" or choice == "yes":
                print("[*] Checking out latest TAP to /usr/share/tap")
                # if old files are there
                if os.path.isdir("/usr/share/tap/"):
                        shutil.rmtree('/usr/share/tap')
                if not os.path.isdir("/usr/share/tap"):
                    os.makedirs("/usr/share/tap")
                subprocess.Popen("git clone https://github.com/trustedsec/tap.git /usr/share/tap/", shell=True).wait()
                print("[*] Finished. If you want to update tap go to /usr/share/tap and type 'git pull'")
                AUTO_UPDATE="ON"
            else:
                print("[*] Copying setup files over...")
                AUTO_UPDATE="OFF"
                if os.path.isdir("/usr/share/tap/"):
                    shutil.rmtree('/usr/share/tap')
                if not os.path.isdir("/usr/share/tap"):
                    os.makedirs("/usr/share/tap")
                subprocess.Popen("cp -rf * /usr/share/tap/", shell=True).wait()


            print("[*] Next we need to configure the remote SSH server you will want to tunnel over.")
            print("[*] This is the main remote SSH server you have running on the Internet that TAP will call back to.")
            print("\nWe need to figure out which method you want to use. The first method will use SSH keys\nfor authentication (preferred). This will generate a pub/priv key pair on your machine\nand automatically upload the key to the remote server. When that happens, a password\nwill not be needed then. The second method will use an actual password for authentication\non the remote server. The password is encrypted with AES but not in a secure format (decryption keys are stored locally, need to be).\n\n")
            choice1 = input("Choice 1: Use SSH keys, Choice 2: Use password (1,2)[1]: ")
            password = ""
            if choice1 == "1" or choice1 == "":
                choice1 = "ssh_keys"
            else:
                choice1 = "password"

            # generate ssh_key gen from setcore
            if choice1 == "ssh_keys":
                keys_q = input("Choice 1: Use existing SSH keys, Choice 2: Create new SSH keys(1,2)[2]: ")
                if keys_q == "1":
                    print("[*] We will first remove any old ones.")
                    if not os.path.isdir("/root/.ssh"):
                        os.mkdir("/root/.ssh", 700)
                    os.chmod("/root/.ssh", stat.S_IRWXU )
                    # remove old
                    if os.path.isfile("/root/.ssh/id_rsa.pub"):
                        print("[*] Removing old SSH keys...")
                        os.remove("/root/.ssh/id_rsa.pub")
                        os.remove("/root/.ssh/id_rsa")
                    print("[*] Copy and Paste the SSH Private Key.\n> "),
                    with open("/root/.ssh/id_rsa", "w") as fd:
                        while True:
                            tmp_input = input("")
                            fd.write( tmp_input + '\n' )
                            if re.match( '-----END .* PRIVATE KEY-----', tmp_input.strip() ): break
                    os.chmod("/root/.ssh/id_rsa", stat.S_IRUSR|stat.S_IWUSR )
                    print("[*] Copy and Paste the SSH Public Key followed by a blank line.\n> "),
                    with open("/root/.ssh/id_rsa.pub", "w") as fd:
                        while True:
                            tmp_input = input("")
                            if tmp_input.strip() == '': break
                            fd.write( tmp_input + '\n' )
                    os.chmod("/root/.ssh/id_rsa.pub", stat.S_IRUSR|stat.S_IWUSR )
                else:
                    print("[*] SSH Key generation was selected, we will begin the process now.")
                    #password = getpass.getpass("Enter the passphrase for your new SSH key: ")
                    password = ""
                    ssh_keygen(password)

            # if we are just using straight passwords
            if choice1 == "password":
                print("[*] This will ask for a username on the REMOTE system (root not recommended)")
                print("The username and password being requested would be the username and password needed to log into the REMOTE system that you have exposed on the Internet for the reverse SSH connection. For example, the TAP box needs to connect OUTBOUND to a box on the Internet - this would be the username and password for that system. ROOT access is NOT needed. This is a simple SSH tunnel. Recommend restricted account in case this box gets taken and has creds on it. Better preference is to use SSH keys.")
                username = input("Enter username for ssh [root]: ")
                if username == "": 
                    username = "root"
                else:                                    
                    password = getpass.getpass("Enter password for %s: " % (username))
        
            if password != "":
                print("[*] Encrypting the password now..")
                password = encryptAES(password) 
                store = password.split("::::")
                password = store[0]
                key = store[1]

                # if the key directory isnt created, do it real quick
                if not os.path.isdir("/root/.tap"):
                    os.makedirs("/root/.tap")
                filewrite = open("/root/.tap/store", "w")
                filewrite.write(key)
                filewrite.close()

            print("[!] Warning when specifying hostname - this implies that the remote TAP device will have DNS - otherwise this will fail.")
            host = input("Enter the remote IP or hostname for SSH connect (remote external server): ")
            port = input("Enter the PORT to the reverse SSH connect (remote external SSH port)[22]: ")
            if port == "": port = "22"
            print("[*] This next option will be the LOCAL port on the EXTERNAL box you will need to SSH into when TAP calls back. For example, when the SSH connection is sent from the TAP device to the box on the Internet, a local port is created on the remote box, so if you wanted to get into the tap, you would first SSH into the remote box, then ssh username@localhost -p <port you specify below>.")
            localport = input("Enter the LOCAL port that will be on the remote SSH box [10003]: ")
            socks = input("Enter the LOCAL port that will be used for the SOCKS HTTP proxy [10004]: ")
            if localport == "": localport = "10003"
            if socks == "": socks = "10004"
            if AUTO_UPDATE == "ON":
                print("[*] The update server is a path to pull NEW versions of the TAP device. Using git isn't recommended if you customize your builds for your TAP devices. By default this will pull from git pull https://github.com/trustedsec/tap - recommended you change this.")
                print("[*] For this field - you want to put every command you would run if you aren't using git, for example - wget https://yourcompany.com/tap.tar.gz;tar -zxvf tap.tar.gz")
                updates = input("Enter the commands for your update server [trustedsec (default)]: ")
                if updates == "": updates = "git pull"
            else:
                updates = ""
                print("""The next option allows you to specify a URL to execute commands.\nThis is used if you mess up and don't have reverse SSH access. Place a file in this location and TAP will execute the commands.""")
                commands = input("Enter URL to text file of commands (ex. https://yourwebsite.com/commands.txt): ")
                if commands == "": print("[!] No update server detected, will leave this blank.")
                print("[*] Creating the config file.")

                # determine if SSH keys are in use 
                if choice1 == "ssh_keys":
                    ssh_keys = "ON"
                    installed = input("[*] Has the SSH Public Key already been installed on the remote server (y/N) [N]?")
                    if installed.lower() == 'y':
                        username = input("Enter the username for the REMOTE account to log into the EXTERNAL server: ")
                        if username == "": username = "root"
                        child = pexpect.spawn("ssh %s@%s -p %s" % (username,host,port))
                        i = child.expect(['The authenticity of host', 'password', 'Connection refused', 'Permission denied, please try again.', 'Last login:'])
                        if i < 4:
                            print("[*] Error: Could not connect to remote server. Either the SSH Key is incorrectly configured or no SSH Key has been configured")
                            sys.exit()
                        if i == 4:
                            print("[*] Successfully logged into the system, good to go from here!")
                    else:
                        print("[*] We need to upload the public key to the remote server, enter the password for the remote server (once) to upload when prompted.")
                        # clearing known hosts
                        if os.path.isfile("/root/.ssh/known_hosts"):
                            print("[!] Removing old known_hosts files..")                    
                            os.remove("/root/.ssh/known_hosts")

                        # pull public key into memory

                        fileopen = open("/root/.ssh/id_rsa.pub", "r")
                        pub = fileopen.read()
                        # spawn pexpect to add key
                        print("[*] Spawning SSH connection and modifying authorized hosts.")
                        print("[*] Below will ask for a username and password, this is for the REMOTE server exposed on the Internet. This is a one time thing where the TAP device will upload and add the SSH keys to the remote system in order to handle SSH authentication. This is the PW for your external server on the Internet.")
                        username = input("Enter the username for the REMOTE account to log into the EXTERNAL server: ")
                        if username == "": username = "root"
                        child = pexpect.spawn("ssh %s@%s -p %s" % (username,host,port))
                        password_onetime = getpass.getpass("Enter your password for the remote SSH server: ")
                        i = child.expect(['The authenticity of host', 'password', 'Connection refused'])
                        if i == 0:
                            child.sendline("yes")
                            child.expect("password")
                            child.sendline(password_onetime)

                        if i == 1:
                            child.sendline(password_onetime)

                        if i ==2:
                            print ("Cannot connect to server - connection refused. Please check the port and try again.")
                            sys.exit()

                        # here we need to verify that we actually log in with the right password
                        i = child.expect(['Permission denied, please try again.', 'Last login:'])
                        if i == 0:
                            print("[!] ERROR!!!! You typed in the wrong password.")
                            password_onetime = getpass.getpass("Lets try this again. Enter your SSH password: ")
                            child.sendline(password_onetime)
                            # second time fat fingering, no dice bro
                            i = child.expect(['Permission denied, please try again.'])
                            if i == 0:
                                print("[!] Sorry boss, still denied. Figure out the password and run setup again.")
                                print("[!] Exiting TAP setup...")
                                # exit TAP here
                                sys.exit()
                            # successfully logged in
                            else:
                                print("[*] Successfully logged into the system, good to go from here!")

                        if i == 1:
                            print("[*] Successfully logged into the system, good to go from here!")

                        # next we grab the hostname so we can enter it in the authorized keys for a description
                        fileopen = open("/etc/hostname", "r")
                        hostname = fileopen.read()
                        # add a space
                        child.sendline("echo '' >> ~/.ssh/authorized_keys")
                        # comment code for authorized list
                        child.sendline("echo '# TAP box for hostname: %s' >> ~/.ssh/authorized_keys" % (hostname))
                        # actual ssh key
                        child.sendline("echo '%s' >> ~/.ssh/authorized_keys" % (pub))
                        print("[*] Key for %s added to the external box: %s" % (hostname, host))
                    
                else:
                    ssh_keys ="OFF"

                # do you want to log everything
                print("TAP has the ability to log every command used via SSH. This is useful for clients who want log files of the pentest. All logs are saved in /var/log/messages")
                log_everything = input("Do you want to log everything? yes or no [yes] ")
                if log_everything == "": log_everything = "yes"
                log_everything = log_everything.upper()

                # write out the config file
                filewrite = open("/usr/share/tap/config", "w")
                filewrite.write("# tap config options\n\n")
                filewrite.write("# The username for the ssh connection\nUSERNAME=%s\n# The password for the reverse ssh connection\nPASSWORD=%s\n# The reverse ssh ipaddr or hostname\nIPADDR=%s\n# The port for the reverse connect\nPORT=%s\n" % (username, password,host,port))
                filewrite.write("# SSH check is in seconds\nSSH_CHECK_INTERVAL=60\n")
                filewrite.write("# The local SSH port on the reverse SSH host\nLOCAL_PORT=%s\n" % (localport))
                filewrite.write("# Where to pull updates from\nUPDATE_SERVER=%s\n" % (updates))
                filewrite.write("# URL for command updates - ENSURE THAT THE FIRST LINE OF TEXT FILE HAS: 'EXECUTE COMMANDS' or it will not execute anything!\nCOMMAND_UPDATES=%s\n" % (commands))
                filewrite.write("# SPECIFY IF TAP WILL AUTOMATICALLY UPDATE OR NOT\nAUTO_UPDATE=%s\n" % (AUTO_UPDATE))
                filewrite.write("# SPECIFY IF SSH KEYS ARE IN USE OR NOT\nSSH_KEYS=%s\n" % (ssh_keys))
                filewrite.write("# LOG EVERY COMMAND VIA SSH? YES OR NO - ALL LOGS GO TO /var/log/messages\nLOG_EVERYTHING=%s\n" % (log_everything))
                filewrite.write("# THIS IS USED TO TUNNEL SOCKS HTTP TRAFFIC FOR LINUX UPDATES\nSOCKS_PROXY_PORT=%s\n" % (socks))
                filewrite.close()

                # set the background
                # background()
            
                # update motd
                client = input("What client are you deploying this to: ")
                motd(client)

                # configuring permissions
                subprocess.Popen("chmod +x /usr/share/tap/tap.py;chmod +x /usr/share/tap/src/core/heartbeat.py", shell=True).wait()

                # ensure proxychains is installed
                print("[*] Installing proxychains-ng for SOCKS5 proxy support.")
                subprocess.Popen("git clone https://github.com/rofl0r/proxychains-ng proxy;cd proxy;./configure && make && make install;cd ..;rm -rf proxy", shell=True).wait()

                # enable root login
                print("[*] Enabling SSH-Server and allow remote root login.. Please ensure and test this ahead of time.")
                data = open("/etc/ssh/sshd_config", "r").read()
                filewrite = open("/etc/ssh/sshd_config", "w")
                data = data.replace("PermitRootLogin without-password", "PermitRootLogin yes")
                filewrite.write(data)
                filewrite.close()
                print("[*] Restarting the SSH service after changes.")
                subprocess.Popen("service ssh restart", shell=True).wait()
                print("[*] Installation complete. Edit /usr/share/tap/config in order to config tap to your liking..")
                    
                # start TAP, yes or no?
                choice = input("Would you like to start TAP now? [y/n]: ")
                if choice == "yes" or choice == "y":
                    subprocess.Popen("/etc/init.d/tap start", shell=True).wait()

                # prompt for ptf install
                print("[*] PTF Install: ")
                ptf = input("[-] Do you want to install PTF and all modules now? [yes][no]: ")
                if ptf == "yes" or ptf == "y":
                    print("[*] Pulling the PenTesters Framework and installing all modules (use modules/install_update_all")
                    if not os.path.isdir("/pentest/"): os.makedirs("/pentest")
                    if not os.path.isdir("/pentest/ptf"):
                        subprocess.Popen("git clone https://github.com/trustedsec/ptf.git /pentest/ptf", shell=True).wait()
                    print("[*] Installing PTF modules/install_update_all...")
                    os.chdir("/pentest/ptf")
                    child = pexpect.spawn("python ptf")
                    child.expect("ptf")
                    child.sendline("use modules/install_update_all")
                    child.interact()
                else:
                    print("[*] Clone the PTF repo at: https://github.com/trustedsec/ptf.git later to install your tools")

    # uninstall tap
    if answer == "uninstall":
        os.remove("/etc/init.d/tap")
        subprocess.Popen("rm -rf /usr/share/tap", shell=True)
        subprocess.Popen("rm -rf /etc/init.d/tap", shell=True)
        print("[*] Checking to see if tap is currently running...")
        kill_tap()
        print("[*] TAP has been uninstalled. Manually kill the process if it is still running.")
