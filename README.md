# Drustan Password Manager

The password manager that does not store your passwords.

## Installation and first run

### Debian

    // command with the prompt '#' must be run as root
    $ git clone https://github.com/Marcel-Brouette/dpm.git 
    # mv dpm/dpm.py /usr/local/bin/dpm
    # chown root:root /usr/local/bin/dpm
    # chmod 555 /usr/local/bin/dpm
    $ rm -r dpm/

    # apt update
    # apt install python python-pip xclip bash-completion python-pyperclip python-argcomplete python-args
    # activate-global-python-argcomplete
    // bash_completion must be run by your .bashrc
    // logout and login in order to enable the python completion

    $ dpm

