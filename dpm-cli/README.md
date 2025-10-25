# Drustan Password Manager

The password manager that does not store your passwords.

## Installation and first run

### Debian

    $ su // or sudo su
    # git clone https://github.com/Marcel-Brouette/dpm.git /opt/dpm/ 
    # ln -s /opt/dpm/dpm-cli/dpm.py /usr/local/bin/dpm
    # chown root:root /usr/local/bin/dpm /opt/dpm/dpm-cli/dpm.py
    # chmod 555 /usr/local/bin/dpm /opt/dpm/dpm-cli/dpm.py

    # apt update
    # apt install python3 python3-pip xclip bash-completion python3-pyperclip python3-argcomplete python3-args python3-keyutils
    # activate-global-python-argcomplete

    // bash_completion must be run by your user's .bashrc
    // run a new terminal in order to enable the python completion

    $ dpm

### Enable completion on zsh

    // in .zsh file : 
    autoload bashcompinit
    bashcompinit
    eval "$(register-python-argcomplete /usr/local/bin/dpm)"


## Usage

    ##############################################
    ########## Drustan Password Manager ##########

    usage: ./dpm.py <command> [<sub_command>] [[options] [value]]

    commands :

        $ help

        $ renew APP_NAME

        $ detail APP_NAME

        $ list

        $ gen [-p] APP_NAME

        $ add {master_key,app}

            app [-l LENGTH] [-s STRENGTH_LEVEL] [-k MASTER_KEY]
            master_key MASTER_KEY

        $ del {master_key,app}

            app APP_NAME
            master_key MASTER_KEY

        $ update {master_key,app}

            app [-l LENGTH] [-n NOTE] [-s STRENGTH_LEVEL] APP_NAME
            master_key MASTER_KEY



