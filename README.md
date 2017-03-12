# Drustan Password Manager

The password manager that does not store your passwords.

## Installation and first run

### Debian

    $ su // or sudo su
    # git clone https://github.com/Marcel-Brouette/dpm.git 
    # mv dpm/dpm.py /usr/local/bin/dpm
    # chown root:root /usr/local/bin/dpm
    # chmod 555 /usr/local/bin/dpm
    # rm -r dpm/

    # apt update
    # apt install python python-pip xclip bash-completion python-pyperclip python-argcomplete python-args
    # activate-global-python-argcomplete

    // bash_completion must be run by your user's .bashrc
    // run a new terminal in order to enable the python completion

    $ dpm

## Usage

    ##############################################
    ########## Drustan Password Manager ##########

    usage: ./dpm.py {help,get,master_key,app} [<sub_command>] [[options] [value]]

    commands :

        $ help

        $ get [-p] APP_NAME 

        $ app {list,add,update,delete,renew,detail}

            renew APP_NAME
            detail APP_NAME
            delete APP_NAME
            list
            add [-l LENGTH] [-k KEY] [-n NOTE] [-s STRENGTH_LEVEL]
            update [-l LENGTH] [-k KEY] [-n NOTE] [-s STRENGTH_LEVEL]

        $ master_key {list,add,update,delete}

            add MASTER_KEY
            list
            update [-k KEY] [-n NEW_NAME] MASTER_KEY
            delete MASTER_KEY
