# Drustan Password Manager

The password manager that does not store your passwords.

## Installation and first run

### Debian

    git clone https://github.com/Marcel-Brouette/dpm.git 
    mv dpm/dpm.py /usr/local/bin/dpm
    rm -r dpm/
    
    apt-get install python python-pip xclip bash-completion python-pyperclip python-argcomplete python-args
    activate-global-python-argcomplete
 
    dpm

## Usage

    ##############################################
    ########## Drustan Password Manager ##########

    usage: ./dpm.py {help,get,master_key,app} [<sub_command>] [[options] [value]]

    commands :

        $ help

        $ get [-p] app_name

        $ app {list,add,update,delete,renew,detail}

            renew app_name
            detail app_name
            delete app_name
            list
            add [-l LENGTH] [-k KEY] [-n NOTE] [-s STRENGTH_LEVEL]
            update [-l LENGTH] [-k KEY] [-n NOTE] [-s STRENGTH_LEVEL]

        $ master_key {list,add,update,delete}

            add master_key
            list
            update [-k KEY] [-n NEW_NAME] master_key
        delete master_key
