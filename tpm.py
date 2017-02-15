#!/usr/bin/python
# PYTHON_ARGCOMPLETE_OK

import argparse
import argcomplete
import os
from os.path import expanduser
from hashlib import sha224
from hashlib import sha512
from base64 import b64encode
from getpass import getpass
from sys import stderr, exit
from subprocess import Popen, PIPE
from pbkdf2 import crypt
import pyperclip
import platform
import re
import json

working_directory  = expanduser("~") + "/.tpx_pass_manager/"
services_file_name = 'services.json'
global_data        = None
description        = '########## TPX Pass Manager ##########'
regex_servicename  = r'^([a-zA-Z\-\_\.0-9])+$'

MIN_SIZE_STRONG_PWD = 12
DEFAULT_PWD_SIZE    = 12
MIN_PWD_SIZE        = 4

#### JSON LABELS

MASTER_CHECK   = "master_check"
SHARED_CHECK   = "shared_check"
SERVICES_LIST  = "services"

PWD_SIZE     = "pwd_size"
VERSION      = "version"
DESC         = "desc"
SHARED       = "shared"
CNIL         = "cnil"

######################################################
################# UTIL FUNCTIONS
######################################################


def load_config():
    global global_data
    if global_data == None:
        is_first_use = False
        full_path_file = working_directory + services_file_name
        if not os.path.exists(working_directory): os.makedirs(working_directory)
        with open(full_path_file, 'a+') as data_file:
            data_file.seek(0,2) # 'a+' don't put the reference point in the end of file ...
            if data_file.tell() == 0:
                global_data = first_use()
            else:
                data_file.seek(0)
                global_data = config_is_valid(data_file)
        save_file()
    return global_data


def services():
    return load_config()[SERVICES_LIST]


def master_pwd_check():
    return load_config()[MASTER_CHECK]


def shared_pwd_check():
    return load_config()[SHARED_CHECK]


def autocomplete_services(prefix, parsed_args, **kwargs):
    return [service for service in services().keys() if prefix in service and service != '']


def save_file():
    with open(working_directory + services_file_name, 'w') as outfile:
        json.dump(load_config(), outfile, indent=4)


def fatal_error(msg):
    stderr.write(msg)
    exit(1)


def config_is_valid(data_file):
    data = {}
    try:
        data = json.load(data_file)
    except:
        fatal_error("[ERROR] The configuration file is not a valid JSON")
    if SERVICES_LIST not in data:
        data[SERVICES_LIST] = {}
    if SHARED_CHECK  not in data:
        data[SHARED_CHECK] = None
    if MASTER_CHECK  not in data:
        print("Your master password fingerprint seem to be missing")
        data[MASTER_CHECK] = fingerprint(ask_strong_pass("[ASK] Initialize your Master password: "))
    return data


def ask_strong_pass(msg):
    asked_pass = ''
    pwd_is_weak = True
    while pwd_is_weak:
        asked_pass   = getpass(msg) 
        pwd_is_weak  = len(asked_pass) < MIN_SIZE_STRONG_PWD
        pwd_is_weak |= pwd_is_basic_charset(asked_pass)        
        if pwd_is_weak: 
            print("[ERROR] Your password is TOO WEAK (size under " + str(MIN_SIZE_STRONG_PWD) + " chars or basic charset only)")
    return asked_pass


def pwd_is_basic_charset(pwd):
    for letter in pwd: 
        is_simple  = False
        is_simple |= (ord(letter) > 100 and ord(letter) < 133)
        is_simple |= (ord(letter) > 140 and ord(letter) < 173)
        if not is_simple: return False
    return True


def fingerprint(pwd):
    return int(sha224(pwd).hexdigest()[:4], 16)


def ask_passwd(fp, msg):
    global_passwd = getpass(msg)
    if fingerprint(global_passwd) != fp:
        fatal_error("[ERROR] Master or Shared password error\n")
    return global_passwd


def hash(service_name):
    pwd_size       = DEFAULT_PWD_SIZE
    version        = 0
    shared         = False
    service_exist  = service_name in services().keys()
    msg            = "[ASK] Master password: "
    fp             = master_pwd_check()
    cnil           = False
    if service_exist:
        version  = services()[service_name][VERSION]
        shared   = services()[service_name].get(SHARED, False)
        pwd_size = services()[service_name][PWD_SIZE]
        cnil     = services()[service_name][CNIL]
    if shared:
        msg = "[ASK] Shared password: "
        fp  = shared_pwd_check()
        if fp is None:
            print "[WARNING] You try to access a shared service password but you have no master shared password registred"
            asked_pass = getpass("[ASK] Initialize your Shared password: ")
            load_config()[SHARED_CHECK] = fingerprint(asked_pass)
            fp = fingerprint(asked_pass)
            save_file()
    globalPassword = ask_passwd(fp, msg)
    version_string = ' _' * version
    if cnil:
        service_hash = crypt(sha512(globalPassword + " " + service_name + version_string).digest())[:pwd_size]
    else:
        service_hash = b64encode(sha512(globalPassword + " " + service_name + version_string).digest())[:pwd_size]
    return service_hash


def give_passwd(service_name, clear_pwd, **options):
    if options.get("print", False):
        print("[SUCCESS] Password: %s (%s)" % (clear_pwd, service_name))
    elif options.get("clipboard", True):
        if platform.system() == "Linux":# store the pass in primary clipboard
            try:
                p = Popen(['xclip', '-selection', 'p'], stdin=PIPE, close_fds=True)
                p.communicate(input=clear_pwd.encode('utf-8'))
            except: 
                fatal_error("[ERROR] Install package xclip or use '-p' option to display the pass")
        else:
            pyperclip.copy(clear_pwd)
        print("[SUCCESS] Password copied in your clipboard (%s)" % (service_name))

######################################################
################# MAIN FUNCTIONS 
######################################################

def first_use():
    print("It seems that you launch TPX Pass Manager for the first time !")
    print("We need some of your inputs in order to use TPX Pass Manager properly:")
    print("")
    ask_global_pass = ask_strong_pass("- Your master password (it won't be stored): ")
    ask_shared_pass = getpass("- A shared password (you can leave it blank): ")
    
    return {
        MASTER_CHECK: fingerprint(ask_global_pass), 
        SHARED_CHECK: fingerprint(ask_shared_pass) if ask_shared_pass != '' else None,
        SERVICES_LIST: {}   
    }


def passwd(service_name, **options):
    service_hash = hash(service_name)
    give_passwd(service_name, service_hash, **options)


def delete_service(service_name):
    service_exist = service_name in services().keys()
    if not service_exist:
        fatal_error("[ERROR] service not found\n")
    else:
        del services()[service_name]
        save_file()
        print("[DELETED] service '%s' correctly deleted" % service_name)


def add_service(service_name, **kwargs):
    if service_name in services().keys():
        print("[ERROR] service '%s' already exist" % service_name)
    else:
        services()[service_name] = {
            PWD_SIZE: kwargs.get(PWD_SIZE, DEFAULT_PWD_SIZE),
            VERSION: kwargs.get(VERSION, 0),
            DESC: kwargs.get(DESC, ""),
            SHARED: kwargs.get(SHARED, False),
            CNIL: kwargs.get(CNIL, False)
        }
        save_file()
        print("[ADDED] service '%s' correctly added." % service_name)
        print_desc(service_name)


def renew_pwd(service_name):
    if service_name not in services().keys():
        fatal_error("[ERROR] can't renew a service that doesn't exist.")
    else:
        services()[service_name][VERSION] = services()[service_name].get(VERSION, 0) + 1
        save_file()
        print("[RENEWED] '%s' password correctly renewed" % service_name)


def set_desc(service_name, desc):
    if service_name not in services().keys():
        fatal_error("[ERROR] can't set a description on a service that doesn't exist.")
    else:
        services()[service_name][DESC] = desc
        save_file()
        print("[SAVED] '%s' description saved" % service_name)
        print_desc(service_name)


def set_cnil(service_name):
    if service_name not in services().keys():
        fatal_error("[ERROR] can't change cnil status on a service that doesn't exist.")
    else:
        if services()[service_name].get(CNIL):
            services()[service_name][CNIL] = False
        else:
            if services()[service_name][PWD_SIZE] < 12 :
                fatal_error("[ERROR] Change the password lenght up to 12 before moving to CNIL (currently %s)" % services()[service_name][PWD_SIZE])
            else:
                services()[service_name][CNIL] = True
        save_file()
        print("[SAVED] '%s' cnil status saved" % service_name)
        print_desc(service_name)


def set_shared(service_name):
    if service_name not in services().keys():
        fatal_error("[ERROR] can't change shared status on a service that doesn't exist.")
    else:
        if services()[service_name].get(SHARED):
            services()[service_name][SHARED] = False
        else:
            services()[service_name][SHARED] = True
        save_file()
        print("[SAVED] '%s' shared status saved" % service_name)
        print_desc(service_name)


def set_lenght(service_name, lenght):
    if service_name not in services().keys():
        fatal_error("[ERROR] can't change password lenght on a service that doesn't exist.")
    else:
        services()[service_name][PWD_SIZE] = lenght
        save_file()
        print("[SAVED] '%s' password lenght saved" % service_name)
        print_desc(service_name)


def print_desc(service_name):
    if service_name not in services().keys():
        fatal_error("[ERROR] can't print description on a service that doesn't exist.")
    else:
        desc = services()[service_name].get(DESC, "")
        cnil = services()[service_name].get(CNIL, "")
        version = services()[service_name].get(VERSION, "")
        pwd_size = services()[service_name].get(PWD_SIZE, "")
        shared = services()[service_name].get(SHARED, "")
        if desc is not None and len(desc.strip()) > 0:
            print("[DESCRIPTION] %s" % desc)
        else:
            print("[DESCRIPTION] None")
        print("[CNIL] %r" % cnil)
        print("[VERSION] %s" % version)
        print("[PWD_SIZE] %s" % pwd_size)
        print("[SHARED] %s" % shared)

######################################################
################# MAIN ROUTINE 
######################################################

def get_params():
    parser_arg = argparse.ArgumentParser(description=description)
    parser_arg.add_argument('service_name', help='the service you want to get the pass').completer = autocomplete_services
    parser_arg.add_argument('-p', '--view', action='store_true', help='print the password instead of using clipboard')
    parser_arg.add_argument('-a', '--add', action='store_true', help='add the service into the service list')
    parser_arg.add_argument('-c', '--cnil', action='store_true', help='[can be used directly with --add] hardener the password output meeting cnil standard')
    parser_arg.add_argument('-s', '--shared', action='store_true', help='[can be used directly with --add] the service will use the shared key')
    parser_arg.add_argument('-l', '--lenght', type=int, help='[can be used directly with --add] set the password lenght of a service')
    parser_arg.add_argument('-i', '--infos', default=argparse.SUPPRESS, nargs='?', help='[can be used directly with --add] set the service description')
    parser_arg.add_argument('-d', '--delete', action='store_true', help='delete the service from the service list')
    parser_arg.add_argument('-r', '--renew', action='store_true', help='renew the pass of the service')
    parser_arg.add_argument('-m', '--desc', action='store_true', help='show the description of the service')

    argcomplete.autocomplete(parser_arg, False)
    return parser_arg.parse_args()

def run(args):
    if re.match(regex_servicename, args.service_name) == None:
        fatal_error("[ERROR] The service name must contains only the following charset [a-Z, 0-9, '-', '_', '.']\n")

    load_config()

    if 'infos' in args and not args.add: set_desc(args.service_name, args.infos)
    elif args.cnil and not args.add: set_cnil(args.service_name)
    elif args.shared and not args.add: set_shared(args.service_name)
    elif args.lenght and not args.add: set_lenght(args.service_name, args.lenght)
    elif args.desc: print_desc(args.service_name)
    elif args.delete: delete_service(args.service_name)
    elif args.renew: renew_pwd(args.service_name)
    elif args.add:
        if args.cnil and args.lenght < 12:
            args.lenght = 12
        elif args.lenght == None:
            args.lenght = DEFAULT_PWD_SIZE
        initial_config = {
            PWD_SIZE: args.lenght,
            DESC    : args.infos if 'infos' in args else "",
            SHARED  : args.shared,
            CNIL    : True if args.cnil else False
        }
        add_service(args.service_name, **initial_config)
    else:
        options = {
            "print": args.view,
            "clipboard": True
        }
        passwd(args.service_name, **options)

args = get_params()
run(args)