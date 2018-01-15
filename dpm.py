#!/usr/bin/python2.7
# PYTHON_ARGCOMPLETE_OK

import argparse
import argcomplete
import os
from os.path import expanduser
from hashlib import sha224
from hashlib import sha512
from md5 import md5
from base64 import b64encode
from getpass import getpass
from sys import stderr
from sys import exit
from sys import argv
from subprocess import Popen
from subprocess import PIPE
import pyperclip 
import platform
import re
import json
import platform


working_directory    = expanduser("~") + "/.dpm/"
services_file_name   = 'db.json'

description          = '########## Drustan Password Manager ##########'
regex_servicename    = r'^([a-zA-Z\-\_\.0-9\/])+$'
allowed_strength_lvl = [1, 2, 3]

global_data          = None
args_parser          = None

MIN_SIZE_STRONG_PWD  = 16
DEFAULT_PWD_SIZE     = 23
DEFAULT_STRENGTH_LVL = 2

#### JSON LABELS

MASTERS_LIST   = "master_keys"
MASTER_CHECK   = "default_master"
SERVICES_LIST  = "services"

PWD_SIZE     = "pwd_size"
VERSION      = "version"
NOTE         = "note"
MASTER_KEY   = "master_key"
PWD_STRENGTH = "pwd_strength"

##########################################################
################## ARGUMENTS SETTINGS ####################
##########################################################

def load_arguments():
    global args_parser

    args_parser = argparse.ArgumentParser(add_help=False)
    main_sub_cmds = args_parser.add_subparsers(dest='command', title="command")
    #args_parser.add_argument('service_name', help='the service you want to get the pass').completer = autocomplete_services

    ###############  SUB_COMMANDS 1 ################

    help_cmd   = main_sub_cmds.add_parser("help", description="", add_help=False)
    gen_cmd    = main_sub_cmds.add_parser("gen", description="", add_help=False)
    add_cmd    = main_sub_cmds.add_parser("add", description="", add_help=False)
    del_cmd    = main_sub_cmds.add_parser("del", description="", add_help=False)
    list_cmd   = main_sub_cmds.add_parser("list", description="", add_help=False)
    renew_cmd  = main_sub_cmds.add_parser("renew", description="", add_help=False)
    update_cmd = main_sub_cmds.add_parser("update", description="", add_help=False)
    detail_cmd = main_sub_cmds.add_parser("detail", description="", add_help=False)
    export_cmd = main_sub_cmds.add_parser("export", description="", add_help=False)

    add_sub_cmds  = add_cmd.add_subparsers(dest='sub_command')
    del_sub_cmds  = del_cmd.add_subparsers(dest='sub_command')
    upd_sub_cmds  = update_cmd.add_subparsers(dest='sub_command')

    ###############  SUB_COMMANDS 2 ################

    add_mkey_cmd  = add_sub_cmds.add_parser('master_key', description='', add_help=False)
    del_mkey_cmd  = del_sub_cmds.add_parser('master_key', description='', add_help=False) 
    upd_mkey_cmd  = upd_sub_cmds.add_parser('master_key', description='', add_help=False)
    upd_app_cmd   = upd_sub_cmds.add_parser('app', description='', add_help=False)
    add_app_cmd   = add_sub_cmds.add_parser('app', description='', add_help=False)
    del_app_cmd   = del_sub_cmds.add_parser('app', description='', add_help=False)

    ##############  ARGS ##############

    gen_cmd.add_argument('APP_NAME').completer = autocomplete_services
    gen_cmd.add_argument('-p', '--print_pwd', action='store_true')

    add_mkey_cmd.add_argument('MASTER_KEY')
    del_mkey_cmd.add_argument('MASTER_KEY').completer = autocomplete_master_key
    upd_mkey_cmd.add_argument('MASTER_KEY').completer = autocomplete_master_key
    export_cmd.add_argument('MASTER_KEY', nargs='?').completer = autocomplete_master_key

    del_app_cmd.add_argument('APP_NAME').completer = autocomplete_services

    upd_app_cmd.add_argument('APP_NAME').completer = autocomplete_services
    upd_app_cmd.add_argument('-l', '--length', type=int, default=argparse.SUPPRESS)
    upd_app_cmd.add_argument('-n', '--note', default=argparse.SUPPRESS)
    upd_app_cmd.add_argument('-s', '--strength_level', type=int, default=argparse.SUPPRESS)

    add_app_cmd.add_argument('APP_NAME')
    add_app_cmd.add_argument('-l', '--length', type=int, default=argparse.SUPPRESS)
    add_app_cmd.add_argument('-s', '--strength_level', type=int, default=argparse.SUPPRESS)
    add_app_cmd.add_argument('-k', '--master_key', default=argparse.SUPPRESS).completer = autocomplete_master_key
    add_app_cmd.add_argument('-n', '--note', default=argparse.SUPPRESS)

    renew_cmd.add_argument('APP_NAME').completer = autocomplete_services
    detail_cmd.add_argument('APP_NAME').completer = autocomplete_services

    argcomplete.autocomplete(args_parser, False)
    

######################################################
################# UTIL FUNCTIONS 
######################################################


def fatal_error(msg):
    stderr.write(msg + "\n")
    exit(1)

def TODO() : 
    print("TODO")

##############  CUSTOM HELP ##############

def print_help():
    header        = "\n##############################################\n"
    header       += "########## Drustan Password Manager ##########\n\n"
    global_usage  = "usage: " + argv[0] + " <command> [<sub_command>] [[options] [value]]\n\n"
    detail        = "commands : \n\n"
    detail += view_cmd_help(commands_tree(args_parser), 1, '')
    custom_help = header + global_usage + detail
    print(custom_help)



def commands_tree(arg_parser) : 
    subparsers_actions = [
        action for action in arg_parser._actions if isinstance(action, argparse._SubParsersAction)
    ]
    max_usage_size   = 0
    choices = {}
    for subparsers_action in subparsers_actions:
        for choice, subparser in subparsers_action.choices.items():
            default_help   = subparser.format_help()
            results        = re.search(r'usage: [^\s\\]* (.*)', default_help)
            usage          = results.group(1)
            usage          = re.sub(r'\.', '', usage)
            max_usage_size = len(usage) if (len(usage) > max_usage_size) else max_usage_size
            child_choices  = commands_tree(subparser)
            choices.update({choice : (usage, subparser.description, child_choices)})

    tree = {'max_usage_size' : max_usage_size, 'list_cmd' : choices} if len(choices) != 0 else {}
    return tree

def view_cmd_help(cmd_tree, level, parent_cmd): 
    if cmd_tree == {} : 
        return ''

    cmd_line = ''
    max_usage_size = cmd_tree['max_usage_size']
    for cmd_name, choice in sorted(cmd_tree['list_cmd'].iteritems(),key = lambda e:len(e[1][2])):
        usage, description, cmd_sub_tree = choice
        if level != 1 : 
            usage      = usage.replace(parent_cmd + ' ', '')
            new_parent_cmd = parent_cmd + ' ' + cmd_name
            eol = "\n"
        else : 
            new_parent_cmd = cmd_name
            usage      = "$ " + usage
            eol = "\n\n"
        space_nb   = max_usage_size + 4 - len(usage)
        cmd_line += ' ' * (3 * level + level) +  usage + (' ' * space_nb) + description + eol
        cmd_line += view_cmd_help(cmd_sub_tree, level + 1, new_parent_cmd)

    return cmd_line + "\n"


##############  configuration functions  ##############

def load_config():
    global global_data
    if global_data == None :
        is_first_use = False 
        full_path_file = working_directory + services_file_name
        if not os.path.exists(working_directory): os.makedirs(working_directory)
        with open(full_path_file, 'a+') as data_file:    
            data_file.seek(0,2) # 'a+' don't put the reference point in the end of file ...
            if data_file.tell() == 0: 
                first_use()
            else : 
                data_file.seek(0)
                global_data = config_is_valid(data_file)
                save_file()
    return global_data 

def services():
    return load_config()[SERVICES_LIST]

def master_keys():
    return load_config()[MASTERS_LIST]

def default_master_check():
    return load_config()[MASTERS_LIST][MASTER_CHECK]

def master_key_fp(master_key_name):
    check_master_exist(master_key_name)
    return load_config()[MASTERS_LIST][master_key_name]

def check_master_exist(master_key_name): 
    if master_key_name not in master_keys().keys() :
        fatal_error("[ERROR] the fingerprint of '%s' master key doesn't exist" % master_key_name)

def autocomplete_services(prefix, parsed_args, **kwargs):
    return [service for service in services().keys() if prefix in service and service != '']

def autocomplete_master_key(prefix, parsed_args, **kwargs):
    return [key for key in master_keys().keys() if prefix in key and key != '']

def save_file():
    with open(working_directory + services_file_name, 'w') as outfile:
        json.dump(load_config(), outfile, indent=4)


def save_config_attr(service_name, key, value, attr_name):
    error_msg   = "[ERROR] can't set a %s on a service that doesn't exist." % attr_name 
    success_msg = "[SAVED] '%s' %s saved" % (service_name, attr_name)
    if service_name not in services().keys():
        fatal_error(error_msg)
    else:
        services()[service_name][key] = value
        save_file()
        print(success_msg)
        print_desc(service_name)


def config_is_valid(data_file):
    data = {}
    try: 
        data = json.load(data_file)
    except: 
        fatal_error("[ERROR] The configuration file is not a valid JSON")
    if MASTERS_LIST not in data : 
        print("[WARN] The configuration file is not valid, Your master password fingerprint seem to be missing")
        data[MASTERS_LIST] = {}
        data[MASTERS_LIST][MASTER_CHECK] = fingerprint(ask_strong_pass("[ASK] Initialize your Master password: "))
    elif MASTER_CHECK not in data[MASTERS_LIST] : 
        print("[WARN] The configuration file is not valid, Your master password fingerprint seem to be missing")
        data[MASTERS_LIST][MASTER_CHECK] = fingerprint(ask_strong_pass("[ASK] Initialize your Master password: "))
    if SERVICES_LIST not in data : 
        data[SERVICES_LIST] = {}
        
    return data


def ask_strong_pass(msg):
    asked_pass  = ''
    pwd_is_weak = True
    while pwd_is_weak :
        asked_pass   = getpass(msg) 
        pwd_is_weak  = len(asked_pass) < MIN_SIZE_STRONG_PWD
        pwd_is_weak |= pwd_is_basic_charset(asked_pass)        
        if pwd_is_weak : 
            print("[ERROR] Your password is TOO WEAK (size under " + str(MIN_SIZE_STRONG_PWD) + " chars or basic charset only)")
    return asked_pass


def pwd_is_basic_charset(pwd):
    for letter in pwd: 
        is_simple  = False
        is_simple |= (ord(letter) > 100 and ord(letter) < 133)    
        is_simple |= (ord(letter) > 140 and ord(letter) < 173)    
        if not is_simple : return False
    return True


def fingerprint(pwd) : 
    return int(sha224(pwd).hexdigest()[:4], 16) 


def ask_passwd(fp, msg):
    global_passwd = getpass(msg)
    if fingerprint(global_passwd) != fp: 
        fatal_error("[FAILED] Password error\n")
    return global_passwd


def hash(service_name) :
    pwd_size       = DEFAULT_PWD_SIZE
    version        = 0    
    service_exist  = service_name in services().keys()
    strength_lvl   = 2
    if service_exist:
        version         = services()[service_name][VERSION]
        master_key_name = services()[service_name].get(MASTER_KEY, MASTER_CHECK)
        pwd_size        = services()[service_name][PWD_SIZE]
        strength_lvl    = services()[service_name][PWD_STRENGTH]

    fp   = master_key_fp(master_key_name)
    msg  = "[ASK][%s] password: " % master_key_name

    globalPassword = ask_passwd(fp, msg) 
    version_string = ' _' * version 
    if strength_lvl == 1:
        version_string = ' *' * version
        service_hash = b64encode(md5(globalPassword + " " + service_name + version_string).digest())[:12]
    elif strength_lvl == 3:
        service_hash = b64encode(sha512(globalPassword + " " + service_name + version_string).digest())[:pwd_size]
    else:
        service_hash  = b64encode(sha512(globalPassword + " " + service_name + version_string).digest())[:pwd_size]
    return service_hash

def give_passwd(service_name, clear_pwd, **options) :
    if options.get("print", False) : 
        print("[SUCCESS][%s] Password: %s " % (service_name, clear_pwd))
    elif options.get("clipboard", True) : 
        if platform.system() == "Linux" : # store the pass in primary clipboard
            try: 
                p = Popen(['xclip', '-selection', 'p'], stdin=PIPE, close_fds=True)
                p.communicate(input=clear_pwd.encode('utf-8'))
            except: 
                fatal_error("[ERROR] Install package xclip or use '-p' option to display the pass")
        else :
            pyperclip.copy(clear_pwd)
        print("[SUCCESS][%s] Password copied in the primary clipboard." % (service_name))

######################################################
################# MAIN FUNCTIONS 
######################################################

def first_use():
    global global_data

    print("It seems that you launch DPM for the first time !")
    print("We need some of your inputs in order to use DPM properly :")
    print("")
    ask_global_pass = ask_strong_pass("- Your master password (it won't be stored): ")
    print("")
    print("If you want to share passwords with a group of people, feel free to registred an additionnal master key.")

    global_data =  {
        SERVICES_LIST : {},
        MASTERS_LIST  : {
            MASTER_CHECK : fingerprint(ask_global_pass)
        }
    }

    save_file()
    print("")
    print("[SUCCESS] DPM Initialization Complete (file: '" + working_directory + services_file_name+ "')")
    print("===> You are ready to use DPM : ")
    print_help()
    exit(0)

def list_apps() :
    current_master = None
    for service in sorted(services().iteritems(),key = lambda e:e[1].get(MASTER_KEY, MASTER_CHECK)):
        app_name, app_infos = service
        if current_master != app_infos.get(MASTER_KEY, MASTER_CHECK) : 
            current_master = app_infos.get(MASTER_KEY, MASTER_CHECK)
            print("")
            print(" ### MASTER KEY : %s " % current_master)
            print("")
        print((' ' * 4) + app_name)
    print("")

def passwd(service_name, **options) :
    service_hash = hash(service_name)    
    give_passwd(service_name, service_hash, **options)
    print_note(service_name)

def delete_service(service_name):
    service_exist = service_name in services().keys() 
    if not service_exist : 
        fatal_error("[ERROR] service not found\n")
    else:
        del services()[service_name]
        save_file()
        print("[DELETED] service '%s' correctly deleted" % service_name)

def delete_master_key(master_key_name):
    key_exist = master_key_name in master_keys().keys() 
    if not key_exist : 
        fatal_error("[ERROR] master key not found\n")
    else:
        del master_keys()[master_key_name]
        save_file()
        print("[DELETED] master_key '%s' correctly deleted" % master_key_name)

def add_service(service_name, **kwargs):
    if service_name in services().keys():
        print("[ERROR] service '%s' already exist" % service_name)
    else:
        services()[service_name] = {
            PWD_SIZE     : kwargs.get(PWD_SIZE, DEFAULT_PWD_SIZE),
            VERSION      : kwargs.get(VERSION, 0),
            NOTE         : kwargs.get(NOTE, ""),
            MASTER_KEY   : kwargs.get(MASTER_KEY, MASTER_CHECK),
            PWD_STRENGTH : kwargs.get(PWD_STRENGTH, False)
        }
        save_file()
        print("[ADDED] service '%s' correctly added." % service_name)

def add_master_key(master_key_name):
    if master_key_name in master_keys().keys():
        print("[ERROR] master key '%s' already exist" % master_key_name)
    else:
        master_keys()[master_key_name] = fingerprint(ask_strong_pass("[ASK] Initialize your '%s' password: " % master_key_name))
        save_file()
        print("[ADDED] service '%s' correctly added." % master_key_name)

def renew_pwd(service_name):
    if service_name not in services().keys():
        fatal_error("[ERROR] can't renew a service that doesn't exist.")
    else:
        services()[service_name][VERSION] = services()[service_name].get(VERSION, 0) + 1
        save_file()
        print("[RENEWED] '%s' password correctly renewed" % service_name)

def print_note(service_name) :
    if service_name in services().keys():
        note = services()[service_name].get(NOTE, "")
        if note is not None and len(note.strip()) > 0 :
            print("[INFOS] : %s" % note)

def set_note(service_name, note_value):
    save_config_attr(service_name, NOTE, note_value, "note")

def set_strength_lvl(service_name, level):
    if level in allowed_strength_lvl :
        save_config_attr(service_name, PWD_STRENGTH, level, "security level") 
    else :  
       fatal_error("[ERROR] unknown security level")    


def set_length(service_name, pwd_size):
    if pwd_size > 0 : 
        save_config_attr(service_name, PWD_SIZE, pwd_size, "password length")    
    else : 
        fatal_error("[ERROR] the password length must be over 0")

def print_desc(service_name):
    if service_name not in services().keys():
        fatal_error("[ERROR] can't print description on a service that doesn't exist.")
    else:
        print("")
        print(json.dumps(services()[service_name], indent=4, sort_keys=True))
        print("")

def export_config(key2export): 
    if key2export is None : 
        print(json.dumps(load_config(), indent=4, sort_keys=True))
    else : 
        data2export = {MASTERS_LIST : {}, SERVICES_LIST : {}}
        for key in load_config()[MASTERS_LIST] : 
            if key == key2export : 
                data2export[MASTERS_LIST][key] = load_config()[MASTERS_LIST][key]
        for app in load_config()[SERVICES_LIST] : 
            if load_config()[SERVICES_LIST][app][MASTER_KEY] == key2export : 
                data2export[SERVICES_LIST][app] = load_config()[SERVICES_LIST][app]
        print(json.dumps(data2export, indent=4, sort_keys=True))   

######################################################
################# MAIN ROUTINE 
######################################################

def run():

    load_arguments()
    load_config()
    args = args_parser.parse_args()

    if args.command == "help" : 
        print_help()

    if args.command == "gen" : 
        options = {
            "print": args.print_pwd,
            "clipboard": True
        }
        passwd(args.APP_NAME, **options)

    if args.command == "renew" :           
        renew_pwd(args.APP_NAME)

    if args.command == "export" :           
        export_config(args.MASTER_KEY)

    if args.command == "detail" : 
        print_desc(args.APP_NAME)

    if args.command == "list" : 
        list_apps()

    if args.command == "del" : 

        if args.sub_command == "app" : 
            delete_service(args.APP_NAME)

        if args.sub_command == "master_key" : 
            delete_master_key(args.MASTER_KEY)

    if args.command == "add" : 

        if args.sub_command == "app" : 
            initial_config = {
                PWD_SIZE     : args.length         if 'length'         in args else DEFAULT_PWD_SIZE,
                NOTE         : args.note           if 'note'           in args else "",
                PWD_STRENGTH : args.strength_level if 'strength_level' in args else DEFAULT_STRENGTH_LVL,
                MASTER_KEY   : args.master_key     if 'master_key'     in args else MASTER_CHECK
            }
            add_service(args.APP_NAME, **initial_config)

        if args.sub_command == "master_key" : 
            add_master_key(args.MASTER_KEY) 

    if args.command == "update" : 

        if args.sub_command == "app" : 
            if 'note'           in args : set_note(args.APP_NAME, args.note)
            if 'strength_level' in args : set_strength_lvl(args.APP_NAME, args.strength_level)
            if 'length'         in args : set_length(args.APP_NAME, args.length)
        
        if args.sub_command == "master_key" : 
            if args.new_password  : TODO()
            if 'new_name' in args : TODO()


run()



