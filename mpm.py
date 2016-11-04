#!/usr/bin/python
# PYTHON_ARGCOMPLETE_OK

import argparse, argcomplete
import os
from os.path import expanduser
from hashlib import sha224, sha512
from base64 import b64encode
from getpass import getpass
from sys import stderr, exit
from subprocess import Popen, PIPE
import re
import json

working_directory  = expanduser("~") + "/.marcel_pass_manager/"
services_file_name = 'services.json'
description        = '########## MARCEL password manager ##########'
check_password     = 0x0000
regex_servicename  = r'^([a-zA-Z\-\_\.0-9])+$'
services_list      = None

DEFAULT_PWD_SIZE   = 23
MIN_PWD_SIZE       = 8

#### JSON LABELS

PWD_SIZE = "pwd_size"
VERSION  = "version"
DESC     = "desc"

################# TODO ################### 
# - display the service desc with -h
# - improve the help
# - generate pwd by a charset
# - give custom fingerprint in argument 
# - improve autocompletion
# - SHA-XXX to HMAC-SHA-XXX
# - init the pass with the tool (fingerprint in json)
# - improve choice of argument name/letter

######################################################
################# UTIL FUNCTIONS 
######################################################

def services():
    global services_list
    if services_list == None : 
        if not os.path.exists(working_directory): os.makedirs(working_directory)
    
        with open(working_directory + services_file_name) as data_file:    
            services_list = json.load(data_file)
    
    return services_list

def autocomplete_services(prefix, parsed_args, **kwargs):
    return [service for service in services().keys() if prefix in service and service != '']

def save_file():
    with open(working_directory + services_file_name, 'w') as outfile:
        json.dump(services(), outfile, indent=4)

def fatal_error(msg):
    stderr.write(msg)
    exit(1)

######################################################
################# MAIN FUNCTIONS 
######################################################

def give_passwd(service_name, print_mode) :
    globalPassword = getpass("Global password: ")

    # Check that the globalPassword is correct.
    if int(sha224(globalPassword).hexdigest()[:4], 16) != check_password :
        fatal_error("[FAILED] Password error\n")
    
    pwd_size = DEFAULT_PWD_SIZE
    version  = 0    

    service_exist = service_name in services().keys()
    if service_exist:
        pwd_size = services()[service_name][PWD_SIZE]
        version  = services()[service_name][VERSION]
     
    version_string = ' _' * version 
    localPassword  = b64encode(sha512(globalPassword + " " + service_name + version_string).digest())[:pwd_size]
    
    if print_mode : 
        print("PASS : %s" % (localPassword))
    else : # store the pass in primary clipboard
        p = Popen(['xclip'], stdin=PIPE)
        p.communicate(input=localPassword)
        print("[SUCCESS] Password Ok (%s)" % (service_name))


def delete_service(service_name):
    service_exist = service_name in services().keys() 

    if not service_exist : 
        fatal_error("[ERROR] service not found\n")
    
    del services()[service_name]
    save_file()    
    print("[DELETED] '%s'" % (service_name) )


def add_service(service_name, **kwargs):
    if service_name in services().keys():
        print("service '%s' already exist" % service_name)
    else : 
        services()[service_name] = {
            PWD_SIZE : kwargs.get(PWD_SIZE, DEFAULT_PWD_SIZE),
            VERSION : kwargs.get(VERSION, 0),
            DESC : kwargs.get(DESC, "")
        }
        save_file()
        print("[ADDED] service correctly added.\n")


def renew_pwd(service_name):
    if service_name not in services().keys():
        fatal_error("[ERROR] can't renew a service that doesn't exist.")
    services()[service_name][VERSION] = services()[service_name].get(VERSION, 0) + 1 
    save_file()
    print("[RENEWED] service passwd correctly renewed")


def set_desc(service_name, desc):
    if service_name not in services().keys():
        fatal_error("[ERROR] can't set a description on a service that doesn't exist.")
    services()[service_name][DESC] = desc
    save_file()
    print("[SAVED] description saved")

######################################################
################# MAIN ROUTINE 
######################################################

def get_params():
    parser_arg = argparse.ArgumentParser(description=description)
    parser_arg.add_argument('service_name', help='the service you want to get the pass').completer = autocomplete_services
    parser_arg.add_argument('-p', '--view', action='store_true' ,help='print the password instead of using clipboard')
    parser_arg.add_argument('-a', '--add', action='store_true' ,help='add the service into the service list')
    parser_arg.add_argument('-s', '--size', default=DEFAULT_PWD_SIZE, type=int ,help='[must be used with --add] set the password size of a service')
    parser_arg.add_argument('-c', '--comment' ,help='set the service description [can be used directly with --add]')
    parser_arg.add_argument('-d', '--delete', action='store_true' ,help='delete the service from the service list')
    parser_arg.add_argument('-r', '--renew', action='store_true' ,help='renew the pass of the service')

    argcomplete.autocomplete(parser_arg, False)
    return parser_arg.parse_args()

def run(args) :
    if re.match(regex_servicename, args.service_name) == None: 
        fatal_error("[ERROR] The service name must contains only the following charset [a-Z, 0-9, '-', '_', '.']\n")
        
    if args.delete : 
        delete_service(args.service_name)
    else : 
        if args.renew : renew_pwd(args.service_name)
        give_passwd(args.service_name, args.view)
        if args.add    : 
            initial_config = {PWD_SIZE : args.size, DESC : args.comment}
            add_service(args.service_name, **initial_config)
        elif args.comment : 
            set_desc(args.service_name)

args = get_params()
run(args)




