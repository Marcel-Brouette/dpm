#!/usr/bin/python3
# PYTHON_ARGCOMPLETE_OK

from os.path import expanduser
from hashlib import sha224, sha512, pbkdf2_hmac
from base64 import b64encode, b64decode
from base64 import b85encode
from getpass import getpass
from sys import stderr
from sys import exit
from sys import argv
from subprocess import Popen
from subprocess import PIPE
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import pyperclip, platform, signal, random, string, time, keyutils, json, re, os, argcomplete, argparse


working_directory    = expanduser("~") + "/.dpm/"
services_file_name   = 'db.json'

description          = '########## Drustan Password Manager ##########'
regex_servicename    = r'^([a-zA-Z\-\_\.0-9\/])+$'
allowed_PWD_TYPE     = ['SHA512', 'PBKDF2', 'AES256']

global_data          = None
args_parser          = None

MIN_SIZE_STRONG_PWD  = 16
DEFAULT_PWD_SIZE     = 23
DEFAULT_PWD_TYPE     = 'PBKDF2'
CHARSET_SPECIAL      = r"[!@#$%^\&*\(\)_\+\{\}|:;<>,/-]"
CHARSET_DIGITS       = "[0-9]"
CHARSET_UPPERCASE    = "[A-Z]"
CHARSET_LOWERCASE    = "[a-z]"
LIST_CHARSET         = ['LOWERCASE', 'UPPERCASE', 'DIGITS', 'SPECIAL']
DEFAULT_PWD_CHARSET  = {
    'LOWERCASE' : CHARSET_LOWERCASE,
    'UPPERCASE' : CHARSET_UPPERCASE,
    'DIGITS'    : CHARSET_DIGITS,
    'SPECIAL'   : CHARSET_SPECIAL
}

#### JSON LABELS

MASTERS_LIST   = "master_keys"
KEYRING_STORAGE = "remember"
MASTER_CHECK   = "default_master"
SERVICES_LIST  = "services"

PWD_SIZE     = "pwd_size"
VERSION      = "version"
NOTE         = "note"
MASTER_KEY   = "master_key"
PWD_CHARSET  = "pwd_charset"
PWD_TYPE     = "type"

##########################################################
################## ARGUMENTS SETTINGS ####################
##########################################################

def load_arguments():
    global args_parser

    args_parser = argparse.ArgumentParser(add_help=False, description="Drustan Password Manager - Secure password management with kernel keyring")
    main_sub_cmds = args_parser.add_subparsers(dest='command', title="command")
    #args_parser.add_argument('service_name', help='the service you want to get the pass').completer = autocomplete_services

    ###############  SUB_COMMANDS 1 ################

    help_cmd   = main_sub_cmds.add_parser("help", description="Show this help message", add_help=True)
    gen_cmd    = main_sub_cmds.add_parser("gen", description="Generate password for a service", add_help=True)
    add_cmd    = main_sub_cmds.add_parser("add", description="Add new app or master key", add_help=True)
    del_cmd    = main_sub_cmds.add_parser("del", description="Delete app or master key", add_help=True)
    list_cmd   = main_sub_cmds.add_parser("list", description="List all apps", add_help=True)
    renew_cmd  = main_sub_cmds.add_parser("renew", description="Renew password for an app", add_help=True)
    update_cmd = main_sub_cmds.add_parser("update", description="Update app or master key settings", add_help=True)
    detail_cmd = main_sub_cmds.add_parser("detail", description="Show detailed app information", add_help=True)
    export_cmd = main_sub_cmds.add_parser("export", description="Export configuration", add_help=True)
    forget_cmd = main_sub_cmds.add_parser("revoke", description="Revoke a master key from keyring", add_help=True)

    add_sub_cmds  = add_cmd.add_subparsers(dest='sub_command')
    del_sub_cmds  = del_cmd.add_subparsers(dest='sub_command')
    upd_sub_cmds  = update_cmd.add_subparsers(dest='sub_command')

    ###############  SUB_COMMANDS 2 ################

    add_mkey_cmd  = add_sub_cmds.add_parser('master_key', description='Add a new master key', add_help=True)
    del_mkey_cmd  = del_sub_cmds.add_parser('master_key', description='Delete a master key', add_help=True) 
    upd_mkey_cmd  = upd_sub_cmds.add_parser('master_key', description='Update master key settings', add_help=True)
    upd_app_cmd   = upd_sub_cmds.add_parser('app', description='Update app settings', add_help=True)
    add_app_cmd   = add_sub_cmds.add_parser('app', description='Add a new app', add_help=True)
    del_app_cmd   = del_sub_cmds.add_parser('app', description='Delete an app', add_help=True)

    ##############  ARGS ##############

    gen_cmd.add_argument('APP_NAME', help='Name of the app to generate password for').completer = autocomplete_services
    gen_cmd.add_argument('-p', '--print_pwd', action='store_true', help='Print password instead of copying to clipboard')
    gen_cmd.add_argument('-mp', '--master_pwd', default=argparse.SUPPRESS, help='Master password (if not stored in keyring)')

    add_mkey_cmd.add_argument('MASTER_KEY', help='Name of the master key to add')
    del_mkey_cmd.add_argument('MASTER_KEY', help='Name of the master key to delete').completer = autocomplete_master_key
    upd_mkey_cmd.add_argument('MASTER_KEY', help='Name of the master key to update').completer = autocomplete_master_key
    upd_mkey_cmd.add_argument('--new_password', action='store_true', help='Update master key password')
    upd_mkey_cmd.add_argument('--new_name', default=argparse.SUPPRESS, help='Rename master key')
    export_cmd.add_argument('MASTER_KEY', nargs='?', help='Master key to export (optional)').completer = autocomplete_master_key

    del_app_cmd.add_argument('APP_NAME', help='Name of the app to delete').completer = autocomplete_services

    upd_app_cmd.add_argument('APP_NAME', help='Name of the app to update').completer = autocomplete_services
    upd_app_cmd.add_argument('-l', '--length', type=int, default=argparse.SUPPRESS, help='Password length')
    upd_app_cmd.add_argument('-n', '--note', default=argparse.SUPPRESS, help='App note')
    upd_app_cmd.add_argument('-m', '--pwd_type', default=argparse.SUPPRESS, help='Password type (SHA512 or PBKDF2)')
    upd_app_cmd.add_argument('-c','--charset', nargs='+', choices=LIST_CHARSET, default=argparse.SUPPRESS, help='Charsets to include in password generation')
    upd_app_cmd.add_argument('-cs','--custom-special', default=argparse.SUPPRESS, help='Custom special characters set')

    add_app_cmd.add_argument('APP_NAME', help='Name of the app to add')
    add_app_cmd.add_argument('-l', '--length', type=int, default=argparse.SUPPRESS, help='Password length')
    add_app_cmd.add_argument('-m', '--pwd_type', default=argparse.SUPPRESS, help='Password type (SHA512 or PBKDF2)')
    add_app_cmd.add_argument('-k', '--master_key', default=argparse.SUPPRESS, help='Master key to use').completer = autocomplete_master_key
    add_app_cmd.add_argument('-n', '--note', default=argparse.SUPPRESS, help='App note')
    add_app_cmd.add_argument('-ng', '--no-gen', action='store_true', help='Skip password generation after adding the app')
    add_app_cmd.add_argument('-c','--charset', nargs='+', choices=LIST_CHARSET, default=argparse.SUPPRESS, help='Charsets to include in password generation')
    add_app_cmd.add_argument('-cs','--custom-special', default=argparse.SUPPRESS, help='Custom special characters set')
    add_app_cmd.add_argument('--store', action='store_true', help='Store encrypted password (less secure, for non-changable passwords)')
    add_app_cmd.add_argument('--store_pwd', default=argparse.SUPPRESS, help='Password to store when using --store mode')

    renew_cmd.add_argument('APP_NAME', help='Name of the app to renew password for').completer = autocomplete_services
    detail_cmd.add_argument('APP_NAME', help='Name of the app to show details for').completer = autocomplete_services
    forget_cmd.add_argument('MASTER_KEY', help='Master key to revoke (or "all" to revoke all)').completer = autocomplete_master_key

    argcomplete.autocomplete(args_parser, False)

######################################################
################# EXIT PROPERLY ON SIGINT

def signal_handler(sig, frame):
    if sig == signal.SIGINT : 
        print("\n")
        exit(0)

signal.signal(signal.SIGINT, signal_handler)

######################################################
################# UTIL FUNCTIONS 
######################################################

def success_msg(msg):
    no_color='\033[0m'
    color='\033[1;32m'
    print(color + msg + no_color)

def warn_msg(msg):
    no_color='\033[0m'
    color='\033[1;33m'
    stderr.write(color + "[WARN] " + msg + no_color + "\n")

def fatal_error(msg):
    no_color='\033[0m'
    color='\033[1;31m'
    stderr.write(color + "[ERROR] " + msg + no_color + "\n")
    exit(1)

def random_string(length):
    charset = string.ascii_letters + string.digits + r"!@#$%^&*()-_=+[{]}\|;:,.<>/?"
    return ''.join(random.choice(charset) for _ in range(length))

##############  CUSTOM HELP ##############

def print_help():
    header        = "\n##############################################\n"
    header       += "########## Drustan Password Manager ##########\n\n"
    global_usage  = "usage: " + argv[0] + " <command> [<sub_command>] [[options] [value]]\n\n"
    detail        = "commands : (not exhaustive options, for detailed help, use '"+argv[0]+" <command> --help')\n\n"
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
    for cmd_name, choice in sorted(cmd_tree['list_cmd'].items(),key = lambda e:len(e[1][2])):
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

def config():
    global global_data
    if global_data == None :
        is_first_use = False 
        full_path_file = working_directory + services_file_name
        if not os.path.exists(working_directory): os.makedirs(working_directory)
        with open(full_path_file, 'a+', encoding='utf-8') as data_file:    
            data_file.seek(0,2) # 'a+' don't put the reference point in the end of file ...
            if data_file.tell() == 0: 
                first_use()
            else : 
                data_file.seek(0)
                global_data = config_is_valid(data_file)
                save_file()
    return global_data 

def services():
    return config()[SERVICES_LIST]

def is_keyring_enabled():
    return KEYRING_STORAGE in config()[MASTERS_LIST] and config()[MASTERS_LIST][KEYRING_STORAGE]

def master_keys():
    return config()[MASTERS_LIST]

def master_key_fp(master_key_name):
    check_master_exist(master_key_name)
    return config()[MASTERS_LIST][master_key_name]

def check_master_exist(master_key_name): 
    if master_key_name not in master_keys().keys() :
        fatal_error(" the fingerprint of '%s' master key doesn't exist" % master_key_name)

def autocomplete_services(prefix, parsed_args, **kwargs):
    return [service for service in services().keys() if prefix in service and service != '']

def autocomplete_master_key(prefix, parsed_args, **kwargs):
    return [key for key in master_keys().keys() if prefix in key and key != '']

def save_file():
    with open(working_directory + services_file_name, 'w') as outfile:
        json.dump(config(), outfile, indent=4)
    os.chmod(working_directory + services_file_name, 0o600)


def save_config_attr(service_name, key, value, attr_name):
    error_msg   = "Can't set a %s on a service that doesn't exist." % attr_name 
    success_msg_text = "[SAVED] '%s' %s saved" % (service_name, attr_name)
    if service_name not in services().keys():
        fatal_error(error_msg)
    else:
        services()[service_name][key] = value
        save_file()
        success_msg(success_msg_text)
        print_desc(service_name)


def config_is_valid(data_file):
    data = {}
    try: 
        data = json.load(data_file)
    except: 
        fatal_error(" The configuration file is not a valid JSON")
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

##############  functions  ##############

def charset_filter(input_str, list_charsets): 
    return ''.join(re.findall('|'.join(list_charsets),input_str))

def substring_from_charsets(input_string, list_charsets, size):
    if len(list_charsets) > size : 
        fatal_error("The password string is too short to match the mandotary charsets")

    input_string = charset_filter(input_string, list_charsets)
    return_value = ""
    isIncomplete = len(return_value) < size
    i = 0

    while isIncomplete :
        if(i >= len(input_string)) : 
            fatal_error("impossible to generate a password that matches all given charsets, only base85 characters allowed")

        current_char     = input_string[i]
        add_only_charset = size - len(return_value) == len(list_charsets)
        charset_is_matched = False

        for charset in list_charsets: 
            if re.match(charset, current_char): 
                list_charsets.remove(charset)
                charset_is_matched = True

        mustAddChar  = add_only_charset and charset_is_matched
        mustAddChar |= not add_only_charset

        if mustAddChar :
            return_value += current_char

        i += 1       
        isIncomplete = len(return_value) < size

    return return_value

def ask_strong_pass(msg):
    asked_pass  = ''
    pwd_is_weak = True
    while pwd_is_weak :
        asked_pass   = getpass(msg) 
        pwd_is_weak  = len(asked_pass) < MIN_SIZE_STRONG_PWD
        pwd_is_weak |= pwd_is_basic_charset(asked_pass)        
        if pwd_is_weak : 
            warn_msg("Your password is TOO WEAK (size under " + str(MIN_SIZE_STRONG_PWD) + " chars or basic charset only)")
    return asked_pass.encode('utf-8')


def pwd_is_basic_charset(pwd):
    for letter in pwd: 
        is_simple  = False
        is_simple |= (ord(letter) > 100 and ord(letter) < 133)    
        is_simple |= (ord(letter) > 140 and ord(letter) < 173)    
        if not is_simple : return False
    return True


def fingerprint(pwd) : 
    return int(sha224(pwd).hexdigest()[:4], 16) 

def ask_passwd(fp, **options):
    master_key_name = options.get("master_key_name", MASTER_CHECK)
    msg  = "[ASK][%s] password: " % master_key_name
    global_passwd = options.get("master_pwd", "") if options.get("master_pwd", "") else getpass(msg)
    if fingerprint(global_passwd.encode('utf-8')) != fp: 
        fatal_error("Bad password\n")    
    return global_passwd

def get_service(service_name):
    """Get service configuration as a dictionary"""
    service_exist = service_name in services().keys()
    
    if service_exist:
        service_config = services()[service_name]
        return {
            'exists': True,
            'version': service_config[VERSION],
            'master_key_name': service_config.get(MASTER_KEY, MASTER_CHECK),
            'pwd_size': service_config[PWD_SIZE],
            'pwd_type': service_config[PWD_TYPE],
            'pwd_charset': service_config.get(PWD_CHARSET, list(DEFAULT_PWD_CHARSET.values()))
        }
    else:
        warn_msg(f"'{service_name}' is not in your application list")
        return {
            'exists': False,
            'version': 0,
            'master_key_name': MASTER_CHECK,
            'pwd_size': DEFAULT_PWD_SIZE,
            'pwd_type': DEFAULT_PWD_TYPE,
            'pwd_charset': list(DEFAULT_PWD_CHARSET.values())
        }

def encrypt_aes256ctr(data, key):
    if len(key) < 12: 
        fatal_error("Encryption Key is too short (min 12 chars)")
    """Encrypt data using AES256-CTR mode with deterministic nonce"""
    key_bytes = sha512(key.encode()).digest()[:32]
    nonce_seed = sha512((key + "DPMAES256CTR").encode()).digest()[:16]
    ctr = modes.CTR(nonce_seed)
    cipher = Cipher(algorithms.AES(key_bytes), ctr, backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(data.encode()) + encryptor.finalize()

    return b64encode(encrypted).decode('utf-8')

def decrypt_aes256ctr(encrypted_data, key):
    """Decrypt data using AES256-CTR mode with deterministic nonce"""
    key_bytes = sha512(key.encode()).digest()[:32]
    nonce_seed = sha512((key + "DPMAES256CTR").encode()).digest()[:16]
    ctr = modes.CTR(nonce_seed)
    encrypted = b64decode(encrypted_data.encode())
    cipher = Cipher(algorithms.AES(key_bytes), ctr, backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(encrypted) + decryptor.finalize()
    
    return decrypted.decode('utf-8')

def hash(service_name, **options) :
    master_pwd = options.get("master_pwd", None) # argument from command line
    service_config  = get_service(service_name)
    master_key_name = service_config['master_key_name']
    pwd_size        = service_config['pwd_size']
    pwd_charset     = service_config['pwd_charset'].copy()
    pwd_type        = service_config['pwd_type']
    version         = service_config['version']
    service_hash    = False
    
    fp = master_key_fp(master_key_name)

    if is_keyring_enabled() and master_pwd is None : 
        master_pwd = retrieve_master_key(master_key_name)

    globalPassword = ask_passwd(fp, master_pwd=master_pwd, master_key_name=master_key_name)    

    if is_keyring_enabled() and not keyring_contains(master_key_name):
        store_master_key(master_key_name, globalPassword)
    
    if pwd_type == 'SHA512':
        version_string = ' _' * version 
        service_hash = b64encode(sha512(f'{globalPassword} {service_name}{version_string}'.encode()).digest())[:pwd_size]
        service_hash = service_hash.decode('utf-8')
    else: # PBKDF2
        derivation_key = b85encode(pbkdf2_hmac('sha512', globalPassword.encode(), service_name.encode(), 10000+version, dklen=4096))
        service_hash = substring_from_charsets(derivation_key.decode('utf-8') ,pwd_charset, pwd_size)

    return service_hash

def give_passwd(service_name, clear_pwd, **options) :
    pyper = False
    if options.get("print", False) : 
        success_msg(f'[SUCCESS][{service_name}] Password: {clear_pwd} ')
    elif options.get("clipboard", True) : 
        if platform.system() == "Linux" : # store the pass in primary clipboard
            err_wl_copy=False
            err_xclip=False

            try: 
                p = Popen(['wl-copy', '-p'], stdin=PIPE, close_fds=True)
                p.communicate(input=bytes(clear_pwd, 'utf-8'))
            except :
                err_wl_copy=True

            try: 
                p = Popen(['xclip', '-selection', 'p'], stdin=PIPE, close_fds=True)
                p.communicate(input=bytes(clear_pwd, 'utf-8'))
            except: 
                err_xclip=True

            success_msg("[SUCCESS][%s] Password copied in the primary clipboard." % (service_name))

            if err_wl_copy and err_xclip :
                warn_msg(" The primary clipboard utility doesn't work : \r\n" +
                            "- if you are running X server, please install xclip \r\n" +
                            "- if you are running wayland, please install wp-clipboard \r\n" +
                            "- You can still use the '-p' option to display the pass")
                warn_msg("Fallback to classic clipboard")
                pyper = True
        else :
            pyper = True
            
        if pyper :
            pyperclip.copy(clear_pwd)
            success_msg("[SUCCESS][%s] Password copied in the clipboard." % (service_name))


######################################################
################# KEYRING MANAGEMENT 
######################################################

# KERNEL KEYRING store in RAM but in kernel ram : 
# - it won't be swap or save on disk    
# - it is bound to the user session
# - it is not accessible from other users
# - IT WON'T PROTECT FROM ROOT USER, RAM DUMP or cold attack on RAM !!!!

def store_master_key(key_name, master_pwd):
    scope = keyutils.KEY_SPEC_SESSION_KEYRING
    key_id = keyutils.add_key(key_name.encode('utf-8'), master_pwd.encode('utf-8'), scope, b'user')
    return key_id

def retrieve_master_key(key_name):
    try:
        scope = keyutils.KEY_SPEC_SESSION_KEYRING
        key_id = keyutils.request_key(key_name.encode('utf-8'), scope, b'user')
        if key_id:
            return keyutils.read_key(key_id).decode('utf-8')
    except Exception as e:
        warn_msg(f"Error retrieving master key from keyring: {e}")
    return None

def keyring_contains(key_name):
    return retrieve_master_key(key_name) is not None

def revoke_master_key(key_name):
    try:
        scope = keyutils.KEY_SPEC_SESSION_KEYRING
        key_id = keyutils.request_key(key_name.encode('utf-8'), scope, b'user')
        if key_id:
            keyutils.revoke(key_id)
    except Exception as e:
        warn_msg(f"Error revoking master key from keyring: {e}")


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

    print("By default, DPM will never store your master key, which means that it will be ask each time. IT IS THE MOST SECURE OPTION !")
    print("")
    print("However, it is possible to store the master key in the kernel keyring. Then you won't be asked for it each time.")
    keyring_choice = input("Do you want to enable this feature? (y/N): ")


    global_data =  {
        SERVICES_LIST : {},
        MASTERS_LIST  : {
            MASTER_CHECK : fingerprint(ask_global_pass),
            KEYRING_STORAGE : keyring_choice.lower() == 'y'
        }
    }
    
    save_file()
    print("")
    success_msg("[SUCCESS] DPM Initialization Complete (file: '" + working_directory + services_file_name+ "')")
    print("")
    print("--------------------------------")
    print("If you want to share passwords with a group of people, feel free to registred an additionnal master key.")
    print("--------------------------------")
    print("")
    print("===> You are ready to use DPM : dpm help")
    print("")
    exit(0)

################## LIST COMMAND ##################

def list_apps() :
    current_master = None
    for service in sorted(services().items(),key = lambda e:e[1].get(MASTER_KEY, MASTER_CHECK)):
        app_name, app_infos = service
        if current_master != app_infos.get(MASTER_KEY, MASTER_CHECK) : 
            current_master = app_infos.get(MASTER_KEY, MASTER_CHECK)
            print("")
            print(" ### MASTER KEY : %s " % current_master)
            print("")
        print((' ' * 4) + app_name)
    print("")

################## GEN COMMAND ##################

def passwd(service_name, **options) :
    service_config = get_service(service_name)
    pwd_type = service_config['pwd_type']
    
    if pwd_type == 'AES256':
        # For AES256 mode: get PBKDF2 hash from hash(), then decrypt stored password
        stored_password = services()[service_name].get('stored_password', None)
        if stored_password is None:
            fatal_error("No stored password found for this service")
        
        service_hash_key = hash(service_name, **options)
        service_password = decrypt_aes256ctr(stored_password, service_hash_key)
    else:
        # For SHA512 or PBKDF2 mode: generate password normally
        service_password = hash(service_name, **options)
    
    give_passwd(service_name, service_password, **options)
    print_note(service_name)

################## DELETE COMMAND ##################

def delete_service(service_name):
    service_exist = service_name in services().keys() 
    if not service_exist : 
        fatal_error("service not found\n")
    else:
        del services()[service_name]
        save_file()
        print("[DELETED] service '%s' correctly deleted" % service_name)

def delete_master_key(master_key_name):
    key_exist = master_key_name in master_keys().keys() 
    if not key_exist : 
        fatal_error("master key not found\n")
    else:
        del master_keys()[master_key_name]
        save_file()
        print("[DELETED] master_key '%s' correctly deleted" % master_key_name)

################## ADD COMMAND ##################

def handle_add_app(app_name, args):
    """Handle the add app command"""
    store_mode = hasattr(args, 'store') and args.store
    charset = build_charset(
        selected_charsets=args.charset if 'charset' in args else None,
        custom_special=args.custom_special if 'custom_special' in args else None
    )
    initial_config = {
        PWD_SIZE     : args.length         if 'length'         in args else DEFAULT_PWD_SIZE,
        NOTE         : args.note           if 'note'           in args else "",
        MASTER_KEY   : args.master_key     if 'master_key'     in args else MASTER_CHECK,
        PWD_TYPE     : args.pwd_type       if 'pwd_type'       in args else DEFAULT_PWD_TYPE,
        PWD_CHARSET  : charset
    }
    add_service(app_name, **initial_config)
    
    if store_mode:
        service_hash = hash(app_name) 
        enable_stored_mode(app_name, service_hash, args.store_pwd if 'store_pwd' in args else None)
    
    # generate password (unless --no-gen is specified or in store mode)
    if not store_mode and (not hasattr(args, 'no_gen') or not args.no_gen):
        options = {"clipboard": True}
        passwd(app_name, **options)

def enable_stored_mode(service_name, service_hash, password_to_store):
    """Add a service with stored encrypted password"""    
    warn_msg("WARNING: Using stored password mode is less secure.")
    warn_msg("WARNING: The password cannot be accessed from another machine.")
    warn_msg("WARNING: This password cannot be renewed.")
    
    if password_to_store is None:
        password_to_store = getpass("Enter the password to store: ")

    # Encrypt the password using the hash key
    stored_password = encrypt_aes256ctr(password_to_store, service_hash)
    services()[service_name][PWD_TYPE] = 'AES256'
    services()[service_name]['stored_password'] = stored_password
    save_file()
    success_msg(f"[ADDED] stored service '{service_name}' correctly added.")

def add_service(service_name, **kwargs):
    if service_name in services().keys():
        fatal_error(f"service '{service_name}' already exist")
    else:
        service_config = {
            PWD_SIZE      : kwargs.get(PWD_SIZE, DEFAULT_PWD_SIZE),
            VERSION       : kwargs.get(VERSION, 0),
            NOTE          : kwargs.get(NOTE, ""),
            MASTER_KEY    : kwargs.get(MASTER_KEY, MASTER_CHECK),
            PWD_TYPE      : kwargs.get(PWD_TYPE, DEFAULT_PWD_TYPE),
            PWD_CHARSET   : kwargs.get(PWD_CHARSET, build_charset())
        }

        services()[service_name] = service_config
        save_file()
        success_msg(f"[ADDED] service '{service_name}' correctly added.")

def add_master_key(master_key_name):
    if master_key_name in master_keys().keys():
        fatal_error("master key '%s' already exist" % master_key_name)
    else:
        master_keys()[master_key_name] = fingerprint(ask_strong_pass("[ASK] Initialize your '%s' password: " % master_key_name))
        save_file()
        print("[ADDED] service '%s' correctly added." % master_key_name)

################## RENEW COMMAND ##################

def renew_pwd(service_name):
    if service_name not in services().keys():
        fatal_error(" can't renew a service that doesn't exist.")
    else:
        service_config = services()[service_name]
        if service_config.get(PWD_TYPE) == 'AES256':
            fatal_error("Cannot renew stored passwords. This service uses stored password mode.")
        services()[service_name][VERSION] = services()[service_name].get(VERSION, 0) + 1
        save_file()
        print("[RENEWED] '%s' password correctly renewed" % service_name)


################## UPDATE COMMAND ##################

def set_note(service_name, note_value):
    save_config_attr(service_name, NOTE, note_value, "note")

def set_length(service_name, pwd_size):
    if pwd_size > 0 : 
        save_config_attr(service_name, PWD_SIZE, pwd_size, "password length")    
    else : 
        fatal_error("The password length must be over 0")

def set_pwd_type(service_name, pwd_type):
    if pwd_type in allowed_PWD_TYPE:
        save_config_attr(service_name, PWD_TYPE, pwd_type, "password type")
    else:
        fatal_error(f"Invalid password type '{pwd_type}'. Allowed types: {', '.join(allowed_PWD_TYPE)}")

def build_charset(selected_charsets=None, custom_special=None):
    """Build charset based on selected charsets and custom special"""
    if selected_charsets is None:
        # Use all charsets by default
        charset = list(DEFAULT_PWD_CHARSET.values())
    else:
        if custom_special is not None:
            DEFAULT_PWD_CHARSET[charset_name] = custom_special

        charset = []
        for charset_name in selected_charsets:
            if charset_name in DEFAULT_PWD_CHARSET:
                charset.append(DEFAULT_PWD_CHARSET[charset_name])
        
    return charset

def set_charset(service_name, selected_charsets):
    """Set charset for a service based on selected charsets"""
    charset = build_charset(selected_charsets)
    save_config_attr(service_name, PWD_CHARSET, charset, "charset setting")

def set_custom_special(service_name, custom_special):
    """Set custom special charset for a service"""
    charset = build_charset(custom_special=custom_special)
    save_config_attr(service_name, PWD_CHARSET, charset, "custom special charset")

def update_master_key_password(master_key_name, new_password):
    if master_key_name not in master_keys().keys():
        fatal_error(f"Master key '{master_key_name}' doesn't exist")
    
    warn_msg(f"WARNING: all passwords using this master key will be invalidated, are you sure you want to continue? (y/N)")
    if input().lower() == 'y':
        new_fp = fingerprint(ask_strong_pass(f"[ASK] Enter new password for '{master_key_name}': "))
        master_keys()[master_key_name] = new_fp
        save_file()
        success_msg(f"[UPDATED] Master key '{master_key_name}' password updated")
        
        # Revoke old key from keyring if it exists
        revoke_master_key(master_key_name)

def update_master_key_name(old_name, new_name):
    if old_name not in master_keys().keys():
        fatal_error(f"Master key '{old_name}' doesn't exist")
    if new_name in master_keys().keys():
        fatal_error(f"Master key '{new_name}' already exists")
    
    # Update the master key name
    master_keys()[new_name] = master_keys()[old_name]
    del master_keys()[old_name]
    
    # Update all services using this master key
    for service_name, service_config in services().items():
        if service_config.get(MASTER_KEY, MASTER_CHECK) == old_name:
            service_config[MASTER_KEY] = new_name
    
    save_file()
    success_msg(f"[UPDATED] Master key '{old_name}' renamed to '{new_name}'")
    
    # Revoke old key from keyring if it exists
    revoke_master_key(old_name)

################## KEYRING COMMAND ##################

def revoke_command(master_key_name):
    if master_key_name == "all":
        # Revoke all master keys from keyring
        for key_name in master_keys().keys():
            revoke_master_key(key_name)
        success_msg("[REVOKED] All master keys removed from keyring")
    else:
        if master_key_name not in master_keys().keys():
            fatal_error(f"Master key '{master_key_name}' doesn't exist")
        
        revoke_master_key(master_key_name)
        success_msg(f"[REVOKED] Master key '{master_key_name}' removed from keyring")

################## PRINT COMMAND ##################

def print_note(service_name) :
    if service_name in services().keys():
        note = services()[service_name].get(NOTE, "")
        if note is not None and len(note.strip()) > 0 :
            print("[INFOS] : %s" % note)

def print_desc(service_name):
    if service_name not in services().keys():
        fatal_error("Can't print description on a service that doesn't exist.")
    else:
        print("")
        print(json.dumps(services()[service_name], indent=4, sort_keys=True))
        print("")

def export_config(key2export): 
    if key2export is None : 
        print(json.dumps(config(), indent=4, sort_keys=True))
    else : 
        data2export = {MASTERS_LIST : {}, SERVICES_LIST : {}}
        for key in config()[MASTERS_LIST] : 
            if key == key2export : 
                data2export[MASTERS_LIST][key] = config()[MASTERS_LIST][key]
        for app in config()[SERVICES_LIST] : 
            if config()[SERVICES_LIST][app][MASTER_KEY] == key2export : 
                data2export[SERVICES_LIST][app] = config()[SERVICES_LIST][app]
        print(json.dumps(data2export, indent=4, sort_keys=True))   

######################################################
################# MAIN ROUTINE 
######################################################

def run():

    load_arguments()
    args = args_parser.parse_args()

    # Si aucun argument n'est fourni, afficher le help
    if not hasattr(args, 'command') or args.command is None:
        print_help()
        exit(0)

    if args.command == "help" : 
        print_help()

    if args.command == "gen" : 
        options = {
            "print": args.print_pwd,
            "master_pwd": args.master_pwd if 'master_pwd' in args else None,
            "clipboard": True
        }
        passwd(args.APP_NAME, **options)

    if args.command == "renew" :           
        renew_pwd(args.APP_NAME)

    if args.command == "export" :           
        export_config(args.MASTER_KEY)

    if args.command == "detail" : 
        print_desc(args.APP_NAME)

    if args.command == "revoke" :
        revoke_command(args.MASTER_KEY)

    if args.command == "list" : 
        list_apps()

    if args.command == "del" : 

        if args.sub_command == "app" : 
            delete_service(args.APP_NAME)

        if args.sub_command == "master_key" : 
            delete_master_key(args.MASTER_KEY)

    if args.command == "add" : 

        if args.sub_command == "app" : 
            handle_add_app(args.APP_NAME, args)
            

        if args.sub_command == "master_key" : 
            add_master_key(args.MASTER_KEY) 

    if args.command == "update" : 

        if args.sub_command == "app" : 
            if 'note'           in args : set_note(args.APP_NAME, args.note)
            if 'length'         in args : set_length(args.APP_NAME, args.length)
            if 'pwd_type'       in args : set_pwd_type(args.APP_NAME, args.pwd_type)
            if 'charset'        in args : set_charset(args.APP_NAME, args.charset)
            if 'custom_special' in args : set_custom_special(args.APP_NAME, args.custom_special)
        
        if args.sub_command == "master_key" : 
            must_update_mk_pwd = hasattr(args, 'new_password') and args.new_password
            if must_update_mk_pwd : update_master_key_password(args.MASTER_KEY, args.new_password)
            if 'new_name' in args : update_master_key_name(args.MASTER_KEY, args.new_name)
    

    exit(0)


run()

