// JSON LABELS

const MASTERS_LIST   = "master_keys"
const MASTER_CHECK   = "default_master"
const SERVICES_LIST  = "services"

const PWD_SIZE       = "pwd_size"
const VERSION        = "version"
const NOTE           = "note"
const MASTER_KEY     = "master_key"
const PWD_STRENGTH   = "pwd_strength"

const MIN_SIZE_STRONG_PWD  = 16
const DEFAULT_PWD_SIZE     = 23
const DEFAULT_STRENGTH_LVL = 2
const ALLOWED_STRENGTH_LVL = [2, 3]

const VAR_LOCALSTOR  = "dpm-config"

let App = {
    'data' : null,

    // method 
    'getConfig' : function() {
        if(App.data == null) {
            local_stored = JSON.parse(localStorage.getItem(VAR_LOCALSTOR))
            if(local_stored){
                App.data = local_stored
            }
            else{
                App.data = {}
                App.clearConfig()
            }
        }
        return App.data
    },
    'clearConfig' : function() {
        App.initEmptyConfig()
        App.saveConfig()
    },
    'initEmptyConfig' : function() {
        App.data[SERVICES_LIST] = {}
        App.data[MASTERS_LIST]  = {}
    },
    'saveConfig' : function(){
        localStorage.setItem(VAR_LOCALSTOR, JSON.stringify(App.data))
    },
    'loadConfig' : function(input_json){
        input_config = JSON.parse(input_json)
        let is_valid_config = true
        is_valid_config    &= SERVICES_LIST in input_config
        is_valid_config    &= MASTERS_LIST  in input_config
        if (!is_valid_config){
            return new Error(INVALID_CONFIG_FILE)
        }
        else {
            App.loadMasterKeys(input_config[MASTERS_LIST])
            App.loadApplications(input_config[SERVICES_LIST])
            App.saveConfig()
            return true
        }
    },
    'loadMasterKeys' : function(key_list){
        App.getConfig()[MASTERS_LIST] = Object.assign({}, key_list)
    },
    'loadApplications' : function(app_list){
        App.getConfig()[SERVICES_LIST] = Object.assign({}, app_list)
    }, 
    'listMasterKeys' : function() {
        return App.getConfig()[MASTERS_LIST]
    }, 
    'listApplications' : function() {
        return App.getConfig()[SERVICES_LIST]
    }, 
    'fingerprint' : function(password) {
        return sha256(password).then((hash_val) => {
            return parseInt(hash_val.substr(0, 4), 16)
        })
    },
    'fpByMasterKey' : function(master_key_name) {
        if (!(master_key_name in listMasterKeys()[MASTERS_LIST])){
            return new Error(MASTER_KEY_DONT_EXIST)
        }
        return listMasterKeys()[MASTERS_LIST][master_key_name]
    },
    'newMasterKey' : function(name, password) {
        if(name in App.listMasterKeys()){
            return new Error(ERR_KEY_ALREADY_EXIST)
        }
        else{
            // test => Object.defineProperty(obj, "b", { value: 2 });
            App.fingerprint(password).then((fp) => {
                App.listMasterKeys()[name] = fp            // notify vuejs ...
                App.loadMasterKeys(App.getConfig()[MASTERS_LIST])
                App.saveConfig()
            })
            return true
        }
    }, 
    'generatePwd' : function(app_name, pwd){
        let pwd_size     = DEFAULT_PWD_SIZE
        let version      = 0 
        let strength_lvl = 2
        let pass_gen     = ''
        let app_exist    = app_name in App.listApplications()
        if(!app_exist){
            return new Error(SERVICE_DONT_EXIST)
        }
        else{
            version         = App.listApplications()[app_name][VERSION]
            master_key_name = App.listApplications()[app_name][MASTER_KEY]
            pwd_size        = App.listApplications()[app_name][PWD_SIZE]
            strength_lvl    = App.listApplications()[app_name][PWD_STRENGTH]
        }
    
        let version_string = ''
        for (let i =0; i < version; i++) {
            version_string += ' _'
        }
        return sha512(pwd + " " + app_name + version_string).then(
            (hashed_val) => {
                return hexToBase64(hashed_val).substr(0, pwd_size)
            }
        )
    }

}
