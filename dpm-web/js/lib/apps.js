// JSON LABELS

const MASTERS_LIST   = "master_keys"
const MASTER_CHECK   = "default_master"
const SERVICES_LIST  = "services"

const PWD_SIZE       = "pwd_size"
const VERSION        = "version"
const NOTE           = "note"
const MASTER_KEY     = "master_key"
const PWD_STRENGTH   = "pwd_strength"

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
                App.data[SERVICES_LIST] = {}
                App.data[MASTERS_LIST]  = {}
                localStorage.setItem(VAR_LOCALSTOR, JSON.stringify(App.data))
            }
        }
        return App.data
    },

    'newMasterKey' : function() {
        console.log
    }
}
