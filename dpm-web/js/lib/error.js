const ERR_OLD_BROWSER       = 0
const ERR_KEY_ALREADY_EXIST = 1
const INVALID_CONFIG_FILE   = 2
const SERVICE_DONT_EXIST    = 3
const MASTER_KEY_DONT_EXIST = 4

const MSG = {}
MSG[ERR_OLD_BROWSER]       = "ERR_OLD_BROWSER"
MSG[ERR_KEY_ALREADY_EXIST] = "ERR_KEY_ALREADY_EXIST"
MSG[INVALID_CONFIG_FILE]   = "INVALID_CONFIG_FILE"
MSG[SERVICE_DONT_EXIST]    = "SERVICE_DONT_EXIST"
MSG[MASTER_KEY_DONT_EXIST] = "MASTER_KEY_DONT_EXIST"


class Error { 
    constructor (err_code) { 
        this.err_code = err_code
        console.error("[DPM ERROR] " + MSG[err_code])
    } 
} 