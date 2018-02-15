function sha256(data){ return hash("SHA-256", data) }
function sha384(data){ return hash("SHA-384", data) }
function sha512(data){ return hash("SHA-512", data) }

function hash(algorithm, data){
    // WARN : return promise ...
    data = utf8ToBuffer(data)
    return window.crypto.subtle.digest(algorithm, data).then(
        function(hash){
            return bufferToHex(hash)
        }, 
        function(){
            console.error("hash error")
        }
    )
}

function utf8ToBuffer(str) {
    let binstr = utf8ToBinaryString(str)
    let buf    = binaryStringToBuffer(binstr)
    return buf
}

function binaryStringToBuffer(binstr) {
    let buf
    if ('undefined' !== typeof Uint8Array) {
      buf = new Uint8Array(binstr.length)
    } else {
      buf = []
    }
  
    Array.prototype.forEach.call(binstr, function (ch, i) {
      buf[i] = ch.charCodeAt(0)
    })
  
    return buf
}

function utf8ToBinaryString(str) {
    let escstr = encodeURIComponent(str)
    // replaces any uri escape sequence, such as %0A,
    // with binary escape, such as 0x0A
    return escstr.replace(
        /%([0-9A-F]{2})/g, 
        function(match, p1) {
            return String.fromCharCode(parseInt(p1, 16));
        }
    )
}

function bufferToHex(buffer) {
    return Array.prototype.map.call(
        new Uint8Array(buffer), 
        x => ('00' + x.toString(16)).slice(-2)
    ).join('');
}
