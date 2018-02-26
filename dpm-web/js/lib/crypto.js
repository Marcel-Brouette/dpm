function sha256(data, hex=true){ return hash("SHA-256", data, hex) }
function sha384(data, hex=true){ return hash("SHA-384", data, hex) }
function sha512(data, hex=true){ return hash("SHA-512", data, hex) }
function base64enc(data){ return window.btoa(data) }

function hash(algorithm, data, hex=true){
    // WARN : return promise ...
    data = utf8ToBuffer(data)
    return window.crypto.subtle.digest(algorithm, data).then(
        function(hash){
            if (hex){
                return bufferToHex(hash)
            }
            else {
                return hash
            }
        }, 
        function(){
            console.error("hash error")
        }
    )
}

function hexToBase64(hexstring) {
    return btoa(hexstring.match(/\w{2}/g).map(function(a) {
        return String.fromCharCode(parseInt(a, 16));
    }).join(""));
}

function utf8ToBuffer(str) {
    let binstr = utf8ToBinaryString(str)
    let buf    = binaryStringToBuffer(binstr)
    return buf
}

function bufferToBinaryString(buf) {
    let binstr = Array.prototype.map.call(buf, function (ch) {
      return String.fromCharCode(ch);
    }).join('');
  
    return binstr;
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
