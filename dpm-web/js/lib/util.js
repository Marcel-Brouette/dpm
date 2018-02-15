function handleContentFile (file, contentHandler){
    let freader = new FileReader()
    freader.onload = function(event) { contentHandler(freader.result) }
    freader.readAsText(file)
}

function localStorageIsEnable(){
    var test = 'test';
    try {
        localStorage.setItem(test, test);
        localStorage.removeItem(test);
        return true;
    } catch(e) {
        return false;
    }
}