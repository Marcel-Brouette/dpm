// TODO : 
// function action(App.function, arg){
//  
// }

let ui = new Vue({
  el: '#app',
  data: {
    model: App.getConfig(),
    test: ''
  }, 
  methods : {
    handleFileSelect : function(evt){
      let list_files = evt.target.files
      for (let file of list_files) {
        handleContentFile(file, function (content){
          console.log(content)
        })
      }
    },
    newMasterKey : function(evt){
      console.log(this.new_key_name)
    }
  }

})

sha256("tutu").then((val) => {ui.test = val})