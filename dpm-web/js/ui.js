// TODO : 
// function action(App.function, arg){
//  
// }


let ui = new Vue({
  el: '#app',
  data: {
    model: App.getConfig(),
    current_app_name: "",
    current_app_config: {},
    generate_pwd : ""
  }, 
  computed: {
    apps_completion : function(){
      let ret_value = []
      for(let current_key in this.model.services){
        ret_value.push({key: current_key, text: current_key, render: current_key})
      }
      return ret_value
    }
  },
  methods : {
    handleFileSelect : function(evt){
      let list_files = evt.target.files
      for (let file of list_files) {
        handleContentFile(file, function (content){
          App.loadConfig(content)
        })
      }
    },
    newMasterKey : function(evt){
      let pwd1 = this.$refs.new_key_pwd.value
      let pwd2 = this.$refs.new_key_pwd_confirm.value
      let name = this.$refs.new_key_name.value
      if(pwd1 == pwd2 && name.trim().length > 3){
        App.newMasterKey(name, pwd1)
      }
    },
    clearPersistentData : function(evt){
      App.clearConfig()
    },
    loadApp : function(value){
      this.current_app_name = value
      this.current_app_config = this.model.services[value]
    }, 
    generatePwd : function(master_pass){
      App.generatePwd(this.current_app_name, master_pass).then(
        (generatePass) => {this.generate_pwd = generatePass}
      )
    }
  },
  filters: {
    pretty: function(value) {
      return JSON.stringify(value, null, 2);
    }
  }

})
