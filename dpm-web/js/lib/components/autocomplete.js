Vue.component('autocomplete', {
  template : ' \
      <div style="position:relative" v-bind:class="{\'open\':openSuggestion}"> \
        <input class="input-completion" type="text" :value="value" \
          @input="updateValue($event.target.value)"\
          @keydown.enter = \'enter\'\
          @keydown.down = \'down\'\
          @keydown.up = \'up\'\
          @keydown.esc = \'closeCompletion\'\
        >\
        <ul v-if=open class="dropdown-menu">\
            <li v-for="(suggestion, index) in matches"\
                v-bind:class="{\'active\': isActive(index)}"\
                @click="suggestionClick(index)" >\
              <span v-html="suggestion.render"></span>\
            </li>\
        </ul>\
      </div>',
  props: {
    value:       { type: String, required: true },
    suggestions: { type: Array,  required: true }
  },
  data () {
    return { open: false, current: 0 }
  },
  computed: {
    // Filtering the suggestion based on the input
    matches () {
      return this.suggestions.filter((obj) => {
        return obj.text.indexOf(this.value) >= 0
      }).slice(0, 10)
    },
    openSuggestion () {
      return this.selection !== '' &&
             this.matches.length !== 0 &&
             this.open === true
    }
  },
  methods: {
    updateValue (value) {
      this.open = value.trim ().length > 0
      this.current = 0
      this.$emit('input', value)
    },
    // When enter pressed on the input
    enter () {
      this.selectValue(this.matches[this.current].text)
    },
    // When up pressed while suggestions are open
    up () {
      this.current = (this.current + this.matches.length - 1) % this.matches.length
    },
    // When up pressed while suggestions are open
    down () {
      this.current = (this.current + this.matches.length + 1) % this.matches.length
    },
    // For highlighting element
    isActive (index) {
      return index === this.current
    },
    // When one of the suggestion is clicked
    suggestionClick (index) {
      this.selectValue(this.matches[index].text)
    }, 
    selectValue (value){
      this.$emit('change', value)
      this.$emit('input',  value)
      this.closeCompletion()
    }, 
    closeCompletion(){
      this.open = false
    },

  }
})