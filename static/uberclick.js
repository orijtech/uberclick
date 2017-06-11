(function() {
  function Uber() {
    console.log("uber init!!");
    var buttonItem =  document.getElementById('uber-one-click');
    // First step is to invoke the backend
    var apiKey = buttonItem.getAttribute('data-apikey');
    this.apiKey = apiKey;
    if (!(apiKey && apiKey.length > 0)) {
      throw new Error('expecting an API key');
      return;
    } 

    var keeper = this;
    var req = new XMLHttpRequest();
    req.onreadystatechange = function() {
      var state = this;
      if (state.readyState === 4) {
	if (state.status >= 200 && state.status <= 299) {
	  var resp = JSON.parse(state.responseText);
	  keeper.nonce = resp.nonce;
	  console.log('nonce ' + keeper.nonce);
	} else {
	  alert('failed to parse data ' + state.responseText + ' state ' + state.readyState);
	}
      }
    };

    req.open('POST', 'http://localhost:9899/init', true);
    req.setRequestHeader('Content-Type', 'application/json');

    req.send(JSON.stringify({
      api_key: apiKey,
      domain: document.location.origin,
    }));
  }

  var trigger = new Uber();
  console.log('Invoked %s', trigger);
}())
