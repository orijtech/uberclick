function Uber(params) {
  params = params || {};
  var el = document.getElementById(params.itemId);
  if (!el) {
      throw new Error('expecting a non-null bound element');
      return;
  }

  this.nonceCookieKey = 'uberclick-nonce';
  this.baseURL = 'http://localhost:9899';
  // this.baseURL = 'https://uberclick.orijtech.com';
  this.init(el);
}

Uber.prototype.init = function(el) {
    // First step is to invoke the backend
    var apiKey = el.getAttribute('data-apikey');
    this.apiKey = apiKey;
    if (!(apiKey && apiKey.length > 0)) {
      throw new Error('expecting an API key');
      return;
    } 

    el.innerHTML = '<button style="max-width:14vw; max-height:6.0vh; min-height: 4vh; min-width:8vw; background-color: Transparent;"><svg viewBox="-8 -2 95 20" width="100%" height="100%" ><g><title>Uber one click</title><g><path fill="#09091A" d="M12.5839109,0.5531071v9.2070246c0,3.0744829-1.3608532,4.3512774-4.5529118,4.3512774 c-3.1923466,0-4.5532475-1.2767944-4.5532475-4.3512774v-9.610198H0.4031733C0.1345027,0.1499339,0,0.2844366,0,0.5531071 v9.3581429c0,5.1411524,3.2761652,6.9388151,8.0309992,6.9388151c4.7545462,0,8.0307112-1.7976627,8.0307112-6.9388151V0.1499339 h-3.0745783C12.7184143,0.1499339,12.5839109,0.2844366,12.5839109,0.5531071z"></path><path fill="#09091A" d="M57.1541595,2.8212435c0.2519836,0,0.3696556-0.0838192,0.4535713-0.2686944l0.8906403-2.2010524 c0.0504456-0.1341919,0-0.2015627-0.1346436-0.2015627H45.9814034c-1.1591721,0-1.5957184,0.3527766-1.5957184,1.1425314 v14.2975407c0,0.6720123,0.335659,0.9744625,1.2263489,0.9744625h11.5421257c0.2519836,0,0.3696556-0.0841522,0.4535713-0.2687416 l0.8906403-2.2010527c0.0504456-0.1344786,0-0.2015629-0.1346436-0.2015629H47.8129425v-2.9066296 c0-1.0080519,0.5544586-1.4617653,2.0495758-1.4617653h4.5699348c0.2520294,0,0.3694153-0.0837717,0.4535713-0.2686234 l0.8569794-2.1169939c0.0503006-0.1345029,0-0.2015629-0.1346436-0.2015629h-7.7954178v-4.116293H57.1541595z"></path></g><path fill="#09091A" d="M35.3563614,7.9118795c1.3438797-0.7056007,1.8982925-2.0328403,1.8982925-3.5952325 c0-3.6289654-2.9567184-4.1667132-6.0145607-4.1667132h-6.9892597c-1.1592674,0-1.5958633,0.3527766-1.5958633,1.1425314 v14.2975407c0,0.6720123,0.3358021,0.9744625,1.2263508,0.9744625h8.6021461c3.2424545,0,5.5609398-1.2600594,5.5609398-4.5362244 C38.0444069,10.0624876,37.2042542,8.3991585,35.3563614,7.9118795z M26.0485687,2.7541118h5.4435081 c1.8144722,0,2.3185349,0.6889615,2.3185349,2.1168747c0,1.4280329-0.5040627,2.1170182-2.3185349,2.1170182h-5.4435081V2.7541118z M32.1305923,13.9601955h-6.0820236v-3.0409174c0-1.008028,0.5544109-1.4615984,2.0498142-1.4615984h4.0322094 c1.9319992,0,2.4697227,0.7393103,2.4697227,2.2513533C34.6003151,13.2211246,34.0625916,13.9601955,32.1305923,13.9601955z"></path><path fill="#09091A" d="M79.9604492,16.2787285l-3.679245-6.3170338c1.8313522-0.4703054,3.3097305-1.6799688,3.3097305-4.7545233 c0-3.9818139-2.4698181-5.0572376-6.55233-5.0572376h-7.0226364c-1.159317,0-1.5961456,0.3527766-1.5961456,1.1425314v14.868782 c0,0.2686005,0.134407,0.4032211,0.4031677,0.4032211h2.9904251v-4.7882318c0-1.0080519,0.5544586-1.4617653,2.0498199-1.4617653 h3.040863l3.3266144,5.9812555c0.1006927,0.1678543,0.2015839,0.2687416,0.4535675,0.2687416h3.1250687 C80.0278625,16.5644684,80.0278625,16.3795223,79.9604492,16.2787285z M73.5426178,7.7606421h-5.7292023V2.7878211h5.7292023 c2.1336365,0,2.6041794,0.8231056,2.6041794,2.4864104C76.1467972,6.9542713,75.6762543,7.7606421,73.5426178,7.7606421z"></path></g></svg></button>';

    var keeper = this;
    el.addEventListener('click', function() {
      if (keeper.err)
	throw new Error(keeper.err);

      var req = new XMLHttpRequest();
      req.onreadystatechange = function() {
	var state = this;
	if (state.readyState === 4) {
	  if (state.status >= 200 && state.status <= 299) {
	    console.log(state.responseText);
	    var resp = JSON.parse(state.responseText);
	    if (resp.url) {
	      window.location = resp.url;
	    } else {
	      console.log('my profile ', resp);
	      viewPage('/map.html?key=newone');
	    }

	    // viewPage('/map.html?key=newone');
	  } else {
	    alert('failed to parse data ' + state.responseText + ' state ' + state.readyState);
	  }
	}
      };

      req.open('POST', keeper.baseURL + '/profile?key=bonjourne', true);
      req.setRequestHeader('Content-Type', 'application/json');

      req.send(JSON.stringify({
	api_key: keeper.apiKey,
	origin: document.location.origin,
      }));
    });

    var req = new XMLHttpRequest();
    req.onreadystatechange = function() {
      var state = this;
      if (state.readyState === 4) {
	console.log(state.responseText);
	if (state.status >= 200 && state.status <= 299) {
	  console.log(state.responseText);
	} else {
	  keeper.err = state.responseText;
	  alert('init error:: ' + state.responseText);
	}
      }
    };

    req.open('POST', keeper.baseURL + '/init', true);
    req.setRequestHeader('Content-Type', 'application/json');

    req.send(JSON.stringify({
      api_key: keeper.apiKey,
      origin: document.location.origin,
    }));
};

function viewPage(url) {
      var blankPage = document.createElement('div');
      blankPage.style = 'width: 95%;height: 95%;border: 5%;position: fixed;padding: 30px;background-size: cover;background-color: #FFFFFF;box-sizing: border-box;left: 0;top: 0;z-index: 10000;'
      document.body.append(blankPage);
	
      var el = document.createElement('div');
      el.setAttribute("class", "displayPage");

      var closeButton = document.createElement('button');
      closeButton.innerText = 'Close';

      var iframe = document.createElement('iframe');
      iframe.style = 'width: 100%; height: 100%';
      iframe.src   = url;
      el.append(closeButton);
      el.append(iframe);

      blankPage.append(el);

      closeButton.onclick = function() {
	el.innerHTML = '';
	blankPage.removeChild(el);
	document.body.removeChild(blankPage);
      };
}

Uber.prototype.click = function() {
    console.log('clicked!');
};

Uber.prototype.getNonceCookie = function() {
    return this.getCookie(this.nonceCookieKey);
}

Uber.prototype.getCookie = function(key) {
    var decodedCookie = decodeURIComponent(document.cookie);
    var splits = decodedCookie.split(';');
    console.log('decodedCookie ', decodedCookie);

    var keyWithEquals = key + '=';
    for (var i=0; i < splits.length; i++) {
      var split = (splits[i]).trim();

      if (split.indexOf(keyWithEquals) === 0)
	return split.substring(keyWithEquals.length, split.length);
    }

    return '';
};

Uber.prototype.clearCookie = function(key) {
    document.cookie = key + '; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';
};

Uber.prototype.invalidateNonceCookie = function(nonce) {
    this.clearCookie(this.nonceCookieKey+'='+nonce);
};
