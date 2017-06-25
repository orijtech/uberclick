$(function() {
  const nonceCookieKey = 'uber-nonce';
  function Uber(params) {
    params = params || {};
    var el = document.getElementById(params.itemId);
    if (!el) {
      throw new Error('expecting a non-null bound element');
      return;
    }

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

    el.innerHTML = '<button style="max-width:16vw; max-height:7.0vh; min-height: 6vh; min-width:10vw; background-color: Transparent;"><svg viewBox="-8 -2 95 20" width="100%" height="100%" ><g><title>Uber one click</title><g><path fill="#09091A" d="M12.5839109,0.5531071v9.2070246c0,3.0744829-1.3608532,4.3512774-4.5529118,4.3512774 c-3.1923466,0-4.5532475-1.2767944-4.5532475-4.3512774v-9.610198H0.4031733C0.1345027,0.1499339,0,0.2844366,0,0.5531071 v9.3581429c0,5.1411524,3.2761652,6.9388151,8.0309992,6.9388151c4.7545462,0,8.0307112-1.7976627,8.0307112-6.9388151V0.1499339 h-3.0745783C12.7184143,0.1499339,12.5839109,0.2844366,12.5839109,0.5531071z"></path><path fill="#09091A" d="M57.1541595,2.8212435c0.2519836,0,0.3696556-0.0838192,0.4535713-0.2686944l0.8906403-2.2010524 c0.0504456-0.1341919,0-0.2015627-0.1346436-0.2015627H45.9814034c-1.1591721,0-1.5957184,0.3527766-1.5957184,1.1425314 v14.2975407c0,0.6720123,0.335659,0.9744625,1.2263489,0.9744625h11.5421257c0.2519836,0,0.3696556-0.0841522,0.4535713-0.2687416 l0.8906403-2.2010527c0.0504456-0.1344786,0-0.2015629-0.1346436-0.2015629H47.8129425v-2.9066296 c0-1.0080519,0.5544586-1.4617653,2.0495758-1.4617653h4.5699348c0.2520294,0,0.3694153-0.0837717,0.4535713-0.2686234 l0.8569794-2.1169939c0.0503006-0.1345029,0-0.2015629-0.1346436-0.2015629h-7.7954178v-4.116293H57.1541595z"></path></g><path fill="#09091A" d="M35.3563614,7.9118795c1.3438797-0.7056007,1.8982925-2.0328403,1.8982925-3.5952325 c0-3.6289654-2.9567184-4.1667132-6.0145607-4.1667132h-6.9892597c-1.1592674,0-1.5958633,0.3527766-1.5958633,1.1425314 v14.2975407c0,0.6720123,0.3358021,0.9744625,1.2263508,0.9744625h8.6021461c3.2424545,0,5.5609398-1.2600594,5.5609398-4.5362244 C38.0444069,10.0624876,37.2042542,8.3991585,35.3563614,7.9118795z M26.0485687,2.7541118h5.4435081 c1.8144722,0,2.3185349,0.6889615,2.3185349,2.1168747c0,1.4280329-0.5040627,2.1170182-2.3185349,2.1170182h-5.4435081V2.7541118z M32.1305923,13.9601955h-6.0820236v-3.0409174c0-1.008028,0.5544109-1.4615984,2.0498142-1.4615984h4.0322094 c1.9319992,0,2.4697227,0.7393103,2.4697227,2.2513533C34.6003151,13.2211246,34.0625916,13.9601955,32.1305923,13.9601955z"></path><path fill="#09091A" d="M79.9604492,16.2787285l-3.679245-6.3170338c1.8313522-0.4703054,3.3097305-1.6799688,3.3097305-4.7545233 c0-3.9818139-2.4698181-5.0572376-6.55233-5.0572376h-7.0226364c-1.159317,0-1.5961456,0.3527766-1.5961456,1.1425314v14.868782 c0,0.2686005,0.134407,0.4032211,0.4031677,0.4032211h2.9904251v-4.7882318c0-1.0080519,0.5544586-1.4617653,2.0498199-1.4617653 h3.040863l3.3266144,5.9812555c0.1006927,0.1678543,0.2015839,0.2687416,0.4535675,0.2687416h3.1250687 C80.0278625,16.5644684,80.0278625,16.3795223,79.9604492,16.2787285z M73.5426178,7.7606421h-5.7292023V2.7878211h5.7292023 c2.1336365,0,2.6041794,0.8231056,2.6041794,2.4864104C76.1467972,6.9542713,75.6762543,7.7606421,73.5426178,7.7606421z"></path></g></svg></button>';

    var keeper = this;
    el.addEventListener('click', function() {
      console.log('onClick:: nonce here: ', keeper.nonce);
      var req = new XMLHttpRequest();
      req.onreadystatechange = function() {
	var state = this;
	if (state.readyState === 4) {
	  if (state.status >= 200 && state.status <= 299) {
	    console.log(state.responseText);
	    var resp = JSON.parse(state.responseText);
	    if (resp.url) {
	      clearNonceCooke(keeper.nonce);
	      var iframe = document.createElement('iframe');
	      iframe.src = resp.url;
	      document.body.append(iframe);
	    } else {
	      console.log('my profile ', resp);
	    }
	  } else {
	    alert('failed to parse data ' + state.responseText + ' state ' + state.readyState);
	  }
	}
      };

      req.open('POST', 'http://localhost:9899/profile', true);
      req.setRequestHeader('Content-Type', 'application/json');

      req.send(JSON.stringify({
	nonce: keeper.nonce,
	origin: document.location.origin,
      }));
    });

    var dataCallback = el.getAttribute('data-callback');
    console.log('dataCallback ' + dataCallback);

    var nonce = getCookie(nonceCookieKey);
    console.log('retrieved nonce: %s', nonce);
    if (!(nonce && nonce.length > 0)) {
      var keeper = this;
      generateNonce(keeper);
      nonce = getCookie(nonceCookieKey);
    }

    this.nonce = nonce;
  }

  Uber.prototype.click = function() {
    console.log('clicked!');
  };

  var trigger = new Uber({'itemId': 'uber-one-click'});
  console.log('Invoked %s', trigger);

  function getCookie(key) {
    var decodedCookie = decodeURIComponent(document.cookie);
    var splits = decodedCookie.split(';');

    var keyWithEquals = key + '=';
    for (var i=0; i < splits.length; i++) {
      var split = (splits[i]).trim();

      if (split.indexOf(keyWithEquals) === 0)
	return split.substring(keyWithEquals.length, split.length);
    }

    return '';
  }

  function clearCookie(key) {
    document.cookie = key + '; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';
  }

  function clearNonceCooke(nonce) {
    clearCookie(nonceCookieKey+'='+nonce);
  }

  function generateNonce(keeper) {
    var req = new XMLHttpRequest();
    req.onreadystatechange = function() {
      var state = this;
      if (state.readyState === 4) {
	if (state.status >= 200 && state.status <= 299) {
	  var resp = JSON.parse(state.responseText);
	  keeper.nonce = resp.nonce;
	  document.cookie = nonceCookieKey + '=' + keeper.nonce;
	  console.log('setting nonce ' + keeper.nonce);
	} else {
	  alert('failed to parse data ' + state.responseText + ' state ' + state.readyState);
	}
      }
    };

    req.open('POST', 'http://localhost:9899/init', true);
    req.setRequestHeader('Content-Type', 'application/json');

    req.send(JSON.stringify({
      api_key: keeper.apiKey,
      origin: document.location.origin,
    }));
  }
});

function generateDialog() {
  var el = `
    <div id="order-container" style="width:100%;height:100%">
      <style>
	#uber-map {
	  height: 100%;
	  width: 100%;
	}

	.uber-one-click: {
	  background-image: url(/assets/uber_rides_api_icon.svg);
	}
      </style>

      <div id='start'>
	<input id='start-input' class='uber-search-inputs' type='text' placeholder='Start'>
	</input>
      </div>
      <br />
      <div id='end'>
	<input id='end-input' class='uber-search-inputs' type='text' placeholder='End'>
	</input>
      </div>

      <div id="uber-map"></div>
      <button id="order"></button>
    </div>

    <script>
      var map, infoWindow;
      var points = {start: null, end: null};
      var lineSymbol = {};

      function initMap() {
	
	infoWindow = new google.maps.InfoWindow;

	// Now for geolocation
	if (!navigator.geolocation) {
	  map = new google.maps.Map(document.getElementById('uber-map'), {
	    center: {lat: -34.397, lng: 150.644},
	    zoom: 8
	  });
	  handleLocationError(false, infoWindow, map.getCenter());
	  initAutocomplete();
	} else {
	  navigator.geolocation.getCurrentPosition(function(position) {
	    var pos = {
	      lat: position.coords.latitude,
	      lng: position.coords.longitude,
	    };
	    
	    map = new google.maps.Map(document.getElementById('uber-map'), {
	      center: pos,
	      zoom: 8
	    });

	    // infoWindow.setPosition(pos);
	    // infoWindow.setContent('Your current location');
	    // infoWindow.open(map);
	    points['start'] = pos;

	    var icon = {
	      url: './assets/Pin.png',
	      size: new google.maps.Size(70, 70),
	      origin: new google.maps.Point(0, 0),
	      anchor: new google.maps.Point(17, 34),
	      scaledSize: new google.maps.Size(25, 25),
	    };
	    
	    var startMarker = new google.maps.Marker({
		map: map,
		icon: icon,
		title: 'Start',
		position: pos,
	    })

	    map.setCenter(pos);
	    initAutocomplete();
	  }, function() {
	    map = new google.maps.Map(document.getElementById('uber-map'), {
	      center: {lat: -34.397, lng: 150.644},
	      zoom: 8
	    });
	    handleLocationError(true, infoWindow, map.getCenter());
	    initAutocomplete();
	  });
	}
      }

      function redrawPointsPath() {
	for (var key in points) {
	  // If any is null don't draw the line
	  if (!points[key])
	    return;
	}

	var line = new google.maps.Polyline({
	  path: [points.start, points.end],
	  icons: [{
	    icon: lineSymbol,
	    offset: '100%',
	  }],
	  map: map,
	});
      }

      function translateIndexToName(i) {
	if (i <= 0)
	  return 'start';
	return 'end';
      }

      function initAutocomplete() {
	var lineSymbol = {
	  path: google.maps.SymbolPath.FORWARD_OPEN_ARROW,
	  scale: 8,
	  strokeColor: '#493',
	};

	var searchElements = document.getElementsByClassName('uber-search-inputs') || [];
	for (var i=0; i < searchElements.length; i++) {
	  var el = searchElements[i];
	  var searchBox = new google.maps.places.SearchBox(el);

	  searchBox.posName = translateIndexToName(i);
	  searchBox.markers = [];
	  searchBox.addListener('places_changed', function() {
	    var places = this.getPlaces();
	    if (places.length === 0)
	      return;

	    var markers = this.markers || [];
	    // Clear out old markers
	    markers.forEach(function(marker) {
	      marker.setMap(null);
	    });
	    markers = [];

	    var posName = this.posName;
	    var bounds = new google.maps.LatLngBounds();
	    places.forEach(function(place) {
	      if (!place.geometry) {
		return;
	      }

	      var icon = {
		url: './assets/Pin.png',
		size: new google.maps.Size(70, 70),
		origin: new google.maps.Point(0, 0),
		anchor: new google.maps.Point(17, 34),
		scaledSize: new google.maps.Size(25, 25),
	      };

	      markers.push(new google.maps.Marker({
		map: map,
		icon: icon,
		title: place.name,
		position: place.geometry.location,
	      }));

	      if (place.geometry.viewport) {
		bounds.union(place.geometry.viewport);
	      } else {
		bounds.extend(place.geometry.location);
	      }

	      points[posName] = place.geometry.location;
	      console.log(posName);
	      redrawPointsPath();
	    });

	    this.markers = markers;
	    map.fitBounds(bounds);
	  });
	}
      }

      function handleLocationError(allowsGeoLocation, infoWindow, pos) {
	infoWindow.setPosition(pos);
	infoWindow.setContent(allowsGeoLocation ?
		      'Geolocation failed' :
		      'Your browser does not support geolocation');
	infoWindow.open(map);
      }
    </script>
    <script src="https://maps.googleapis.com/maps/api/js?key=AIzaSyBCPNOYk3Fm1XtndKmdqc8uj0zWAV-joZs&callback=initMap&libraries=places" async defer></script>
  `;

  return el;
}
