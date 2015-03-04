

function generate(passwordSource){
	var password;
		if(passwordSource == "custom"){
			password = document.getElementById("customPassword").value;
		} else {
			password = CryptoJS.lib.WordArray.random(128/8).toString();
		}

	var request = new XMLHttpRequest();
	request.open('POST', '/chat/create/', true);
	request.setRequestHeader("Content-type", "application/x-www-form-urlencoded");

	request.onload = function() {
	  if (request.status >= 200 && request.status < 400) {
	    var resp = request.responseText;
	    var resultMsg = resp +  "<br><br>" + "The password is: " + password;
		document.getElementById("result").style.visibility = "visible";
		document.getElementById("finishedMessage").innerHTML = resultMsg;
	  } else {
	  	//Error
	  }
	};

	request.onerror = function() {
	  //Error
	};

	request.send();

	return false;
}
