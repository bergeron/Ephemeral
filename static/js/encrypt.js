
function choosePwd(){
	document.getElementById("encryptBox").style.display = "block";
}

function encrypt(message, passwordSource){

	try{
		var password;
		if(passwordSource == "custom"){
			password = document.getElementById("customPassword").value;
		} else {
			password = CryptoJS.lib.WordArray.random(128/8).toString();
		}

		var salt = CryptoJS.lib.WordArray.random(128/8).toString();
		var key = CryptoJS.PBKDF2(password, salt, { keySize: 128/32 }).toString();
		var encryptedText = CryptoJS.AES.encrypt(message, key).toString();

		var expireMinutes = document.getElementById("expireMinutes").value;
		var params = "text=" + encodeURIComponent(encryptedText) + "&expireMinutes=" 
						+ encodeURIComponent(expireMinutes) + "&salt=" + salt;

		var request = new XMLHttpRequest();
		request.open('POST', '/create/client/', true);
		request.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
		request.onload = function() {
			if (request.status >= 200 && request.status < 400) {
				var resp = request.responseText;
				var resultMsg = "I have a message for you at: " + resp + "<br><br>" + "The password is: " + password;
				document.getElementById("finishedMessage").innerHTML = resultMsg;
				document.getElementById("result").style.visibility="visible";
			} else {
		  	//Error
		  }
		};
		request.onerror = function() {
		  //Error
		};

		request.send(params);
	} catch (e) {console.log(e)}
	
	return false;
}
