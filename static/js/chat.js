/* chat.js */

var key;
var salt;
var password;
var chatroomId = document.URL.substring(document.URL.indexOf("/chat/") + 6);
var dtUpdateAfter = "";
var nicknameId;
var nicknames = [];
var colors = [];

function create(nickname, passwordSource){

	try{
		if(passwordSource == "custom"){
			password = document.getElementById("customPassword").value;
		} else {
			password = CryptoJS.lib.WordArray.random(128/8).toString();
		}

		salt = CryptoJS.lib.WordArray.random(128/8).toString();
		key = CryptoJS.PBKDF2(password, salt, { keySize: 128/32 }).toString();
		var encryptedNickname = CryptoJS.AES.encrypt(nickname, key).toString();
		var encryptedWelcome =  CryptoJS.AES.encrypt("has joined the chat", key).toString();
		var params = "encryptedNickname=" + encodeURIComponent(encryptedNickname) + "&salt=" + encodeURIComponent(salt)
					+ "&encryptedWelcome=" + encodeURIComponent(encryptedWelcome);

		var request = new XMLHttpRequest();
		request.open('POST', '/chat/create/', true);
		request.setRequestHeader("Content-type", "application/x-www-form-urlencoded");

		request.onload = function() {
			if (request.status >= 200 && request.status < 400) {
				var resp = JSON.parse(request.responseText);
				nicknameId = resp.NicknameId;
				chatroomId = resp.ChatroomId;

				document.getElementById("chatRoom").style.display = "block";
				document.getElementById("encryptBox").style.display = "none";
				document.getElementById("chatInstructions").style.display = "none";
				document.getElementById("chatPrompt").style.display = "block";
				document.getElementById("promptPwd").value = password;
				document.getElementById("promptPwd").disabled = true;
				document.getElementById("promptNickname").disabled = true;
				document.getElementById("promptNickname").value = nickname;
				document.getElementById("openChatBtn").style.display = "none";
				document.getElementById("inviteBtn").style.display = "block";
				document.getElementById("inviteInstructions").style.display = "block";

				addNicknameIfNew(nickname);
				// messageToHTML(nickname, " has joined the chat");
				setInterval(update, 5000);

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

function openChat(pwd, nickname){

	try{
		password = pwd;
		key = CryptoJS.PBKDF2(password, salt, { keySize: 128/32 }).toString();

		encryptedNicknames.forEach(function(e){
			addNicknameIfNew(CryptoJS.AES.decrypt(e, key).toString(CryptoJS.enc.Utf8));
		});
				
		setNickname(nickname, function(resp){
			nicknameId = resp.NicknameId;
			addNicknameIfNew(nickname);

			document.getElementById("chatRoom").style.display = "block";
			document.getElementById("promptPwd").disabled = true;
			document.getElementById("promptNickname").disabled = true;
			document.getElementById("openChatBtn").style.display = "none";
			document.getElementById("inviteBtn").style.display = "block";
			document.getElementById("inviteInstructions").style.display = "block";
			setInterval(update, 5000);


		});

	} catch (e) {console.log(e)}

	return false;
}

function sendMsg(message){
	try {

		document.getElementById("messageText").value = "";
		var encryptedText = CryptoJS.AES.encrypt(message, key).toString();
		var params = "nicknameId=" + encodeURIComponent(nicknameId) + "&encryptedText=" + encodeURIComponent(encryptedText)
						+ "&chatroomId=" + encodeURIComponent(chatroomId);

		var request = new XMLHttpRequest();
		request.open('POST', '/chat/addMsg/', true);
		request.setRequestHeader("Content-type", "application/x-www-form-urlencoded");

		request.onload = function() {
			if (request.status >= 200 && request.status < 400) {
			} else {
			  	//Error
			  }
			};

		request.onerror = function() {
			  //Error
		};

		request.send(params);

	} catch (e) {console.log(e);}

	return false;
}

function setNickname(nickname, fn){

	var encryptedNickname = CryptoJS.AES.encrypt(nickname, key).toString();
	var encryptedWelcome =  CryptoJS.AES.encrypt("has joined the chat", key).toString();
	var params = "encryptedNickname=" + encodeURIComponent(encryptedNickname) + "&chatroomId="
				+ encodeURIComponent(chatroomId) + "&encryptedWelcome=" + encodeURIComponent(encryptedWelcome);

	var request = new XMLHttpRequest();
	request.open('POST', '/chat/setNickname/', true);
	request.setRequestHeader("Content-type", "application/x-www-form-urlencoded");

	request.onload = function() {
		if (request.status >= 200 && request.status < 400) {
			fn(JSON.parse(request.responseText));
		} else {
		  	//Error
		}
	};

	request.onerror = function() {
		//Error
	};

	request.send(params);
}

function update(){

	var params = "chatroomId=" + encodeURIComponent(chatroomId) + "&dtUpdateAfter=" + encodeURIComponent(dtUpdateAfter);
	var request = new XMLHttpRequest();
	request.open('GET', '/chat/update/?'+ params, true);
	request.setRequestHeader("Content-type", "application/x-www-form-urlencoded");

	request.onload = function() {
		if (request.status >= 200 && request.status < 400) {
			var resp = JSON.parse(request.responseText);
			console.log(resp);
			dtUpdateAfter = resp.DtUpdateAfter;
			resp.Messages.forEach(decryptMessage);

		} else {
		  	//Error
		}
	};

	request.onerror = function() {
		//Error
	};

	request.send();
}


function decryptMessage(msg){

	var nickname = CryptoJS.AES.decrypt(msg.EncryptedNickname, key).toString(CryptoJS.enc.Utf8);
	var text = CryptoJS.AES.decrypt(msg.EncryptedText, key).toString(CryptoJS.enc.Utf8);
	addNicknameIfNew(nickname);
	messageToHTML(nickname, text);
}



function messageToHTML(nickname, text){
	var color = colors[nicknames.indexOf(nickname)];
	var messageHTML = '' +
	'<div class="chatMsg">' +
		'<span class="nickname" style="color: #' + color + ';">' +
			nickname + ": " + 
		'</span>' +
		'<span class="msgText">' +
			text +
		'</span>' +
	'</div>';

	var messagesDiv = document.getElementById("messages").innerHTML += messageHTML;

	var chatRoomWindow = document.getElementById("chatRoomWindow");
	chatRoomWindow.scrollTop = chatRoomWindow.scrollHeight	/* Scroll to bottom when message added */
}

function addNicknameIfNew(nickname){
	if(nicknames.indexOf(nickname) == -1){
		nicknames.push(nickname);
		var color = randDarkColor();
		colors.push(color);
		document.getElementById("membersUl").innerHTML += '<li style="color:#' + color + '">' + nickname + '</li>';
	}
}

function randDarkHex() {
    var hex = (Math.floor(Math.random() * 175)).toString(16);
    while(hex.length < 2){
    	hex = "0" + hex;
    }
    return hex;
}

function randDarkColor() {
    return randDarkHex() + "" + randDarkHex() + "" + randDarkHex();
}

function invite(){

	var params = "chatroomId=" + encodeURIComponent(chatroomId);
	var request = new XMLHttpRequest();
	request.open('POST', '/invite/', true);
	request.setRequestHeader("Content-type", "application/x-www-form-urlencoded");

	request.onload = function() {
		if (request.status >= 200 && request.status < 400) {
			var inviteId = request.responseText;
			var inviteURL = "localhost:11994/invite/" + inviteId;
			document.getElementById("inviteBtn").innerHTML="Regenerate Invite URL";
			document.getElementById("inviteWell").innerHTML = "Join the chat at: " + inviteURL + "<br><br>The password is: " + password;
			document.getElementById("inviteWell").style.display = "block";
		} else {
		  	//Error
		}
	};

	request.onerror = function() {
		//Error
	};

	request.send(params);
}
