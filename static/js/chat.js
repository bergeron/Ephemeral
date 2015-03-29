/* chat.js */

var socket;
var key;
var salt;
var password;
var chatroomId = $(location).attr('pathname').substring(6);
var nicknameId;
var nicknames = [];
var colors = [];


if (!window['WebSocket']) {
	alert('Your browser does not support WebSockets. Ephemeral chat requires WebSockets');
}

function create(nickname, passwordSource){

	try{
		if(passwordSource == 'custom'){
			password = $('#customPassword').val();
		} else {
			password = CryptoJS.lib.WordArray.random(128/8).toString();
		}

		salt = CryptoJS.lib.WordArray.random(128/8).toString();
		key = CryptoJS.PBKDF2(password, salt, { keySize: 128/32 }).toString();
		var encryptedNickname = CryptoJS.AES.encrypt(nickname, key).toString();

		$.ajax({
			method: 'POST',
			url: '/chat/create/',
			data: {
				encryptedNickname: 	encryptedNickname,
				salt: 				salt
			}
		})
		.done(function(data) {
			nicknameId = data.NicknameId;
			chatroomId = data.ChatroomId;

			$('#encryptBox').hide();
			$('#chatInstructions').hide();
			$('#openChatBtn').hide();

			$('#chatPrompt').show();
			$('#chatRoom').show();
			$('#inviteBtn').show();
			$('#inviteInstructions').show();

			$('#promptPwd').val(password);
			$('#promptPwd').prop('disabled', true);
			$('#promptNickname').val(nickname);
			$('#promptNickname').prop('disabled', true);

			addMember(nickname);
			openWebSocket();
		})
		.fail(function(status, err){
			console.log(status + ' ' + err);
		});


	} catch (e) {console.log(e)}

	return false;
}

function openChat(pwd, nickname){
	try{
		password = pwd;
		key = CryptoJS.PBKDF2(password, salt, { keySize: 128/32 }).toString();

		for(var i=0; i < encryptedNicknames.length; i++){
			addMember(CryptoJS.AES.decrypt(encryptedNicknames[i], key).toString(CryptoJS.enc.Utf8));
		}

		/* Duplicate nickname */
		var origNickname = nickname;
		var dupes = 0;
		for(var i=0; i < nicknames.length; i++){
			if(nicknames[i] == nickname){
				nickname = origNickname + '(' + (dupes+1) + ')';
				dupes ++;
				i=0;
			}
		}
				
		setNickname(nickname, function(){
			 openWebSocket();
		});

	} catch (e) {console.log(e)}

	return false;
}

function openWebSocket(){

	socket = new WebSocket('wss://ephemeral.pw/chat/ws?chatroomId=' + chatroomId);
    socket.onopen = function(event){
		sendMsg('has joined the chat');
    }
    socket.onmessage = function(event) {
    	var data = JSON.parse(event.data);

    	if(data.Type == 'newMessage'){
			var nickname = CryptoJS.AES.decrypt(data.EncryptedNickname, key).toString(CryptoJS.enc.Utf8);
			var text = CryptoJS.AES.decrypt(data.EncryptedText, key).toString(CryptoJS.enc.Utf8);
			messageToHTML(nickname, text);
		} else if(data.Type == 'newMember'){
			var nickname = CryptoJS.AES.decrypt(data.EncryptedNickname, key).toString(CryptoJS.enc.Utf8);
			addMember(nickname);
		}
    }
    socket.onclose = function(event) {
        console.log('Connection closed');
    }
}

function sendMsg(message){
	try {

		if(message.length > 2700){
			alert('Maximum message length is 2700');
			return false;
		} else if (!socket) {
			return false;
		}

		var encryptedText = CryptoJS.AES.encrypt(message, key).toString();
		var msg = {
			chatroomId: 	chatroomId,
			encryptedText: 	encryptedText,
			nicknameId: 	nicknameId
		};

		socket.send(JSON.stringify(msg));
		$('#messageText').val('');

	} catch (e) {console.log(e);}

	return false;
}

function setNickname(nickname, fn){

	var encryptedNickname = CryptoJS.AES.encrypt(nickname, key).toString();

	$.ajax({
		method: 'POST',
		url: '/chat/setNickname/',
		data: {
			chatroomId: 		chatroomId,
			encryptedNickname: 	encryptedNickname
		}
	})
	.done(function(data) {
		nicknameId = data;

		$('#openChatBtn').hide();
		$('#promptPwd').prop('disabled', true);
		$('#promptNickname').prop('disabled', true);
		$('#chatRoom').show();
		$('#inviteBtn').show();
		$('#inviteInstructions').show();

		addMember(nickname);
		fn();
	})
	.fail(function(status, err){
		console.log(status + ' ' + err);
	});

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

	$('#messages').append(messageHTML);

	var chatWindow = $('#chatRoomWindow');
	chatWindow.scrollTop(chatWindow.prop('scrollHeight'));	/* Scroll to bottom when message added */
}

function addMember(nickname){
	nicknames.push(nickname);
	var color = randDarkColor();
	colors.push(color);
	$('#membersUl').append('<li style="color:#' + color + '">' + nickname + '</li>');
}

function randDarkColor() {
	var randDarkHex = function() {
		var hex = (Math.floor(Math.random() * 175)).toString(16);
		while(hex.length < 2){
			hex = '0' + hex;
		}
		return hex;
	}
	return randDarkHex() + '' + randDarkHex() + '' + randDarkHex();
}

function invite(){

	$.ajax({
		method: 'POST',
		url: '/invite/',
		data: {
			chatroomId: 	chatroomId
		}
	})
	.done(function(inviteId) {
		var inviteURL = 'https://ephemeral.pw/invite/' + inviteId;
		$('#inviteBtn').html('Regenerate Invite URL');
		$('#inviteWell').html('Join the chat at: ' + inviteURL + '<br><br>The password is: ' + password);
		$('#inviteWell').show();
	})
	.fail(function(status, err){
		console.log(status + ' ' + err);
	});
}
