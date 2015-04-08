/* chat.js */

var chatroomId = $(location).attr('pathname').substring(6);
var keypair = forge.pki.rsa.generateKeyPair({bits: 2048, e: 0x10001});
var socket;
var sharedSecret;
var nickname;
var nicknameId;
var nicknames = [];
var colors = [];


if (!window['WebSocket']) {
	alert('Your browser does not support WebSockets. Ephemeral chat requires WebSockets.');
}

$(document).ready(function() {

	if(!creating){
		openWebSocket(chatroomId);
	}

	$('#nicknameForm').submit(function(e){
		nickname = $('#nickname').val();

		if(creating){
			create();
		} else {
			setNickname(nickname);
		}
		openChatroom();
		return false;
	});
});

function escapeHtml(str) {
    var div = document.createElement('div');
    div.appendChild(document.createTextNode(str));
    return div.innerHTML;
}

function openChatroom(){
	$('#nicknameForm').hide();
	$('#chatInstructions').hide();
	$('#openChatBtn').hide();

	$('#chatPrompt').show();
	$('#chatRoom').show();
	$('#inviteBtn').show();
	$('#inviteInstructions').show();
}

function create(){
	try{
		
		sharedSecret = CryptoJS.lib.WordArray.random(128/8).toString();

		$.ajax({
			method: 'POST',
			url: '/chat/create/'
		})
		.done(function(data) {
			chatroomId = data.ChatroomId;
			openWebSocket(chatroomId);
		})
		.fail(function(status, err){
			console.log(status + ' ' + err);
		});

	} catch (e) {console.log(e)}

	return false;
}

function decryptNicknames(){
	try{

		for(var i=0; i < encryptedNicknames.length; i++){
			var nickname = CryptoJS.AES.decrypt(encryptedNicknames[i], sharedSecret).toString(CryptoJS.enc.Utf8);
			nickname = escapeHtml(nickname);
			addMember(nickname);
		}
	} catch (e) {console.log(e)}

	return false;
}

function openWebSocket(chatroomId){

	socket = new WebSocket('ws://ephemeral.pw/chat/ws?chatroomId=' + chatroomId);
    socket.onopen = function(event){
    	if(creating){
			setNickname(nickname);
    	} else {
    		initiateKeyExchange();
    	}
    }
    socket.onmessage = function(event) {
    	var data = JSON.parse(event.data);

    	console.log(data);

    	if(data.msgType == 'keyExchangeReq' && sharedSecret != undefined){
    		var publicKey = forge.pki.publicKeyFromPem(data.publicKeyPem);
    		var encrypted = publicKey.encrypt(sharedSecret);

    		var msg = {
				msgType: 				"keyExchangeResp",
				chatroomId: 			chatroomId,
				sharedSecretEncrypted: 	encrypted,
				publicKeyPem: 			data.publicKeyPem
    		};

    		socket.send(JSON.stringify(msg));

    	} else if(data.msgType == "keyExchangeResp" && sharedSecret == undefined && data.publicKeyPem == forge.pki.publicKeyToPem(keypair.publicKey)) {
    		sharedSecret = keypair.privateKey.decrypt(data.sharedSecretEncrypted);
    		decryptNicknames();
    	} else if(data.msgType == 'newMessage'){
			var nickname = CryptoJS.AES.decrypt(data.encryptedNickname, sharedSecret).toString(CryptoJS.enc.Utf8);
			var text = CryptoJS.AES.decrypt(data.encryptedText, sharedSecret).toString(CryptoJS.enc.Utf8);
			messageToHTML(nickname, text);
		} else if(data.msgType == 'newMember'){
			var nickname = CryptoJS.AES.decrypt(data.encryptedNickname, sharedSecret).toString(CryptoJS.enc.Utf8);
			nickname = escapeHtml(nickname);
			addMember(nickname);
		} else if(data.msgType == 'lostMember'){
			var nickname = CryptoJS.AES.decrypt(data.encryptedNickname, sharedSecret).toString(CryptoJS.enc.Utf8);
			nickname = escapeHtml(nickname);
			lostMember(nickname);
		} else if(data.msgType == 'nicknameId'){
			nicknameId = data.nicknameId;
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

		var encryptedText = CryptoJS.AES.encrypt(message, sharedSecret).toString();
		var msg = {
			msgType: 		"newMessage",
			chatroomId: 	chatroomId,
			encryptedText: 	encryptedText,
			nicknameId: 	nicknameId
		};

		socket.send(JSON.stringify(msg));

		$('#messageText').val('');

	} catch (e) {console.log(e);}

	return false;
}

function setNickname(nickname){

	if(sharedSecret == undefined){
		console.log("Waiting for sharedSecret");
		return;
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

	var encryptedNickname = CryptoJS.AES.encrypt(nickname, sharedSecret).toString();

	var msg = {
		msgType: 			"newMember",
		chatroomId: 		chatroomId,
		encryptedNickname: 	encryptedNickname
	};

	socket.send(JSON.stringify(msg));
}

function messageToHTML(nickname, text){
	var color = colors[nicknames.indexOf(nickname)];

	var messageHTML = '' +
	'<div class="chatMsg">' +
		'<span class="nickname" style="color: #' + color + ';">' +
			escapeHtml(nickname) + ": " + 
		'</span>' +
		'<span class="msgText">' +
			escapeHtml(text) +
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
	messageToHTML(nickname, 'has joined the chat');
}

function lostMember(nickname){
	nicknames.splice(nicknames.indexOf(nickname), 1);
	colors.splice(nicknames.indexOf(nickname), 1);
	//TODO
	messageToHTML(nickname, 'has left the chat');
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
		$('#inviteWell').html(inviteURL);
		$('#inviteWell').show();
	})
	.fail(function(status, err){
		console.log(status + ' ' + err);
	});
}

function initiateKeyExchange(){
	var msg = {
			msgType: 		"keyExchangeReq",
			chatroomId: 	chatroomId,
			publicKeyPem: 	forge.pki.publicKeyToPem(keypair.publicKey)
		};

	socket.send(JSON.stringify(msg));
}
