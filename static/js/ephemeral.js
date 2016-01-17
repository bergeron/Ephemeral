/* encrypt.js */

$(document).ready(function(){
     
    login()
    .then(init)
    .catch(function(e){
        messageToHTML('Ephemeral', 'Login failed: ' + e);
    });
});


function login(){
    return new Promise(function(resolve, reject) {
 
        var pubStr = getEphemeral('pubStr');
        var privStr = getEphemeral('privStr');
        
        if(pubStr && privStr){

            messageToHTML('Ephemeral', 'Keys found in localstorage');
            
            resolve({
                'pubStr': pubStr,
                'privStr': privStr
            });

        } else {
            messageToHTML('Ephemeral', 'Generating keypair');
            
            var options = {
                numBits: 2048,
                userId: 'improvjam',
                passphrase: 'p'
            };

            window.openpgp.generateKeyPair(options).then(function(keypair) {
                setEphemeral('pubStr', keypair.publicKeyArmored);
                setEphemeral('privStr', keypair.privateKeyArmored);
                
                messageToHTML('Ephemeral', 'Keys set in localstorage');
                
                resolve({
                    'pubStr': keypair.publicKeyArmored,
                    'privStr': keypair.privateKeyArmored
                });
                
            }).catch(function(error) {
                reject('Key generation failed: ' + error);
            });
        }
    });
}


function init(pair){
    pair['pub'] = openpgp.key.readArmored(pair.pubStr);
    pair['priv'] = openpgp.key.readArmored(pair.privStr);
    p = pair;
    [pair.pub, pair.priv].forEach(
     function(k){
         if(k.err){
            messageToHTML('Ephemeral', 'Key deserialization failed: ');
            messageToHTML('Ephemeral', k.err[0]);
         }
     });
     
     if(pair.pub.err || pair.priv.err){
         return;
     } else {
         messageToHTML('Ephemeral', 'Login Successful');
     }
    
        
    $('#refresh').click(function(){
        sign(pair)
        .then(refresh(pair));
    });
    
    $('#chatSendBtn').click(function(){
        send(pair, pair.pubStr, $('#messageText').val());
    });
    
  
    $('.tab').click(function(e){
        $('.tab').removeClass('tab-selected');
        $(this).addClass('tab-selected');
        
        if($(this).text() == 'Friends'){
            $('#friends').show();
            $('#settings').hide();
        } else if($(this).text() == 'Settings'){
            $('#friends').hide();
            $('#settings').show();
        }
    });
    
    $('.friend').click(function(){
       $(this); 
    });
         
}



function add(toPubStr){
    var friends = getEphemeral('friends');
    if(!friends){
        friends = [];
    }
    
    friends.push({
        'pubStr': toPubStr,
        'nickname': ''
    });
    
    setEphemeral('friends', friends);
}

function send(pair, toPubStr, msg){
    
    var toPub = openpgp.key.readArmored(toPubStr);

    window.openpgp.encryptMessage(toPub.keys, msg)
    .then(function(ct) {
        $.ajax({
            method: 'POST',
            'url': '/send/',
            'data': {
                'toPubStr': toPubStr,
                'fromPubStr': pair.pubStr,
                'ct': ct,
                'expireMinutes': 100000
            }
        }).done(function(data){
            if(data == "success"){
                messageToHTML(pair.pub.keys[0].users[0].userId.userid, msg);
            } else {
                messageToHTML('Ephemeral', 'Send failed');
            }
        }).fail(function(status, error){
            messageToHTML('Ephemeral', 'Send failed: ' + error);
        });      
    }).catch(function(error) {});
    
}

function sign(pair){
    pair.priv.keys[0].decrypt('p');
    var msgToSign = 'Proof I own the key: ' + pair.pubStr;
    return window.openpgp.signClearMessage(pair.priv.keys[0], msgToSign);
}

function refresh(pair){
    return function(signature){
        
        signature = signature.substring(signature.indexOf('-----BEGIN PGP SIGNATURE-----'));
        
        $.ajax({
            method: 'GET',
            url: '/refresh/',
            data: {
                'pubStr': pair.pubStr,
                'signature': signature
            }
        })
        .done(function(data) {
            decrypt(pair, data.Messages);
        })
        .fail(function(status, err){
            messageToHTML('Ephemeral', status + ' ' + err);
        });      
    }  
}
    

function decrypt(pair, messages){
    
    pair.priv.keys[0].decrypt('p');
    
    messages.forEach(function(m){
        ct = openpgp.message.readArmored(m);
        window.openpgp.decryptMessage(pair.priv.keys[0], ct).then(function(pt) {
            messageToHTML('Ephemeral', pt);
        }).catch(function(error) {
            messageToHTML('Ephemeral', error);
        });
    });
}


function escapeHtml(str) {
    var div = document.createElement('div');
    div.appendChild(document.createTextNode(str));
    return div.innerHTML;
}

function messageToHTML(nickname, text){

	var color = randDarkColor();

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
	chatWindow.scrollTop(chatWindow.prop('scrollHeight'));	
}

function addMember(nickname){
	//nicknames.push(nickname);
	var color = randDarkColor();
	//colors.push(color);
	$('#membersUl').append('<li style="color:#' + color + '">' + nickname + '</li>');
	messageToHTML(nickname, 'has joined the chat');
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


function getEphemeral(key){
    var ephemeral = JSON.parse(localStorage.getItem('ephemeral'));
    return ephemeral ? ephemeral[key] : false;
}

function setEphemeral(key, val){
    var ephemeral = JSON.parse(localStorage.getItem('ephemeral'));
    if(!ephemeral){
        ephemeral = {};
    }
    
    ephemeral[key] = val;
    localStorage.setItem('ephemeral', JSON.stringify(ephemeral));
}

