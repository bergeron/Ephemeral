
function choosePwd(){
	$('#encryptBox').show();
}

function encrypt(message, passwordSource){

	try{
		var password;
		if(passwordSource == 'custom'){
			password = $('#customPassword').val();
		} else {
			password = CryptoJS.lib.WordArray.random(128/8).toString();
		}

		var salt = CryptoJS.lib.WordArray.random(128/8).toString();
		var key = CryptoJS.PBKDF2(password, salt, { keySize: 128/32 }).toString();
		var encryptedText = CryptoJS.AES.encrypt(message, key).toString();
		var expireMinutes = $('#expireMinutes').val();

		$.ajax({
			method: 'POST',
			url: '/create/client/',
			data: {
				text: 			encryptedText,
				expireMinutes: 	expireMinutes,
				salt: 			salt
			}
		})
		.done(function(data) {
			var resultMsg = 'I have a message for you at: ' + data + '<br><br>' + 'The password is: ' + password;
			$('#finishedMessage').html(resultMsg);
			$('#result').show();
		})
		.fail(function(status, err){
			console.log(status + ' ' + err);
		});
		
	} catch (e) {console.log(e)}
	
	return false;
}
