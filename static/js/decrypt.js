
function decrypt(password){

	try {
		var key = CryptoJS.PBKDF2(password, salt, { keySize: 128/32 }).toString();
		var decrypted = CryptoJS.AES.decrypt(encryptedText, key).toString(CryptoJS.enc.Utf8).split("\n").join("<br>");
		$('#decryptedMessage').html(decrypted);
	} catch (e) {console.log(e)}	/* Error when incorrect key doesn't generate UTF8 */

	return false;
}
