

function decrypt(password){

	try {
		var key = CryptoJS.PBKDF2(password, salt, { keySize: 128/32 }).toString();
		var decrypted = CryptoJS.AES.decrypt(encryptedText, key).toString(CryptoJS.enc.Utf8);
		document.getElementById("decryptedMessage").innerHTML = decrypted.split("\n").join("<br>");
	} catch (e) {console.log(e)}	/* Error when incorrect key doesn't generate UTF8 */

	return false;
}
