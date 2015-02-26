

function decrypt(password){

	var decrypted = CryptoJS.AES.decrypt(encryptedText, password).toString(CryptoJS.enc.Utf8);
	document.getElementById("decryptedMessage").innerHTML = decrypted;
	return false;
}