/* message.js */

$(document).ready(function(){

    $('#expireCheckbox').click(function(e){
        toggleCheckbox($('#expireCheckbox'), $('#expireMinutes'));
    });

    $('#passwordCheckbox').click(function(e){
        toggleCheckbox($('#passwordCheckbox'), $('#customPassword'))
    });
});

function toggleCheckbox(checkBox, input){
    if(checkBox.prop('checked')){
        input.prop('disabled', false);
    } else {
        input.prop('disabled', true);
        input.val('');
    }
}

function create(message){

    if($('#passwordCheckbox').prop('checked')){
        return encrypt(message, $('#customPassword').val());
    } else {
        return true;
    }
}

function encrypt(message, password){

    try{
        var salt = CryptoJS.lib.WordArray.random(128/8).toString();
        var key = CryptoJS.PBKDF2(password, salt, { keySize: 128/32 }).toString();
        var encryptedText = CryptoJS.AES.encrypt(message, key).toString();
        var expireMinutes = $('#expireMinutes').val();

        $.ajax({
            method: 'POST',
            url: '/create/client/',
            data: {
                text:           encryptedText,
                expireMinutes:  expireMinutes,
                salt:           salt
            }
        })
        .done(function(data) {
            var resultMsg = data;
            $('#finishedMessage').html(resultMsg);
            $('#result').show();
        })
        .fail(function(status, err){
            console.log(status + ' ' + err);
        });
        
    } catch (e) {console.log(e)}
    
    return false;
}


function decrypt(password){

    try {
        var key = CryptoJS.PBKDF2(password, salt, { keySize: 128/32 }).toString();
        var decrypted = CryptoJS.AES.decrypt(encryptedText, key).toString(CryptoJS.enc.Utf8).split("\n").join("<br>");
        
        if(decrypted){
            $('#decryptedMessage').html('');
            var lines = decrypted.split('<br>');
            for(var i=0; i < lines.length; i++){
                $('#decryptedMessage').append(escapeHtml(lines[i]) + '<br>');
            }
        }
    } catch (e) {}  /* Error when incorrect key doesn't generate UTF8 */

    return false;
}

function escapeHtml(str) {
    var div = document.createElement('div');
    div.appendChild(document.createTextNode(str));
    return div.innerHTML;
}
