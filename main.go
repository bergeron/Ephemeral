
package main
import (
	"net/http"
	"crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "encoding/base64"
    "errors"
    "fmt"
    "io"
    "log"
	"encoding/hex" 
	"strings"
)

type Message struct {
    Text string
    SecretId  string
}


func encrypt(key, text []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	b := base64.StdEncoding.EncodeToString(text)
	ciphertext := make([]byte, aes.BlockSize+len(b))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], []byte(b))
	return ciphertext, nil
}

func decrypt(key, text []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(text) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}
	iv := text[:aes.BlockSize]
	text = text[aes.BlockSize:]
	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(text, text)
	data, err := base64.StdEncoding.DecodeString(string(text))
	if err != nil {
		return nil, err
	}
	return data, nil
}


func createHandler(w http.ResponseWriter, r *http.Request) {
	key := make([]byte, 16)
	msgSecret := make([]byte, 8)
	_, err1 := rand.Read(key)
	_, err2 := rand.Read(msgSecret)
	if err1 != nil {
		log.Fatal(err1)
	} else if err2 != nil {
		log.Fatal(err2)
	}

	keyString := hex.EncodeToString(key)
	msgSecretString := hex.EncodeToString(msgSecret)
	
	text := "this is my private noteeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	fmt.Printf("%s\n", text)

	ciphertext, err := encrypt(key, []byte(text))
	if err != nil {
		log.Fatal(err)
	}

	encryptedtext := hex.EncodeToString(ciphertext)
	fmt.Printf("encryptedtext:%s\n", encryptedtext)

	//TODO Store the encryptedtext with secret msgSecretString

	fmt.Fprintf(w, "<h1>%s</h1><br><h1>%s</h1><br><h1>%s</h1>", msgSecretString, text, keyString)

}

func viewHandler(w http.ResponseWriter, r *http.Request) {
	params := r.URL.Path[len("/view/"):]
	keyString, msgSectet := params[:strings.Index(params, "/")], params[strings.Index(params, "/")+1:]
	
	key, _ := hex.DecodeString(keyString)
	fmt.Printf("keystring: %s\n", keyString)
	fmt.Printf("msgSectet: %s\n", msgSectet)

	//TODO go get message with msgSecret
	messageEncrypted ,_ := hex.DecodeString("ce527bc328685ae6af5d3e8843d0233dc8e15cd4bbeeb0ea2444e25996abb12a1a32276201175eaa176d0197e97749cde4e630ca1b01ae90ca92fba08a9d75eccead016a6785cbe2203f2d71fc0edbbe07e8d290df8c6781ed06d2171d07452d09812b4f786113ea36e75a963ac1a18b75252f7fd6f606e2ffcd5cc4")
	message, err := decrypt(key, []byte(messageEncrypted))
	if err != nil {
		log.Fatal(err)
	}

	fmt.Fprintf(w, "<h1>%s</h1>", message)
}

func main() {
	http.HandleFunc("/create/", createHandler)
	http.HandleFunc("/view/", viewHandler)
	http.ListenAndServe(":1337", nil)
}

