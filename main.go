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
	"html/template"
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
	text := r.FormValue("text")

	encryptKey := make([]byte, 16)
	msgSecretKey := make([]byte, 8)
	_, err1 := rand.Read(encryptKey)
	_, err2 := rand.Read(msgSecretKey)
	if err1 != nil {
		log.Fatal(err1)
	} else if err2 != nil {
		log.Fatal(err2)
	}

	/* Convert keys to hex String */
	keyString := hex.EncodeToString(encryptKey)
	msgSecretString := hex.EncodeToString(msgSecretKey)

	fmt.Printf("%s\n", text)

	ciphertext, err := encrypt(encryptKey, []byte(text))

	if err != nil {
		log.Fatal(err)
	}

	encryptedtext := hex.EncodeToString(ciphertext)
	fmt.Printf("encryptedtext:%s\n keyString:%s\n msgSecretKey:%s\n", encryptedtext, keyString, msgSecretKey)

	type Out struct {
		MsgSecretString string
		Text string
		KeyString string
		EncryptedText string
	}

	data := Out{msgSecretString, text, keyString, encryptedtext}
	tmpl, err := template.ParseFiles("create.html")

	err = tmpl.Execute(w, data)
}

func viewHandler(w http.ResponseWriter, r *http.Request) {
	queryString := r.URL.Path[len("/view/"):]
	params := strings.Split(queryString, "/")

	keyString := params[0]
	msgSectet := params[1]
	encryptedText := params[2]

	key, _ := hex.DecodeString(keyString)
	fmt.Printf("keystring: %s\n", keyString)
	fmt.Printf("msgSectet: %s\n", msgSectet)

	//TODO go get message with msgSecret
	messageEncrypted ,_ := hex.DecodeString(encryptedText)
	message, err := decrypt(key, []byte(messageEncrypted))
	if err != nil {
		log.Fatal(err)
	}

	fmt.Fprintf(w, "<h1>%s</h1>", message)
}


func homeHandler(w http.ResponseWriter, r *http.Request) {

	http.ServeFile(w, r, "home.html")
}


func main() {
	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/create/", createHandler)
	http.HandleFunc("/view/", viewHandler)
	http.ListenAndServe(":1337", nil)
}
