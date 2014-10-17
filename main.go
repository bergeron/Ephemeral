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
	"database/sql"
	_ "github.com/go-sql-driver/mysql"
)


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

/* Curried with db */
func createHandler (db *sql.DB) func(http.ResponseWriter, *http.Request) {
	return  func(w http.ResponseWriter, r *http.Request) {

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

		/* Insert into db */
		_, err = db.Exec("insert into messages values (?, ?, ?)", encryptKey, msgSecretString, encryptedtext)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Printf("encryptedtext:%s\n keyString:%s\n msgSecretKey:%s\n", encryptedtext, keyString, msgSecretKey)
		type Out struct {
			MsgSecretString string
			Text string
			KeyString string
			EncryptedText string
		}
		data := Out{msgSecretString, text, keyString, encryptedtext}
		tmpl, err := template.ParseFiles("static/create.html")
		err = tmpl.Execute(w, data)
	}
}



/* Curried with db */
func viewHandler(db *sql.DB) func(http.ResponseWriter, *http.Request) {
	return  func(w http.ResponseWriter, r *http.Request) {

		queryString := r.URL.Path[len("/view/"):]
		params := strings.Split(queryString, "/")

		keyString := params[0]
		msgSectet := params[1]

		key, _ := hex.DecodeString(keyString)
		fmt.Printf("keystring: %s\n", keyString)
		fmt.Printf("msgSectet: %s\n", msgSectet)


		/* Lookup message in db */
		var encryptedText string
		err := db.QueryRow("select encryptedtext from messages where secret = ?", msgSectet).Scan(&encryptedText)
		if err != nil {
			log.Fatal(err)
		}

		/* Delete message from db */
		//TODO

		/* Convert hex string to byte[] */
		msgEncryptedBytes , err := hex.DecodeString(encryptedText)
		if err != nil {
			log.Fatal(err)
		}

		/* Decrypt byte[] into actual message */
		message, err := decrypt(key, []byte(msgEncryptedBytes))
		if err != nil {
			log.Fatal(err)
		}

		fmt.Fprintf(w, "<h1>%s</h1>", message)
	}
}


func homeHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "static/home.html")
}


func connectDb() *sql.DB{
	db, err := sql.Open("mysql", "username:pass@/ephemeral")
	if err != nil {
		log.Fatal(err)
	}

	/* Actually connect */
	err = db.Ping()
	if err != nil {
		log.Fatal(err)
	}

	return db
}


func main() {

	db := connectDb()
	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/create/", createHandler(db))
	http.HandleFunc("/view/", viewHandler(db))
	http.ListenAndServe(":1337", nil)
}
