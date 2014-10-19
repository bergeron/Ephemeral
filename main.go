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
	"bufio"
	"os"
	"sync"
	"time"
	"database/sql"
	_ "github.com/go-sql-driver/mysql"
)

/* Given a random 128 bits, encrypt text with an AES cipher */
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

/* Given encrypted text and the AES cipher key, decrypt the text */
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

/* POST to /create (Curried with db) */
func createHandler (db *sql.DB) func(http.ResponseWriter, *http.Request) {
	return  func(w http.ResponseWriter, r *http.Request) {

		text := r.FormValue("text")
		if len(text) > 16000{
			writeError(w, "Message too long. Max character length is 16000.")
			return
		}

		/* Generate two random byte []
		   One as key to encrypt, the other as secret message identifier
		*/
		keyBytes := make([]byte, 16)
		secretBytes := make([]byte, 8)
		_, err1 := rand.Read(keyBytes)
		_, err2 := rand.Read(secretBytes)
		if err1 != nil {
			log.Fatal(err1)
		} else if err2 != nil {
			log.Fatal(err2)
		}

		/* Convert byte[] keys to Strings */
		keyString := hex.EncodeToString(keyBytes)
		secretString := hex.EncodeToString(secretBytes)

		/* Encrypt the text */
		encryptedtextBytes, err := encrypt(keyBytes, []byte(text))
		if err != nil {
			log.Fatal(err)
		}
		encryptedtext := hex.EncodeToString(encryptedtextBytes)

		/* Insert message into db */
		_, err = db.Exec("insert into messages values (?, ?, ?)", secretString, encryptedtext, time.Now())
		if err != nil {
			log.Fatal(err)
		}

		/* Write HTML */
		type Out struct {
			Host string
			SecretString string
			KeyString string
		}

		data := Out{os.Getenv("EPHEMERAL_HOST"), secretString, keyString}
		tmpl := template.Must(template.ParseFiles("static/create.html", "static/top.html", "static/head.html"))
		tmpl.ExecuteTemplate(w, "create", data)
	}
}

/* GET to /view (Curried with db) */
func viewHandler(db *sql.DB) func(http.ResponseWriter, *http.Request) {
	return  func(w http.ResponseWriter, r *http.Request) {

		/* Blacklist sites that GET the url before sending to recipient */
		blacklist := [...]string{"facebook"}
		
		for _,e := range blacklist {
			if strings.Contains(r.UserAgent(), e) {
				fmt.Fprintf(w, "Go away %s! This is only for the recipient!", e)
				return
			}
		}

		/* get query params */
		queryString := strings.TrimSuffix(r.URL.Path[len("/view/"):],"/")
		params := strings.Split(queryString, "/")
		if len(params) != 2 {
			writeError(w, "Message not found. It may have been deleted.")
			return
		}
		msgSectet:= params[0]
		keyString := params[1]
		keyBytes, err := hex.DecodeString(keyString)
		if err != nil {
			fmt.Println("Key is not hex")
			writeError(w, "Message not found. It may have been deleted.")
			return
		}

		var m sync.Mutex
		m.Lock() /* ONLY ONE THREAD IN HERE AT A TIME */
		message, err := loadDecryptDelete(db, msgSectet, keyBytes)
		m.Unlock()	/*DONE */

		if err != nil{
			fmt.Println(err)
			writeError(w, "Message not found. It may have been deleted.")
			return
		} else {
			fmt.Println("Message Found!")
		}

		/* Write HTML */
		type Out struct {
			Success bool
			Message string
		}
		data := Out{true, message}
		tmpl := template.Must(template.ParseFiles("static/view.html", "static/top.html", "static/head.html"))
		tmpl.ExecuteTemplate(w, "view", data)
	}
}

/* Atomic transaction */
func loadDecryptDelete(db *sql.DB, msgSectet string, keyBytes []byte) (string, error){

	/* Lookup message in db */
	var encryptedtext string
	err := db.QueryRow("SELECT encryptedtext FROM messages WHERE secret = ?", msgSectet).Scan(&encryptedtext)
	if err != nil {
		return "", errors.New("No message found with msgSecret: " + msgSectet)
	}

	/* Decrypt message */
	encryptedtextBytes , err := hex.DecodeString(encryptedtext)
	if err != nil {
		return "", errors.New("Error converting encryptedext from string to byte[]")
	}
	messageBytes, err := decrypt(keyBytes, []byte(encryptedtextBytes))
	if err != nil {
		return "", errors.New("Valid msgSecret, but invalid key")
	}
	message:= string(messageBytes)

	/* Delete message from db */
	_, err = db.Exec("DELETE FROM messages WHERE secret = ? LIMIT 1", msgSectet)
	if err != nil {
		//Weird (given atomicity), but continue anyway.
	}
	
	return message, nil
}

/* Write the given error message as HTML */
func writeError(w http.ResponseWriter, message string){
	type Out struct {
		Message string
	}

	/* Write HTML */
	data := Out{message}
	tmpl := template.Must(template.ParseFiles("static/error.html", "static/top.html", "static/head.html"))
	tmpl.ExecuteTemplate(w, "error", data)
}


/* GET / */
func homeHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFiles("static/home.html", "static/top.html", "static/head.html"))
	tmpl.ExecuteTemplate(w, "home", nil)
}

/* GET /about */
func aboutHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFiles("static/about.html", "static/top.html", "static/head.html"))
	tmpl.ExecuteTemplate(w, "about", nil)
}


/*  Schema:
		secret VARCHAR(16),
		encryptedtext VARCHAR(43688),
		dt DATETIME
*/
func connectDb() (*sql.DB, error){

	/* Load auth file */
	file, err := os.Open("mysql.priv")
	defer file.Close()
	if err != nil {
		return nil, errors.New("Could not find mysql.priv")
	}

	bio := bufio.NewReader(file)
	tablename, _, err := bio.ReadLine()
	username, _, err := bio.ReadLine()
	password, _, err := bio.ReadLine()

	/* 'Connect' lazily */
	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@/%s", username, password, tablename))
	if err != nil {
		return nil, err
	}

	/* Actually try to connect */
	err = db.Ping()
	if err != nil {
		return nil, err
	}

	return db, nil /* Success */
}


func main() {

	db, err := connectDb()
	if err != nil {
		log.Fatal(err)
	}

	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/about/", aboutHandler)
	http.HandleFunc("/create/", createHandler(db))
	http.HandleFunc("/view/", viewHandler(db))
	fs := http.FileServer(http.Dir("static"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))

	/* SSL/TLS */
	path_to_certificate := "/etc/nginx/ssl/concat_server_and_CA_certs.pem"
	path_to_key := "/etc/nginx/ssl/private.key"
	err = http.ListenAndServeTLS(":11994", path_to_certificate, path_to_key, nil)
	if err != nil {
		log.Fatal(err)
	}
}
