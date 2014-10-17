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

		/* Encrypt text */
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
			SecretString string
			KeyString string
		}
		data := Out{secretString, keyString}
		tmpl, err := template.ParseFiles("static/create.html")
		err = tmpl.Execute(w, data)
	}
}

func messsageNotFound(w http.ResponseWriter){

	/* Write HTML */
	fmt.Fprintf(w, "<h1>%s</h1>", "Not found. May have been deleted")
}


/* Curried with db */
func viewHandler(db *sql.DB) func(http.ResponseWriter, *http.Request) {
	return  func(w http.ResponseWriter, r *http.Request) {
		/* get query params */
		queryString := strings.TrimSuffix(r.URL.Path[len("/view/"):],"/")
		params := strings.Split(queryString, "/")
		if len(params) != 2 {
			messsageNotFound(w)
			return
		}
		msgSectet:= params[0]
		keyString := params[1]
		keyBytes, err := hex.DecodeString(keyString)
		if err != nil {	/* Parameters weren't even */
			messsageNotFound(w)
			return
		}

		var loadDecryptDelete sync.Mutex
		loadDecryptDelete.Lock()
		/***** ONLY ONE THREAD IN HERE AT A TIME */

			/* Lookup message in db */
			var encryptedtext string
			err = db.QueryRow("SELECT encryptedtext FROM messages WHERE secret = ?", msgSectet).Scan(&encryptedtext)
			if err != nil {
				messsageNotFound(w)
				return
			}

			/* Decrypt message */
			encryptedtextBytes , err := hex.DecodeString(encryptedtext)
			if err != nil {
				messsageNotFound(w)
				return
			}
			message, err := decrypt(keyBytes, []byte(encryptedtextBytes))
			if err != nil { 	/* Correct message secret, but wrong key */
				messsageNotFound(w)
				return
			}

			/* Delete message from db */
			_, err = db.Exec("DELETE FROM messages WHERE secret = ? LIMIT 1", msgSectet)
			if err != nil {
				//Weird, but continue anyway. Just be glad its gone
			}
		/***** DONE */
		loadDecryptDelete.Unlock()

		/* Write HTML */
		fmt.Fprintf(w, "<h1>%s</h1>", message)
	}
}


func homeHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "static/home.html")
}


/* SCHEMA = (	secret VARCHAR(16),
				encryptedtext VARCHAR(4096),
				dt DATETIME
			)
*/
func connectDb() *sql.DB{

	/* Load auth file */
	file, err := os.Open("mysql.priv")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	bio := bufio.NewReader(file)
	tablename, _, err := bio.ReadLine()
	username, _, err := bio.ReadLine()
	password, _, err := bio.ReadLine()

	/* 'Connect' lazily */
	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@/%s", username, password, tablename))
	if err != nil {
		log.Fatal(err)
	}

	/* Actually try to connect */
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
