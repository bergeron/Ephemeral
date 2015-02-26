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
	"strconv"
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

/* POST /create/server */
func createServerHandler (db *sql.DB) func(http.ResponseWriter, *http.Request) {
	return  func(w http.ResponseWriter, r *http.Request) {

		text := r.FormValue("text")
		if len(text) > 16000{
			writeError(w, "Message too long. Max character length is 16000.")
			return
		}

		/* Generate 128 random bits, twice */
		key128bits := make([]byte, 16)
		msgId128bits := make([]byte, 16)
		_, err1 := rand.Read(key128bits)
		_, err2 := rand.Read(msgId128bits)
		if err1 != nil {
			log.Fatal(err1)
		} else if err2 != nil {
			log.Fatal(err2)
		}

		msgId := hex.EncodeToString(msgId128bits)

		/* Encrypt the text */
		encryptedtextBytes, err := encrypt(key128bits, []byte(text))
		if err != nil {
			log.Fatal(err)
		}
		encryptedtext := hex.EncodeToString(encryptedtextBytes)

		/* Set expiration date */
		expireMinutes, err := strconv.Atoi(r.FormValue("expireMinutes"))
		var dt_delete time.Time
		if err != nil {
			dt_delete = time.Date(9999, 0, 0, 0, 0, 0, 0, time.FixedZone("UTC", 0))	/* Never expire */
		} else {
			dt_delete =  time.Now().Add(time.Minute * time.Duration(expireMinutes))
		}

		/* Insert message into db */
		_, err = db.Exec("insert into messages values (?, ?, ?, ?, ?)", msgId, encryptedtext, time.Now(), dt_delete, true)
		if err != nil {
			log.Fatal(err)
		}

		/* Write HTML */
		type Out struct {
			Host string
			SecretString string
			KeyString string
		}

		format := r.FormValue("format")
		if format == "url" {	/* Return only url */
			url := "http://" + os.Getenv("EPHEMERAL_HOST") + "/view/server/" +msgId + "/" + hex.EncodeToString(key128bits)
			w.Write([]byte(url))
		} else {	/* Return html */
			data := Out{os.Getenv("EPHEMERAL_HOST"), msgId, hex.EncodeToString(key128bits)}
			tmpl := template.Must(template.ParseFiles("static/create.html", "static/top.html", "static/head.html"))
			tmpl.ExecuteTemplate(w, "create", data)
		}
	}
}

/* POST /create/client */
func createClientHandler (db *sql.DB) func(http.ResponseWriter, *http.Request) {
	return  func(w http.ResponseWriter, r *http.Request) {

		encryptedText := r.FormValue("text")
		if len(encryptedText) > 16000{
			writeError(w, "Message too long. Max character length is 16000.")
			return
		}

		fmt.Println(encryptedText)

		/* Generate 128 random bits */
		msgId128bits := make([]byte, 16)
		_, err := rand.Read(msgId128bits)
		if err != nil {
			log.Fatal(err)
		}

		msgId := hex.EncodeToString(msgId128bits)

		/* Set expiration date */
		expireMinutes, err := strconv.Atoi(r.FormValue("expireMinutes"))
		var dt_delete time.Time
		if err != nil {
			dt_delete = time.Date(9999, 0, 0, 0, 0, 0, 0, time.FixedZone("UTC", 0))	/* Never expire */
		} else {
			dt_delete =  time.Now().Add(time.Minute * time.Duration(expireMinutes))
		}

		/* Insert message into db */
		_, err = db.Exec("insert into messages values (?, ?, ?, ?, ?)", msgId, encryptedText, time.Now(), dt_delete, false)
		if err != nil {
			log.Fatal(err)
		}

		url := "https://" + os.Getenv("EPHEMERAL_HOST") + "/view/client/" + msgId
		w.Write([]byte(url))
	}
}

/* GET /view/server */
func viewServerHandler(db *sql.DB) func(http.ResponseWriter, *http.Request) {
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
		queryString := strings.TrimSuffix(r.URL.Path[len("/view/server/"):],"/")
		params := strings.Split(queryString, "/")
		if len(params) != 2 {
			writeError(w, "Message not found. It may have been deleted.")
			return
		}
		msgId := params[0]
		keyString := params[1]
		keyBytes, err := hex.DecodeString(keyString)
		if err != nil {
			fmt.Println("Key is not hex")
			writeError(w, "Message not found. It may have been deleted.")
			return
		}

		var m sync.Mutex
		m.Lock() /* ONLY ONE THREAD IN HERE AT A TIME */

		/* Lookup message in db */
		var encryptedText string
		err = db.QueryRow("SELECT encrypted_text FROM messages WHERE id = ?", msgId).Scan(&encryptedText)
		if err != nil {
			fmt.Println("No message found with msgId: " + msgId)
			writeError(w, "Message not found. It may have been deleted.")
			return
		}

		/* Decrypt message */
		encryptedtextBytes , err := hex.DecodeString(encryptedText)
		if err != nil {
			fmt.Println("Error converting encryptedext from string to byte[]")
			writeError(w, "Message not found. It may have been deleted.")
			return
		}
		messageBytes, err := decrypt(keyBytes, []byte(encryptedtextBytes))
		if err != nil {
			fmt.Println("Valid msgId, but invalid key")
			writeError(w, "Message not found. It may have been deleted.")
			return
		}
		message := string(messageBytes)

		/* Delete message from db */
		_, err = db.Exec("DELETE FROM messages WHERE id = ? LIMIT 1", msgId)
		if err != nil {
			fmt.Println("Message already deleted.")		/* Shouldn't happen */
		}
	
		m.Unlock()	/*DONE */

		fmt.Println("Message Found!")

		/* Write HTML */
		type Out struct {
			Success bool
			Message string
		}
		data := Out{true, message}
		tmpl := template.Must(template.ParseFiles("static/viewServer.html", "static/top.html", "static/head.html"))
		tmpl.ExecuteTemplate(w, "viewServer", data)
	}
}

/* GET /view/client */
func viewClientHandler(db *sql.DB) func(http.ResponseWriter, *http.Request) {
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
		queryString := strings.TrimSuffix(r.URL.Path[len("/view/client/"):],"/")
		params := strings.Split(queryString, "/")
		if len(params) != 1 {
			writeError(w, "Message not found. It may have been deleted.")
			return
		}
		msgId := params[0]

		var m sync.Mutex
		m.Lock() /* ONLY ONE THREAD IN HERE AT A TIME */

		/* Lookup message in db */
		var encryptedText string
		err := db.QueryRow("SELECT encrypted_text FROM messages WHERE id = ?", msgId).Scan(&encryptedText)
		if err != nil {
			fmt.Println("No message found with msgId: " + msgId)
			writeError(w, "Message not found. It may have been deleted.")
			return
		}

		/* Delete message from db */
		_, err = db.Exec("DELETE FROM messages WHERE id = ? LIMIT 1", msgId)
		if err != nil {
			fmt.Println("Message already deleted.")		/* Shouldn't happen */
		}

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
		fmt.Println(encryptedText)
		data := Out{true, encryptedText}
		tmpl := template.Must(template.ParseFiles("static/viewClient.html", "static/top.html", "static/head.html"))
		tmpl.ExecuteTemplate(w, "viewClient", data)
	}
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
		id VARCHAR(32) NOT NULL,
		encryptedtext VARCHAR(43688) NOT NULL,
		dt_created DATETIME NOT NULL,
		dt_delete DATETIME NOT NULL,
		server_encrypted BOOLEAN NOT NULL
*/
func connectDb() (*sql.DB, error){

	/* Load config file */
	file, err := os.Open("mysql.priv")
	defer file.Close()
	if err != nil {
		return nil, errors.New("Could not find mysql.priv")
	}

	bio := bufio.NewReader(file)
	tablename, _, err := bio.ReadLine()
	username, _, err := bio.ReadLine()
	password, _, err := bio.ReadLine()

	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@/%s", username, password, tablename))
	if err != nil {
		return nil, err
	}

	/* Actually try to connect */
	err = db.Ping()
	if err != nil {
		return nil, err
	}

	return db, nil
}


func main() {

	db, err := connectDb()
	if err != nil {
		log.Fatal(err)
	}

	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/about/", aboutHandler)
	http.HandleFunc("/create/server/", createServerHandler(db))
	http.HandleFunc("/create/client/", createClientHandler(db))
	http.HandleFunc("/view/server/", viewServerHandler(db))
	http.HandleFunc("/view/client/", viewClientHandler(db))
	fs := http.FileServer(http.Dir("static"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))

	/* SSL/TLS *//*
	path_to_certificate := "/etc/nginx/ssl/ephemeral/concat_server_and_CA_certs.pem"
	path_to_key := "/etc/nginx/ssl/ephemeral/private.key"
*/
	err = http.ListenAndServe(":11994", nil)
	if err != nil {
		log.Fatal(err)
	}
}
