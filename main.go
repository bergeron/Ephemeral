/* main.go */

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
	_ "github.com/gorilla/websocket"
)

var db *sql.DB = connectDb()

func main() {
	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/about/", aboutHandler)
	http.HandleFunc("/create/server/", createServerHandler)
	http.HandleFunc("/create/client/", createClientHandler)
	http.HandleFunc("/view/server/", viewServerHandler)
	http.HandleFunc("/view/client/", viewClientHandler)
	http.HandleFunc("/chat/", chatHandler)
	http.HandleFunc("/chat/create/", createChatHandler)
	http.HandleFunc("/chat/ws", serveWs)
	http.HandleFunc("/invite/", inviteHandler)

	fs := http.FileServer(http.Dir("static"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))

	/* SSL/TLS */
	path_to_certificate := "/etc/nginx/ssl/ephemeral/concat_server_and_CA_certs.pem"
	path_to_key := "/etc/nginx/ssl/ephemeral/private.key"
	err := http.ListenAndServeTLS(":11994", path_to_certificate, path_to_key, nil)
}

func connectDb() (*sql.DB){

	/* Load config file */
	file, err := os.Open("mysql.priv")
	defer file.Close()
	if err != nil {
		fmt.Println("Could not find mysql.priv")
		return nil
	}

	bio := bufio.NewReader(file)
	tablename, _, err := bio.ReadLine()
	username, _, err := bio.ReadLine()
	password, _, err := bio.ReadLine()

	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@/%s", username, password, tablename))
	if err != nil {
		fmt.Println(err.Error())
		return nil
	}

	/* Test connection */
	err = db.Ping()
	if err != nil {
		fmt.Println(err.Error())
		return nil
	}

	return db
}

/* Write the given error message as HTML */
func writeError(w http.ResponseWriter, message string){
	type Out struct {
		Message string
	}

	/* Write HTML */
	data := Out{message}
	tmpl := template.Must(template.ParseFiles("static/html/error.html", "static/html/top.html", "static/html/head.html"))
	tmpl.ExecuteTemplate(w, "error", data)
}

/* GET / */
func homeHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFiles("static/html/home.html", "static/html/top.html", "static/html/head.html"))
	tmpl.ExecuteTemplate(w, "home", nil)
}

/* GET /about */
func aboutHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFiles("static/html/about.html", "static/html/top.html", "static/html/head.html"))
	tmpl.ExecuteTemplate(w, "about", nil)
}

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
func createServerHandler(w http.ResponseWriter, r *http.Request) {

	text := r.FormValue("text")
	if len(text) > 16000{
		writeError(w, "Message too long. Max character length is 16000.")
		return
	}

	msgId := generateTableId(db, "messages")

	/* Generate 128 bit key */
	key128bits := make([]byte, 16)
	_, err := rand.Read(key128bits)
	if err != nil {
		log.Fatal(err)
	}

	/* Encrypt the text */
	encryptedtextBytes, err := encrypt(key128bits, []byte(text))
	if err != nil {
		log.Fatal(err)
	}
	encryptedtext := hex.EncodeToString(encryptedtextBytes)

	/* Set expiration date */
	expireMinutes, err := strconv.Atoi(r.FormValue("expireMinutes"))
	if err != nil {
		expireMinutes = 43200	/* Default expire in 30 days */
	}

	/* Insert message into db */
	_, err = db.Exec("insert into messages values (?, ?, ?, ?, ?, ?)", 
						msgId, encryptedtext, nil, time.Now().Unix(), expireMinutes, true)
	if err != nil {
		log.Fatal(err)
	}

	format := r.FormValue("format")
	if format == "url" {	/* Return only url */
		url := "https://" + r.Host + "/view/server/" +msgId + "/" + hex.EncodeToString(key128bits)
		w.Write([]byte(url))
	} else {	/* Return html */
		
		type Out struct {
			Host string
			SecretString string
			KeyString string
		}
		data := Out{r.Host, msgId, hex.EncodeToString(key128bits)}
		tmpl := template.Must(template.ParseFiles("static/html/create.html", "static/html/top.html", "static/html/head.html"))
		tmpl.ExecuteTemplate(w, "create", data)
	}
}

/* POST /create/client */
func createClientHandler(w http.ResponseWriter, r *http.Request) {

	encryptedText := r.FormValue("text")
	if len(encryptedText) > 16000{
		writeError(w, "Message too long. Max character length is 16000.")
		return
	}

	msgId := generateTableId(db, "messages")
	salt := r.FormValue("salt")

	/* Set expiration date */
	expireMinutes, err := strconv.Atoi(r.FormValue("expireMinutes"))
	if err != nil {
		expireMinutes = 43200	/* Default expire in 30 days */
	}

	/* Insert message into db */
	_, err = db.Exec("insert into messages values (?, ?, ?, ?, ?, ?)", 
						msgId, encryptedText, salt, time.Now().Unix(), expireMinutes, false)
	if err != nil {
		log.Fatal(err)
	}

	url := "https://" + r.Host + "/view/client/" + msgId
	w.Write([]byte(url))
}

/* GET /view/server */
func viewServerHandler(w http.ResponseWriter, r *http.Request) {

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

	message := template.HTMLEscapeString(string(messageBytes))	/* no XSS */

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
		Message []string
	}
	data := Out{true, strings.Split(message, "\n")}
	tmpl := template.Must(template.ParseFiles("static/html/viewServer.html", "static/html/top.html", "static/html/head.html"))
	tmpl.ExecuteTemplate(w, "viewServer", data)
}

/* GET /view/client */
func viewClientHandler(w http.ResponseWriter, r *http.Request) {

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
	var salt string
	err := db.QueryRow("SELECT encrypted_text, salt FROM messages WHERE id = ?", msgId).Scan(&encryptedText, &salt)
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

	fmt.Println("Message Found!")

	/* Write HTML */
	type Out struct {
		Success bool
		Message string
		Salt string
	}
	data := Out{true, encryptedText, salt}
	tmpl := template.Must(template.ParseFiles("static/html/viewClient.html", "static/html/top.html", "static/html/head.html"))
	tmpl.ExecuteTemplate(w, "viewClient", data)
}

/* Generate unique 128 random bits */
func generateTableId(db *sql.DB, tablename string) string {

	rand128bits := make([]byte, 16)
	_, err := rand.Read(rand128bits)
	if err != nil {
		log.Fatal(err)
	}
	id := hex.EncodeToString(rand128bits)

	/* Check for collision */
	var available bool
	test := fmt.Sprintf("SELECT COUNT(*) = 0 FROM %s WHERE id = %q", tablename, id)
	err = db.QueryRow(test).Scan(&available)

	if err != nil {
		fmt.Println("err.Error()")
		return id
	}

	if(available){
		return id
	} else {
		return generateTableId(db, tablename)
	}
}
