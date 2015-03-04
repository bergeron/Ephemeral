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

		msgId := generateMsgId(db)

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
		_, err = db.Exec("insert into messages values (?, ?, ?, ?, ?, ?)", msgId, encryptedtext, nil, time.Now().Unix(), expireMinutes, true)
		if err != nil {
			log.Fatal(err)
		}

		format := r.FormValue("format")
		if format == "url" {	/* Return only url */
			url := "https://" + os.Getenv("EPHEMERAL_HOST") + "/view/server/" +msgId + "/" + hex.EncodeToString(key128bits)
			w.Write([]byte(url))
		} else {	/* Return html */
			
			type Out struct {
				Host string
				SecretString string
				KeyString string
			}
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

		msgId := generateMsgId(db)
		salt := r.FormValue("salt")

		fmt.Println("Create: ")
		fmt.Println(salt)

		/* Set expiration date */
		expireMinutes, err := strconv.Atoi(r.FormValue("expireMinutes"))
		if err != nil {
			expireMinutes = 43200	/* Default expire in 30 days */
		}

		/* Insert message into db */
		_, err = db.Exec("insert into messages values (?, ?, ?, ?, ?, ?)", msgId, encryptedText, salt, time.Now().Unix(), expireMinutes, false)
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
		tmpl := template.Must(template.ParseFiles("static/viewClient.html", "static/top.html", "static/head.html"))
		tmpl.ExecuteTemplate(w, "viewClient", data)
	}
}


/* Generate unique 128 random bits */
func generateMsgId(db *sql.DB) string {

	msgId128bits := make([]byte, 16)
	_, err := rand.Read(msgId128bits)
	if err != nil {
		log.Fatal(err)
	}

	msgId := hex.EncodeToString(msgId128bits)

	/* Check for collision */
	var available bool
	err = db.QueryRow("SELECT COUNT(*) = 0 FROM messages WHERE id = ?", msgId).Scan(&available)
	if err != nil {
		fmt.Println("Error checking msgId collision.")
		return msgId
	}

	if(available){
		return msgId
	} else {
		return generateMsgId(db)
	}
}


/* GET /chat */
func chatHandler(db *sql.DB) func(http.ResponseWriter, *http.Request) {
	return  func(w http.ResponseWriter, r *http.Request) {
		tmpl := template.Must(template.ParseFiles("static/chatCreate.html", "static/top.html", "static/head.html"))
		tmpl.ExecuteTemplate(w, "chatCreate", nil)
	}
}


/* POST /chat/create */
func createChatHandler(db *sql.DB) func(http.ResponseWriter, *http.Request) {
	return  func(w http.ResponseWriter, r *http.Request) {

		/* Generate 128 random bits */
		chatId128bits := make([]byte, 16)
		_, err := rand.Read(chatId128bits)
		if err != nil {
			log.Fatal(err)
		}

		chatId := hex.EncodeToString(chatId128bits)

		/* Insert chat into db */
		_, err = db.Exec("insert into chats values (?, ?)", chatId, time.Now())
		if err != nil {
			log.Fatal(err)
		}

		url := "http://" + os.Getenv("EPHEMERAL_HOST") + "/chat/view/" + chatId
		w.Write([]byte(url))
	}
}

/* GET /chat/view */
func viewChatHandler(db *sql.DB) func(http.ResponseWriter, *http.Request) {
	return  func(w http.ResponseWriter, r *http.Request) {

		/* get query params */
		queryString := strings.TrimSuffix(r.URL.Path[len("/chat/view/"):],"/")
		params := strings.Split(queryString, "/")
		if len(params) != 1 {
			writeError(w, "Chat not found. It may have been deleted.")
			return
		}

		chatId := params[0]

		/* Lookup chat in db */
		err := db.QueryRow("SELECT chatId FROM chats WHERE chatId=?", chatId).Scan(&chatId)
		if err != nil {
			fmt.Println("No chat found with chatId: " + chatId)
			writeError(w, "Chat not found. It may have been deleted.")
			return
		}


		rows, err := db.Query("SELECT encrypted_text, username from chat_msgs where chatId=?", chatId)
		if err != nil {
			fmt.Println("No chat messages found with chatId: " + chatId)
			writeError(w, "Chat not found. It may have been deleted.")
			return
		}

		defer rows.Close()
	    for rows.Next() {
	            var encrypted_text string
	            var username string
	            if err := rows.Scan(&encrypted_text, &username); err != nil {
	                    log.Fatal(err)
	            }
	            fmt.Printf("%s \n\n %s\n", encrypted_text, username)
	    }
	    if err := rows.Err(); err != nil {
	            log.Fatal(err)
	    }


		tmpl := template.Must(template.ParseFiles("static/chatView.html", "static/top.html", "static/head.html"))
		tmpl.ExecuteTemplate(w, "chatView", nil)
	}
}

/* POST /chat/addmsg */
func addMsgChatHandler(db *sql.DB) func(http.ResponseWriter, *http.Request) {
	return  func(w http.ResponseWriter, r *http.Request) {

		chatId := "TODO_chatid"
		encryptedText := "TODO_encrypted_text"
		username := "TODO_username"
		dt_delete := time.Now()

		/* Lookup chat in db */
		err := db.QueryRow("SELECT chatId FROM chats WHERE chatId= ?", chatId).Scan(&chatId)
		if err != nil {
			fmt.Println("No chat found with chatId: " + chatId)
			writeError(w, "Chat not found. It may have been deleted.")
			return
		}

		/* Insert message into db */
		_, err = db.Exec("insert into chat_msgs values (?, ?, ?, ?, ?)", chatId, encryptedText, username, time.Now(), dt_delete)
		if err != nil {
			log.Fatal(err)
		}

		w.Write([]byte("added message"))

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
	http.HandleFunc("/chat/", chatHandler(db))
	http.HandleFunc("/chat/create/", createChatHandler(db))
	http.HandleFunc("/chat/view/", viewChatHandler(db))
	http.HandleFunc("/chat/addmsg/", addMsgChatHandler(db))

	fs := http.FileServer(http.Dir("static"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))

	/* SSL/TLS */
	path_to_certificate := "/etc/nginx/ssl/ephemeral/concat_server_and_CA_certs.pem"
	path_to_key := "/etc/nginx/ssl/ephemeral/private.key"

	err = http.ListenAndServe(":11994", nil)
	if err != nil {
		log.Fatal(err)
	}
}
