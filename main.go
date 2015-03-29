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
	"encoding/json"
	_ "github.com/go-sql-driver/mysql"
	_ "github.com/gorilla/websocket"
)

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
	http.HandleFunc("/chat/addMsg/", addMsgChatHandler(db))
	http.HandleFunc("/chat/update/", updateChatHandler(db))
	http.HandleFunc("/chat/setNickname/", setNicknameHandler(db))
	http.HandleFunc("/invite/", inviteHandler(db))


	fs := http.FileServer(http.Dir("static"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))

	/* SSL/TLS */
	// path_to_certificate := "/etc/nginx/ssl/ephemeral/concat_server_and_CA_certs.pem"
	// path_to_key := "/etc/nginx/ssl/ephemeral/private.key"
	err = http.ListenAndServe(":11994", nil)
	if err != nil {
		log.Fatal(err)
	}
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
func createServerHandler (db *sql.DB) func(http.ResponseWriter, *http.Request) {
	return  func(w http.ResponseWriter, r *http.Request) {

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
			url := "https://" + os.Getenv("EPHEMERAL_HOST") + "/view/server/" +msgId + "/" + hex.EncodeToString(key128bits)
			w.Write([]byte(url))
		} else {	/* Return html */
			
			type Out struct {
				Host string
				SecretString string
				KeyString string
			}
			data := Out{os.Getenv("EPHEMERAL_HOST"), msgId, hex.EncodeToString(key128bits)}
			tmpl := template.Must(template.ParseFiles("static/html/create.html", "static/html/top.html", "static/html/head.html"))
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

		msgId := generateTableId(db, "messages")
		salt := r.FormValue("salt")

		fmt.Println("Create: ")
		fmt.Println(salt)

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
		tmpl := template.Must(template.ParseFiles("static/html/viewClient.html", "static/html/top.html", "static/html/head.html"))
		tmpl.ExecuteTemplate(w, "viewClient", data)
	}
}

/* GET /chat */
func chatHandler(db *sql.DB) func(http.ResponseWriter, *http.Request) {
	return  func(w http.ResponseWriter, r *http.Request) {

		queryString := strings.TrimSuffix(r.URL.Path[len("/"):],"/")
		params := strings.Split(queryString, "/")

		if len(params) == 2 {
			viewChatHandler(db)(w,r)
		} else {

			type Out struct {
				Creating bool
			}
			tmpl := template.Must(template.ParseFiles("static/html/chatCreate.html", "static/html/top.html", "static/html/head.html", "static/html/chat.html", "static/html/chatPrompt.html"))
			tmpl.ExecuteTemplate(w, "chatCreate", Out{true})
		}
	}
}

/* POST /chat/create */
func createChatHandler(db *sql.DB) func(http.ResponseWriter, *http.Request) {
	return  func(w http.ResponseWriter, r *http.Request) {

		chatroomId := generateTableId(db, "chatrooms")
		chatMsgId := generateTableId(db, "messages")
		nicknameId := generateTableId(db, "nicknames")
		encryptedNickname := r.FormValue("encryptedNickname")
		encryptedWelcome := r.FormValue("encryptedWelcome")
		salt := r.FormValue("salt")

		fmt.Println(encryptedWelcome)

		/* Insert chat, nickname into db */
		expireMinutes := 43200	/* Default expire in 30 days */
		_, err := db.Exec("insert into chatrooms values (?, ?, UTC_TIMESTAMP(6))", chatroomId, salt)
		_, err = db.Exec("insert into nicknames values (?, ?, ?, UTC_TIMESTAMP(6))", nicknameId, chatroomId, encryptedNickname)
		_, err = db.Exec("insert into chat_msgs values (?, ?, ?, ?, ?, UTC_TIMESTAMP(6), ?)", chatMsgId, chatroomId, encryptedWelcome, encryptedNickname, 0, expireMinutes)
		if err != nil {
			log.Fatal(err)
		}

		type Resp struct {
			ChatroomId 	string
			NicknameId 	string
			OldestId 	string
		}

		json, err := json.Marshal(Resp{chatroomId, nicknameId, chatMsgId})
		if err != nil {
			w.Write([]byte(err.Error()))
			fmt.Println(err)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(json)
	}
}

/* GET /chat/chatroomId */
func viewChatHandler(db *sql.DB) func(http.ResponseWriter, *http.Request) {
	return  func(w http.ResponseWriter, r *http.Request) {

		/* get query params */
		queryString := strings.TrimSuffix(r.URL.Path[len("/chat/"):],"/")
		params := strings.Split(queryString, "/")
		if len(params) != 1 {
			writeError(w, "Chatroom not found. It may have been deleted.")
			return
		}

		chatroomId := params[0]

		var salt string
		err := db.QueryRow("SELECT salt FROM chatrooms WHERE id = ?", chatroomId).Scan(&salt)
		if err != nil{
			fmt.Println(err.Error())
			writeError(w, "Chatroom not found. It may have been deleted!!!.")
			return
		}

		rows, err := db.Query("SELECT encrypted_nickname FROM nicknames WHERE chatroom_id=?", chatroomId)
		if err != nil {
			fmt.Println(err.Error())
			return
		}

		nicknames := []string{}

		defer rows.Close()
	    for rows.Next() {
			var encrypted_nickname string
			err = rows.Scan(&encrypted_nickname)
			nicknames = append(nicknames, encrypted_nickname)
		}
		err = rows.Err()

		if err != nil {
			fmt.Println(err.Error())
		}

		type Out struct {
			Salt string
			EncryptedNicknames []string
			Creating bool
		}

		tmpl := template.Must(template.ParseFiles("static/html/chatView.html", "static/html/top.html", "static/html/head.html", "static/html/chat.html", "static/html/chatPrompt.html"))
		tmpl.ExecuteTemplate(w, "chatView", Out{salt, nicknames, false})
	}
}

/* POST /chat/addmsg */
func addMsgChatHandler(db *sql.DB) func(http.ResponseWriter, *http.Request) {
	return  func(w http.ResponseWriter, r *http.Request) {

		chatMsgId := generateTableId(db, "chat_msgs")
		chatroomId := r.FormValue("chatroomId")
		encryptedText := r.FormValue("encryptedText")
		nicknameId := r.FormValue("nicknameId")
		var encrypted_nickname string

		err := db.QueryRow("SELECT encrypted_nickname FROM nicknames WHERE id= ?", nicknameId).Scan(&encrypted_nickname)
		if err != nil {
			fmt.Println("No nickname found with id: " + nicknameId)
			writeError(w, "Nickname not found.")
			return
		}

		/* Lookup chat in db */
		err = db.QueryRow("SELECT id FROM chatrooms WHERE id= ?", chatroomId).Scan(&chatroomId)
		if err != nil {
			fmt.Println("No chatroom found with chatroom_id: " + chatroomId)
			writeError(w, "Chatroom not found. It may have been deleted.")
			return
		}

		/* Insert message into db */
		expireMinutes := 43200	/* Default expire in 30 days */
		_, err = db.Exec("insert into chat_msgs values (?, ?, ?, ?, ?, UTC_TIMESTAMP(6), ?)", 
							chatMsgId, chatroomId, encryptedText, encrypted_nickname, 0, expireMinutes)
		if err != nil {
			log.Fatal(err)
		}

		w.Write([]byte("added message"))

	}
}


/* GET /chat/update */
func updateChatHandler(db *sql.DB) func(http.ResponseWriter, *http.Request) {
	return  func(w http.ResponseWriter, r *http.Request) {

		chatroomId := r.FormValue("chatroomId")
		dtUpdateAfter := r.FormValue("dtUpdateAfter")

		fmt.Println(dtUpdateAfter)

		rows, err := db.Query("SELECT id, encrypted_text, encrypted_nickname, views FROM chat_msgs WHERE chatroom_id=? and dt_created >= ? ORDER BY dt_created ASC", chatroomId, dtUpdateAfter)
		if err != nil {
			fmt.Println(err.Error())
			return
		}

		var newDtUpdateAfter string
		err = db.QueryRow("select UTC_TIMESTAMP(6)").Scan(&newDtUpdateAfter)
		if err != nil {
			fmt.Println(err.Error())
			return
		}

		var numMembers int
		db.QueryRow("SELECT COUNT(*) from nicknames WHERE chatroom_id=?", chatroomId).Scan(&numMembers)
		if err != nil {
			fmt.Println(err.Error())
		}

		type ChatMsg struct{
			EncryptedText 	string
			EncryptedNickname 	string
		}

		msgs := []ChatMsg{}

		defer rows.Close()
		for rows.Next() {
			var id string
			var encrypted_text string
			var encrypted_nickname string
			var views int
			err = rows.Scan(&id, &encrypted_text, &encrypted_nickname, &views)

			// /* Delete the msg. Everyone has seen it. */
			// if (views + 1) == numMembers {
			// 	_, err = db.Exec("DELETE FROM chat_msgs WHERE id = ?", id)
			// 	if err != nil {
			// 		fmt.Println(err.Error())
			// 	}
			// } else {
			// 	// increment views
			// }

			msgs = append(msgs, ChatMsg{encrypted_text, encrypted_nickname})
		}
		err = rows.Err()

		if err != nil {
			fmt.Println(err.Error())
		}

		type Resp struct{
			Messages 	[]ChatMsg
			DtUpdateAfter 	string
		}

		json, err := json.Marshal(Resp{msgs, newDtUpdateAfter})
		if err != nil {
			w.Write([]byte(err.Error()))
			fmt.Println(err)
			return
		}

	    w.Header().Set("Content-Type", "application/json")
	    w.Write(json)

	}
}

/* POST /chat/setNickname */
func setNicknameHandler(db *sql.DB) func(http.ResponseWriter, *http.Request) {
	return  func(w http.ResponseWriter, r *http.Request) {

		chatMsgId := generateTableId(db, "messages")
		nicknameId := generateTableId(db, "nicknames")
		chatroomId := r.FormValue("chatroomId")
		encryptedNickname := r.FormValue("encryptedNickname")
		encryptedWelcome := r.FormValue("encryptedWelcome")

		expireMinutes := 43200	/* Default expire in 30 days */
		_, err := db.Exec("insert into nicknames values (?, ?, ?, UTC_TIMESTAMP(6))", nicknameId, chatroomId, encryptedNickname)
		_, err = db.Exec("insert into chat_msgs values (?, ?, ?, ?, ?, UTC_TIMESTAMP(6), ?)", chatMsgId, chatroomId, encryptedWelcome, encryptedNickname, 0, expireMinutes)
		if err != nil {
			log.Fatal(err)
		}

		type Resp struct{
			NicknameId 	string
		}

		json, err := json.Marshal(Resp{nicknameId})
		if err != nil {
			w.Write([]byte(err.Error()))
			fmt.Println(err.Error())
			return
		}

		w.Write([]byte(json))
	}
}

/* /chat/invite/ */
func inviteHandler(db *sql.DB) func(http.ResponseWriter, *http.Request) {
	return  func(w http.ResponseWriter, r *http.Request) {

		queryString := strings.TrimSuffix(r.URL.Path[len("/"):],"/")
		params := strings.Split(queryString, "/")

		if len(params) == 2 {
			inviteViewHandler(db)(w,r)
		} else {
			inviteCreateHandler(db)(w,r)
		}
	}
}

/* GET /invite/inviteId */
func inviteViewHandler(db *sql.DB) func(http.ResponseWriter, *http.Request) {
	return  func(w http.ResponseWriter, r *http.Request) {

		/* get query params */
		queryString := strings.TrimSuffix(r.URL.Path[len("/invite/"):],"/")
		params := strings.Split(queryString, "/")
		if len(params) != 1 {
			writeError(w, "Invite not found. It may have been deleted.")
			return
		}

		inviteId := params[0]

		var chatroomId string
		err := db.QueryRow("SELECT chatroom_id FROM invites WHERE id=?", inviteId).Scan(&chatroomId)
		if err != nil {
			writeError(w, "Invite not found. It may have already been used.")
			return
		}

		/* Delete invite from db */
		_, err = db.Exec("DELETE FROM invites WHERE id = ?", inviteId)
		if err != nil {
			fmt.Println(err.Error())
		}

		url := "http://localhost:11994/chat/" + chatroomId
		http.Redirect(w, r, url, 303)		
	}
}

/* POST /invite */
func inviteCreateHandler(db *sql.DB) func(http.ResponseWriter, *http.Request) {
	return  func(w http.ResponseWriter, r *http.Request) {

		inviteId := generateTableId(db, "invites")
		chatroomId := r.FormValue("chatroomId")

		_, err := db.Exec("insert into invites values (?, ?, UTC_TIMESTAMP(6))", inviteId, chatroomId)
		if err != nil {
			fmt.Println(err.Error())
			return
		}

		w.Write([]byte(inviteId))
	}
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
