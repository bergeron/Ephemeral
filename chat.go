/* chat.go */

package main
import (
	"net/http"
	"fmt"
	"log"
	"strings"
	"html/template"
	"encoding/json"
	"github.com/gorilla/websocket"
)

var chatIdToHub map[string]*hub = make(map[string]*hub)

/* Websocket to /chat/ws */
func serveWs(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", 405)
		return
	}

	chatroomId := r.FormValue("chatroomId")

	var upgrader = websocket.Upgrader{
		ReadBufferSize:  4096,
		WriteBufferSize: 4096,	
		CheckOrigin: func(r *http.Request) bool { return true },
	}

	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println(err)
		return
	}

	h := chatIdToHub[chatroomId]
	if h == nil{
		fmt.Println("Couldn't find hub.")
	}

	c := &connection{chatroomId: chatroomId, nicknameId: "sadf", hub: h, send: make(chan []byte, 256), ws: ws}
	c.hub.register <- c
	go c.writePump()
	c.readPump()
}


/* GET /chat */
func chatHandler(w http.ResponseWriter, r *http.Request) {

	queryString := strings.TrimSuffix(r.URL.Path[len("/"):],"/")
	params := strings.Split(queryString, "/")

	if len(params) == 2 {
		viewChatHandler(w,r)
	} else {

		type Out struct {
			Creating bool
		}
		tmpl := template.Must(template.ParseFiles("static/html/chat.html", "static/html/top.html",
													"static/html/head.html", "static/html/nicknamePrompt.html"))
		tmpl.ExecuteTemplate(w, "chat", Out{true})
	}
}

/* POST /chat/create */
func createChatHandler(w http.ResponseWriter, r *http.Request) {

	chatroomId := generateTableId(db, "chatrooms")

	/* New hub to broadcast messages to chatroom */
	var h = hub{
		chatroomId:	 chatroomId,
		broadcast:   make(chan []byte),
		register:    make(chan *connection),
		unregister:  make(chan *connection),
		connections: make(map[*connection]bool),
	}

	go h.run()

	chatIdToHub[chatroomId] = &h

	_, err := db.Exec("insert into chatrooms values (?, UTC_TIMESTAMP())", chatroomId)
	if err != nil {
		log.Fatal(err)
	}

	type Resp struct {
		ChatroomId 	string
	}

	json, err := json.Marshal(Resp{chatroomId})
	if err != nil {
		w.Write([]byte(err.Error()))
		fmt.Println(err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(json)
}

/* GET /chat/chatroomId */
func viewChatHandler(w http.ResponseWriter, r *http.Request) {

	/* get query params */
	queryString := strings.TrimSuffix(r.URL.Path[len("/chat/"):],"/")
	params := strings.Split(queryString, "/")
	if len(params) != 1 {
		writeError(w, "Chatroom not found. It may have been deleted.")
		return
	}

	chatroomId := params[0]

	var exists bool
	test := fmt.Sprintf("SELECT COUNT(*) > 0 FROM chatrooms WHERE id = %q", chatroomId)
	err := db.QueryRow(test).Scan(&exists)
	if err != nil {
		fmt.Println(err.Error())
		writeError(w, "Chatroom not found1. It may have been deleted!")
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
		EncryptedNicknames []string
		Creating bool
		ChatroomId string
	}

	tmpl := template.Must(template.ParseFiles("static/html/top.html", "static/html/head.html", "static/html/chat.html", "static/html/nicknamePrompt.html"))
	tmpl.ExecuteTemplate(w, "chat", Out{nicknames, false, chatroomId})
}

func setNickname(c *connection, encryptedNickname string, chatroomId string) {

	nicknameId := generateTableId(db, "nicknames")

	_, err := db.Exec("insert into nicknames values (?, ?, ?, UTC_TIMESTAMP())", nicknameId, chatroomId, encryptedNickname)
	if err != nil {
		fmt.Println(err.Error())
	}

	data := make(map[string]string)
	data["msgType"] = "nicknameId"
	data["nicknameId"] = nicknameId

	json, err := json.Marshal(data)
	if err != nil {
		fmt.Println(err.Error())
		json = []byte("Error")
	}

	err = c.write(websocket.TextMessage, json)
	if err != nil{
		return
	}
}

/* /chat/invite/ */
func inviteHandler(w http.ResponseWriter, r *http.Request) {

	queryString := strings.TrimSuffix(r.URL.Path[len("/"):],"/")
	params := strings.Split(queryString, "/")

	if len(params) == 2 {
		inviteViewHandler(w,r)
	} else {
		inviteCreateHandler(w,r)
	}
}

/* GET /invite/inviteId */
func inviteViewHandler(w http.ResponseWriter, r *http.Request) {

	/* Blacklist sites that GET the url before sending to recipient */
	blacklist := [...]string{"facebook"}
	
	for _,e := range blacklist {
		if strings.Contains(r.UserAgent(), e) {
			fmt.Fprintf(w, "Go away %s! This is only for the recipient!", e)
			return
		}
	}

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

	url := "https://" + r.Host + "/chat/" + chatroomId
	http.Redirect(w, r, url, 303)		
}

/* POST /invite */
func inviteCreateHandler(w http.ResponseWriter, r *http.Request) {

	inviteId := generateTableId(db, "invites")
	chatroomId := r.FormValue("chatroomId")

	_, err := db.Exec("insert into invites values (?, ?, UTC_TIMESTAMP())", inviteId, chatroomId)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	w.Write([]byte(inviteId))
}

func deleteChatroom(chatroomId string){
	delete(chatIdToHub, chatroomId)

	_, err := db.Exec("DELETE FROM chatrooms WHERE id = ?", chatroomId)
	if err != nil {
		fmt.Println(err.Error())
	}

	_, err = db.Exec("DELETE FROM nicknames WHERE chatroom_id = ?", chatroomId)
	if err != nil {
		fmt.Println(err.Error())
	}

	_, err = db.Exec("DELETE FROM invites WHERE chatroom_id = ?", chatroomId)
	if err != nil {
		fmt.Println(err.Error())
	}
}

func hubPreProcessor(c *connection, data map[string]string) []byte {

	/* Convert nicknameId to encryptedNickname */
	if data["msgType"] == "newMessage"{

		nicknameId := data["nicknameId"]
		var encryptedNickname string
		err := db.QueryRow("SELECT encrypted_nickname FROM nicknames WHERE id= ?", nicknameId).Scan(&encryptedNickname)
		if err != nil {
			fmt.Println("No nickname found with id: " + nicknameId)
			encryptedNickname = "Unknown"
		}
		delete(data, "nicknameId")
		data["encryptedNickname"] = encryptedNickname

	} else if data["msgType"] == "newMember"{
		setNickname(c, data["encryptedNickname"], data["chatroomId"])
	} else if data["msgType"] == "keyExchangeReq"{
		//
	} else if data["msgType"] == "keyExchangeResp"{
		//
	} else {
		fmt.Println("Unknown Message Type")
	}

	json, err := json.Marshal(data)
	if err != nil {
		fmt.Println(err.Error())
		json = []byte("Error")
	}

	return json
}
