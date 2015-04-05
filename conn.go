// Copyright 2013 The Gorilla WebSocket Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"github.com/gorilla/websocket"
	"log"
	"net/http"
	"time"
	"encoding/json"
	"fmt"
)

// connection is an middleman between the websocket connection and the hub.
// There is 1 socket connection for each chat member. Each connection
// is associated with 1 hub. When the user writes a message to the socket
// connection, the message is passed to the hub for broadcast.
// When the connection receives a message from the hub, it is written to the user.
type connection struct {

	chatroomId string

	hub *hub

	// The websocket connection.
	ws *websocket.Conn

	// Buffered channel of outbound messages.
	send chan []byte
}

const (
	// Time allowed to write a message to the peer.
	writeWait = 10 * time.Second

	// Time allowed to read the next pong message from the peer.
	pongWait = 60 * time.Second

	// Send pings to peer with this period. Must be less than pongWait.
	pingPeriod = (pongWait * 9) / 10

	// Maximum message size allowed from peer.
	maxMessageSize = 4096
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
}

/* Converts to JSON */
func parseMessage(data map[string]string) []byte {

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
		//
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

// readPump pumps messages from the websocket connection to the hub. (User sending msg)
func (c *connection) readPump() {
	defer func() {
		c.hub.unregister <- c
		c.ws.Close()
	}()
	c.ws.SetReadLimit(maxMessageSize)
	c.ws.SetReadDeadline(time.Now().Add(pongWait))
	c.ws.SetPongHandler(func(string) error { c.ws.SetReadDeadline(time.Now().Add(pongWait)); return nil })
	for {
		_, bytes, err := c.ws.ReadMessage()
		if err != nil {
			break
		}

		var data map[string]string

		err = json.Unmarshal(bytes, &data);
		if err != nil{
			fmt.Println(err.Error())
			break
		}

		c.hub.broadcast <- parseMessage(data)
	}
}

// write writes a message with the given message type and payload.
func (c *connection) write(mt int, payload []byte) error {
	c.ws.SetWriteDeadline(time.Now().Add(writeWait))
	return c.ws.WriteMessage(mt, payload)
}

// writePump pumps messages from the hub to the websocket connection. (User receiving msg)
func (c *connection) writePump() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		c.ws.Close()
	}()
	for {
		select {
		case message, ok := <-c.send:
			if !ok {
				c.write(websocket.CloseMessage, []byte{})
				return
			}
			if err := c.write(websocket.TextMessage, message); err != nil {
				return
			}
		case <-ticker.C:
			if err := c.write(websocket.PingMessage, []byte{}); err != nil {
				return
			}
		}
	}
}

// initiates websocket requests from the peer.
func serveWs(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", 405)
		return
	}

	chatroomId := r.FormValue("chatroomId")

	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println(err)
		return
	}

	h := chatIdToHub[chatroomId]
	c := &connection{chatroomId: chatroomId, hub: h, send: make(chan []byte, 256), ws: ws}
	c.hub.register <- c
	go c.writePump()
	c.readPump()
}
