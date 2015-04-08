/* hub.go */

package main

/*	There is 1 hub per chatroom. Each hub:
	-Detects when client opens/closes socket.
	-Maintains the set of active socket connections (users)
	-Broadcasts messages to all members of the chatroom.	*/
type hub struct {

	chatroomId string

	// Registered connections.
	connections map[*connection]bool

	// Inbound messages from the connections.
	broadcast chan []byte

	// Register requests from the connections.
	register chan *connection

	// Unregister requests from connections.
	unregister chan *connection
}

/* */
func (h *hub) run() {
	for {
		select {
		case c := <-h.register:
			h.connections[c] = true
		case c := <-h.unregister:
			if _, ok := h.connections[c]; ok {
				delete(h.connections, c)
				close(c.send)

				/* All members have exited chat */
				if len(h.connections) == 0{
					deleteChatroom(h.chatroomId)
				}
			}
		case m := <-h.broadcast:
			for c := range h.connections {
				select {
				case c.send <- m:
				default:
					close(c.send)
					delete(h.connections, c)
				}
			}
		}
	}
}
