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
    "os"
    "sync"
    "time"
    "strconv"
    "database/sql"
    _ "github.com/go-sql-driver/mysql"
)

var db *sql.DB = connectDb()

func main() {
    http.HandleFunc("/create/server/", createServerHandler)
    http.HandleFunc("/create/client/", createClientHandler)
    http.HandleFunc("/view/server/", viewServerHandler)
    http.HandleFunc("/view/client/", viewClientHandler)
    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        http.ServeFile(w, r, "static/home.html")
    })
    
    fs := http.FileServer(http.Dir("static"))
    http.Handle("/static/", http.StripPrefix("/static/", fs))
    
    err := http.ListenAndServe(":11994", nil)
    if err != nil {
        log.Fatal(err)
    }
}

func connectDb() (*sql.DB){
    tablename := "Ephemeral"
    username := os.Getenv("ephemeralUsername")
    password := os.Getenv("ephemeralPassword")

    db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@/%s", username, password, tablename))
    if err != nil {
        log.Fatal(err)
    }
    
    /* Test connection */
    err = db.Ping()
    if err != nil {
        log.Fatal(err)
    }
    return db
}

/* Write the given error message as HTML */
func writeError(w http.ResponseWriter, message string){
    type Out struct {
        Message string
    }
    
    tmpl := template.Must(template.ParseFiles("static/error.html"))
    tmpl.Execute(w, Out{message})
}

/* 128 bit AES */
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

/* 128 bit AES */
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
        expireMinutes = 43200   /* Default expire in 30 days */
    }
    
    /* Insert message into db */
    _, err = db.Exec("insert into messages values (?, ?, ?, ?, ?, ?)", 
                        msgId, encryptedtext, nil, time.Now().Unix(), expireMinutes, true)
    if err != nil {
        log.Fatal(err)
    }
    
    type Out struct {
        MsgId string
        Key string
    }
    
    tmpl := template.Must(template.ParseFiles("static/create.html"))
    tmpl.Execute(w, Out{msgId, hex.EncodeToString(key128bits)})
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
        expireMinutes = 43200   /* Default expire in 30 days */
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
    
    /* Delete message from db */
    _, err = db.Exec("DELETE FROM messages WHERE id = ? LIMIT 1", msgId)
    if err != nil {
        fmt.Println("Message already deleted.")     /* Shouldn't happen */
    }
    
    m.Unlock()  /*DONE */
    
    message := template.HTMLEscapeString(string(messageBytes))  /* no XSS */
    
    type Out struct {
        Message []string
    }
    data := Out{strings.Split(message, "\n")}
    tmpl := template.Must(template.ParseFiles("static/viewServer.html"))
    tmpl.Execute(w, data)
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
        fmt.Println("Message already deleted.")     /* Shouldn't happen */
    }
    
    m.Unlock()  /*DONE */
    
    type Out struct {
        Message string
        Salt string
    }
    
    tmpl := template.Must(template.ParseFiles("static/viewClient.html"))
    tmpl.Execute(w, Out{encryptedText, salt})
}

/* Generate unique 64 random bits */
func generateTableId(db *sql.DB, tablename string) string {
    
    rand128bits := make([]byte, 8)
    _, err := rand.Read(rand128bits)
    if err != nil {
        log.Fatal(err)
    }
    id := hex.EncodeToString(rand128bits)
    
    /* Check for collision */
    var available bool
    test := fmt.Sprintf("SELECT COUNT(*) = 0 FROM %s WHERE id = %q", tablename, id)
    db.QueryRow(test).Scan(&available)
    
    if(available){
        return id
    } else {
        return generateTableId(db, tablename)
    }
}
