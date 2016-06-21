/* main.go */

package main
import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "database/sql"
    "encoding/base64"
    "encoding/hex"
    "errors"
    "fmt"
    "html/template"
    "io"
    "log"
    "net/http"
    "os"
    "strconv"
    "strings"
    "sync"
    "time"
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
    template.Must(template.ParseFiles("static/error.html")).Execute(w, Out{message})
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
        return nil, errors.New("Ciphertext too short")
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
    if r.Method != http.MethodPost {
        http.Error(w, "POST required", http.StatusMethodNotAllowed)
        return
    }
    
    text := r.PostFormValue("text")
    expireMinutes, err := strconv.Atoi(r.PostFormValue("expireMinutes"))
    if err != nil {
        expireMinutes = 43200   /* Default expire in 30 days */
    }
    
    if len(text) > 16000{
        writeError(w, "Message too long. Max character length is 16000.")
        return
    }
    
    /* Generate 128 bit key */
    key128bits := make([]byte, 16)
    _, err = rand.Read(key128bits)
    if err != nil {
        http.Error(w, "Something went wrong :(", http.StatusInternalServerError)
        return
    }
    
    /* Encrypt the text */
    encryptedtextBytes, err := encrypt(key128bits, []byte(text))
    if err != nil {
        http.Error(w, "Something went wrong :(", http.StatusInternalServerError)
        return
    }
    
    msgId := generateMsgId(db)
    _, err = db.Exec("insert into messages values (?, ?, ?, ?, ?, ?)", 
        msgId, hex.EncodeToString(encryptedtextBytes), nil, time.Now().Unix(), expireMinutes, true)
    
    if err != nil {
        http.Error(w, "Something went wrong :(", http.StatusInternalServerError)
        return
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
    if r.Method != http.MethodPost {
        http.Error(w, "POST required", http.StatusMethodNotAllowed)
        return
    }
    
    encryptedText := r.PostFormValue("text")
    salt := r.PostFormValue("salt")
    expireMinutes, err := strconv.Atoi(r.PostFormValue("expireMinutes"))
    if err != nil {
        expireMinutes = 43200   /* Default expire in 30 days */
    }
    
    if len(encryptedText) > 16000{
        writeError(w, "Message too long. Max character length is 16000.")
        return
    }
    
    msgId := generateMsgId(db)
    _, err = db.Exec("insert into messages values (?, ?, ?, ?, ?, ?)", 
        msgId, encryptedText, salt, time.Now().Unix(), expireMinutes, false)
    
    if err != nil {
        http.Error(w, "Something went wrong :(", http.StatusInternalServerError)
        return
    }
    
    w.Write([]byte("https://ephemeral.pw/view/client/" + msgId))
}

/* GET /view/server */
func viewServerHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
        http.Error(w, "GET required", http.StatusMethodNotAllowed)
        return
    }
    
    /* Blacklist sites that GET the url before sending to recipient */
    blacklist := [...]string{"facebook"}
    for _,e := range blacklist {
        if strings.Contains(r.UserAgent(), e) {
            fmt.Fprintf(w, "Go away %s! This is only for the recipient!", e)
            return
        }
    }
    
    /* ephemeral.pw/view/server/msgId/key/ */
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
        /* Key is not hex */
        writeError(w, "Message not found. It may have been deleted.")
        return
    }
    
    var m sync.Mutex
    m.Lock() /* ONLY ONE THREAD IN HERE AT A TIME */
    
    var encryptedText string
    err = db.QueryRow("SELECT encrypted_text FROM messages WHERE id = ?", msgId).Scan(&encryptedText)
    if err != nil {
        writeError(w, "Message not found. It may have been deleted.")
        return
    }
    
    /* Decrypt message */
    encryptedtextBytes , err := hex.DecodeString(encryptedText)
    if err != nil {
        writeError(w, "Message not found. It may have been deleted.")
        return
    }
    messageBytes, err := decrypt(keyBytes, []byte(encryptedtextBytes))
    if err != nil {
        /* Valid msgId, but invalid key */
        writeError(w, "Message not found. It may have been deleted.")
        return
    }
    
    db.Exec("DELETE FROM messages WHERE id = ? LIMIT 1", msgId)
    
    m.Unlock()
    
    type Out struct {
        Message []string
    }
    
    message := template.HTMLEscapeString(string(messageBytes))  /* no XSS */
    tmpl := template.Must(template.ParseFiles("static/viewServer.html"))
    tmpl.Execute(w, Out{strings.Split(message, "\n")})
}

/* GET /view/client */
func viewClientHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
        http.Error(w, "GET required", http.StatusMethodNotAllowed)
        return
    }
    
    /* Blacklist sites that GET the url before sending to recipient */
    blacklist := [...]string{"facebook"}
    for _,e := range blacklist {
        if strings.Contains(r.UserAgent(), e) {
            fmt.Fprintf(w, "Go away %s! This is only for the recipient!", e)
            return
        }
    }
    
    /* ephemeral.pw/view/client/msgId */
    queryString := strings.TrimSuffix(r.URL.Path[len("/view/client/"):],"/")
    params := strings.Split(queryString, "/")
    if len(params) != 1 {
        writeError(w, "Message not found. It may have been deleted.")
        return
    }
    msgId := params[0]
    
    var m sync.Mutex
    m.Lock() /* ONLY ONE THREAD IN HERE AT A TIME */
    
    var encryptedText string
    var salt string
    err := db.QueryRow("SELECT encrypted_text, salt FROM messages WHERE id = ?", msgId).Scan(&encryptedText, &salt)
    if err != nil {
        writeError(w, "Message not found. It may have been deleted.")
        return
    }
    
    db.Exec("DELETE FROM messages WHERE id = ? LIMIT 1", msgId)
    
    m.Unlock()
    
    type Out struct {
        Message string
        Salt string
    }
    
    tmpl := template.Must(template.ParseFiles("static/viewClient.html"))
    tmpl.Execute(w, Out{encryptedText, salt})
}

/* Generate unique 64 random bits */
func generateMsgId(db *sql.DB) string {
    
    rand64bits := make([]byte, 8)
    _, err := rand.Read(rand64bits)
    if err != nil {
        return generateMsgId(db)
    }
    id := hex.EncodeToString(rand64bits)
    
    /* Check for collision */
    var available bool
    db.QueryRow("SELECT COUNT(*) = 0 FROM messages WHERE id = ?", id).Scan(&available)
    
    if(available){
        return id
    } else {
        return generateMsgId(db)
    }
}
