/* main.go */

package main
import (
    "net/http"
    "crypto/rand"
    "fmt"
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
    "bytes"
    "encoding/json"
    _ "github.com/go-sql-driver/mysql"
    _ "github.com/gorilla/websocket"
    "golang.org/x/crypto/openpgp"
)

var db *sql.DB = connectDb()

func main() {
    http.HandleFunc("/", homeHandler)
    http.HandleFunc("/about/", aboutHandler)
    http.HandleFunc("/send/", sendHandler)
    http.HandleFunc("/refresh/", refreshHandler)

    fs := http.FileServer(http.Dir("static"))
    http.Handle("/static/", http.StripPrefix("/static/", fs))

    err := http.ListenAndServe(":11994", nil)
    if err != nil {
        log.Fatal(err)
    }
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

/* GET / */
func homeHandler(w http.ResponseWriter, r *http.Request) {
    tmpl := template.Must(template.ParseFiles("static/html/home.html"))
    tmpl.ExecuteTemplate(w, "home", nil)
}

/* GET /about */
func aboutHandler(w http.ResponseWriter, r *http.Request) {
    tmpl := template.Must(template.ParseFiles("static/html/about.html"))
    tmpl.ExecuteTemplate(w, "about", nil)
}

/* POST /send/ */
func sendHandler(w http.ResponseWriter, r *http.Request) {

    ct := r.FormValue("ct")
    toPubStr := r.FormValue("toPubStr")
    fromPubStr :=  r.FormValue("fromPubStr")

    expireMinutes, err := strconv.Atoi(r.FormValue("expireMinutes"))
    if err != nil {
        expireMinutes = 4320
    } 
  
    _, err = db.Exec("insert into messages values (?, ?, ?, ?, ?)", 
                        ct, fromPubStr, toPubStr, time.Now().Unix(), expireMinutes)
    if err != nil {
        log.Fatal(err)
        w.Write([]byte("fail"))
    }

    w.Write([]byte("success"))
}

/* GET /refresh/ */
func refreshHandler(w http.ResponseWriter, r *http.Request) {
    blacklist := [...]string{"facebook"}
    
    for _,e := range blacklist {
        if strings.Contains(r.UserAgent(), e) {
            fmt.Fprintf(w, "Go away %s! This is only for the recipient!", e)
            return
        }
    }

    pubStr := r.FormValue("pubStr")
    signature := r.FormValue("signature")
    
    if !verifySignature(pubStr, signature){
        w.Write([]byte("failed"))
        return
    }
    
    var m sync.Mutex
    m.Lock() /* ONLY ONE THREAD IN HERE AT A TIME */

    rows, err := db.Query("SELECT ct FROM messages WHERE to_pub_str = ?", pubStr)
    if err != nil {
        fmt.Println(err.Error())
    }
    if rows.Err() != nil {
        fmt.Println(err.Error())
    }

    messages := []string{}

    defer rows.Close()
    for rows.Next() {
        var ct string
        err = rows.Scan(&ct)
        messages = append(messages, ct)
    }
    
    _, err = db.Exec("DELETE FROM messages WHERE to_pub_str = ?", pubStr)
    if err != nil {
        fmt.Println(err.Error())
    }

    m.Unlock()  /*DONE */

    type Out struct {
        Success bool
        Messages []string
    }

    json, err := json.Marshal(Out{true, messages})
    if err != nil {
        w.Write([]byte(err.Error()))
        fmt.Println(err.Error())
        return
    }

    w.Header().Set("Content-Type", "application/json")
    w.Write(json)

}

func verifySignature(pubStr string, signature string)(bool){
    msgNoArmor := "Proof I own the key: " + pubStr

    keyring, err := openpgp.ReadArmoredKeyRing(bytes.NewBufferString(pubStr))
    if err != nil {
            fmt.Printf("failed to parse public key: %s", err)
    }
   
    entity, err := openpgp.CheckArmoredDetachedSignature(keyring, bytes.NewBufferString(msgNoArmor),  bytes.NewBufferString(signature));
    
    if err != nil {
        fmt.Printf("failed to check signature: %s", err)
        return false
    } else if keyring[0].PrimaryKey.KeyId == entity.PrimaryKey.KeyId {
        fmt.Println("VERIFIED")
        return true
    }
    
    return false
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
