// Main logic/functionality for the web application.
// This is where you need to implement your own server.
package main

// Reminder that you're not allowed to import anything that isn't part of the Go standard library.
// This includes golang.org/x/
import (
	"database/sql"
	"fmt"
	"io/ioutil"
	_ "io/ioutil"
	"net/http"
	"os"
	_ "os"
	"path/filepath"
	_ "path/filepath"
	"regexp"
	"strings"
	"text/template"
	"time"

	log "github.com/sirupsen/logrus"
)

func processRegistration(response http.ResponseWriter, request *http.Request) {
	username := request.FormValue("username")
	password := request.FormValue("password")

	// Check if username already exists
	row := db.QueryRow("SELECT username FROM users WHERE username = ?", username)
	var savedUsername string
	err := row.Scan(&savedUsername)
	if err != sql.ErrNoRows {
		response.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(response, "username %s already exists", savedUsername)
		return
	}

	// Generate salt
	const saltSizeBytes = 16
	salt, err := randomByteString(saltSizeBytes)
	if err != nil {
		response.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(response, err.Error())
		return
	}

	hashedPassword := hashPassword(password, salt)

	_, err = db.Exec("INSERT INTO users VALUES (NULL, ?, ?, ?)", username, hashedPassword, salt)

	if err != nil {
		response.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(response, err.Error())
		return
	}

	// Set a new session cookie
	initSession(response, username)

	// Redirect to next page
	http.Redirect(response, request, "/", http.StatusFound)
}

func processLoginAttempt(response http.ResponseWriter, request *http.Request) {
	// Retrieve submitted values
	username := request.FormValue("username")
	password := request.FormValue("password")

	row := db.QueryRow("SELECT password, salt FROM users WHERE username = ?", username)

	// Parse database response: check for no response or get values
	var encodedHash, encodedSalt string
	err := row.Scan(&encodedHash, &encodedSalt)
	if err == sql.ErrNoRows {
		response.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(response, "unknown user")
		return
	} else if err != nil {
		response.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(response, err.Error())
		return
	}

	// Hash submitted password with salt to allow for comparison
	submittedPassword := hashPassword(password, encodedSalt)

	// Verify password
	if submittedPassword != encodedHash {
		fmt.Fprintf(response, "incorrect password")
		return
	}

	// Set a new session cookie
	initSession(response, username)

	// Redirect to next page
	http.Redirect(response, request, "/", http.StatusFound)
}

func processLogout(response http.ResponseWriter, request *http.Request) {
	// get the session token cookie
	cookie, err := request.Cookie("session_token")
	// empty assignment to suppress unused variable warning
	if err != nil {
		response.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(response, err.Error())
		return
	}


	// get username of currently logged in user
	username := getUsernameFromCtx(request)
	// empty assignment to suppress unused variable warning
	_= username
	//////////////////////////////////
	// BEGIN TASK 2: YOUR CODE HERE
	//////////////////////////////////

	// TODO: clear the session token cookie in the user's browser
	// HINT: to clear a cookie, set its MaxAge to -1
	cookie.MaxAge = -1
	// TODO: delete the session from the database
	_, err = db.Exec("DELETE FROM sessions WHERE token = ?", cookie.Value)
	if err != nil{
		response.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(response, err.Error())
		return
	}
	//////////////////////////////////
	// END TASK 2: YOUR CODE HERE
	//////////////////////////////////

	// redirect to the homepage
	http.Redirect(response, request, "/", http.StatusSeeOther)
}

func processUpload(response http.ResponseWriter, request *http.Request, username string) {

	//////////////////////////////////
	// BEGIN TASK 3: YOUR CODE HERE
	//////////////////////////////////
	file_obj, header, err := request.FormFile("file")
	filename := header.Filename
	if len(filename) > 50 || len(filename) < 1 {
		response.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(response, err.Error())
		return
	}
	reg, err := regexp.Compile("[^a-zA-Z0-9.]+")
	notValid := reg.Match([]byte(filename))
	if notValid {
		response.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(response, err.Error())
		return
	}
	fileData, err := ioutil.ReadAll(file_obj)
	defer file_obj.Close()
	if err != nil {
		response.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(response, err.Error())
		return
	}
	fileResolution := filepath.Join(filePath, username)
	err = os.Mkdir(fileResolution, 0644)
	fileResolution = filepath.Join(fileResolution, filename)
	err = ioutil.WriteFile(fileResolution, fileData, 0644)
	if err != nil {
		response.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(response, err.Error())
		return
	}
	_, err = db.Exec("INSERT INTO files VALUES (NULL, ?, ?, ?)", username, username, filename)
	if err != nil{
		response.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(response, err.Error())
		return
	}
	//verify cookie

	// HINT: files should be stored in const filePath = "./files"

	// replace this statement
	//////////////////////////////////
	// END TASK 3: YOUR CODE HERE
	//////////////////////////////////
}

// fileInfo helps you pass information to the template
type fileInfo struct {
	Filename  string
	FileOwner string
	FilePath  string
}

func listFiles(response http.ResponseWriter, request *http.Request, username string) {
	files := make([]fileInfo, 0)

	//////////////////////////////////
	// BEGIN TASK 4: YOUR CODE HERE
	//////////////////////////////////

	// TODO: for each of the user's files, add a
	// corresponding fileInfo struct to the files slice.
	fileQuery, err := db.Query("SELECT owner, filename FROM files WHERE recipient = ?", username)
	defer fileQuery.Close()
	for fileQuery.Next() {
		var owner, filename string
		err := fileQuery.Scan(&owner, &filename)
		if err != nil {
			response.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(response, err.Error())
			return
		}
		fullPath := filepath.Join(filePath, username, filename)
		fileInformation := fileInfo{filename, owner,fullPath}
		files = append(files, fileInformation)
	}
	err = fileQuery.Err()
	if err != nil {
		response.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(response, err.Error())
		return
	}
	// replace this line
	//fmt.Fprintf(files, "placeholder")

	//////////////////////////////////
	// END TASK 4: YOUR CODE HERE
	//////////////////////////////////

	data := map[string]interface{}{
		"Username": username,
		"Files":    files,
	}

	tmpl, err := template.ParseFiles("templates/base.html", "templates/list.html")
	if err != nil {
		log.Error(err)
	}
	err = tmpl.Execute(response, data)
	if err != nil {
		log.Error(err)
	}
}

func getFile(response http.ResponseWriter, request *http.Request, username string) {
	fileString := strings.TrimPrefix(request.URL.Path, "/file/")


	//////////////////////////////////
	// BEGIN TASK 5: YOUR CODE HERE
	//////////////////////////////////
	splitString := strings.Split(fileString, "/")
	temp_username := splitString[1]
	if temp_username != username {
		response.WriteHeader(http.StatusInternalServerError)
		return
	}
	temp_filename := splitString[2]
	row := db.QueryRow("SELECT recipient, filename FROM files WHERE recipient = ? AND filename = ?", username, temp_filename)
	var recipient, filename string
	err := row.Scan(&recipient, &filename)
	if err != nil {
		response.WriteHeader(http.StatusInternalServerError)
		return
	}
	setNameOfServedFile(response, filename)
	http.ServeFile(response,request, fileString)

	//////////////////////////////////
	// END TASK 5: YOUR CODE HERE
	//////////////////////////////////
}

func setNameOfServedFile(response http.ResponseWriter, fileName string) {
	response.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", fileName))
}

func processShare(response http.ResponseWriter, request *http.Request, sender string) {
	recipient := request.FormValue("username")
	filename := request.FormValue("filename")
	_ = filename

	if sender == recipient {
		response.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(response, "can't share with yourself")
		return
	}

	//////////////////////////////////
	// BEGIN TASK 6: YOUR CODE HERE
	//////////////////////////////////

	// replace this line
	fmt.Fprintf(response, "placeholder")

	//////////////////////////////////
	// END TASK 6: YOUR CODE HERE
	//////////////////////////////////

}

// Initiate a new session for the given username
func initSession(response http.ResponseWriter, username string) {
	// Generate session token
	sessionToken, err := randomByteString(16)
	if err != nil {
		response.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(response, err.Error())
		return
	}

	expires := time.Now().Add(sessionDuration)

	// Store session in database
	_, err = db.Exec("INSERT INTO sessions VALUES (NULL, ?, ?, ?)", username, sessionToken, expires.Unix())
	if err != nil {
		response.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(response, err.Error())
		return
	}

	// Set cookie with session data
	http.SetCookie(response, &http.Cookie{
		Name:     "session_token",
		Value:    sessionToken,
		Expires:  expires,
		SameSite: http.SameSiteStrictMode,
	})
}
