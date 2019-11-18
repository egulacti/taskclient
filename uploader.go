// uploader.go
package main

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"hash/fnv"
	"io"
	"io/ioutil"
	"math/rand" //TODO use crypto/rand if higher security is required
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
	"unsafe"
)

// this content is randomly created an instance initialization
// and is used for read operations with hit guarantee
var knownContent = ""
var knownContentHash = ""

// use scheduleArray to run 100 iterations
var scheduleArray [100]int

// used to create different seed for each instance
var SEED_DIF uint64

// parameter default values
// Content Size should be in the range 1 to 5,242,880 bytes == 5 MiB
var CAS_CONTENT_SIZE = 300

// Hit Ratio should be an integer in the range 0..100
var CAS_HIT_RATIO = 20

// Test Delay should be a positive integer in milliseconds
var CAS_TEST_DELAY = 500

// Test Pattern should be r for read, w for write
var CAS_TEST_PATTERN = "r"

// CAS Server should be a full URL with http, currently https is not supported
var CAS_TARGET_SERVER = "http://localhost:25478"

// CAS TOKEN should be the static authentication token
var CAS_TOKEN = "f9403fc5f537b4ab332d"

// Files to read should be a "-" separated string of hashes to be read from CAS
// For example: becd6d8e129d46bbd40b6d8b51a3eb2fc0283bdd-c226a629dd42dfc566d9f0aad482b868d2ef42fb
var CAS_FILES_2READ = ""
var CAS_FILES_ARR []string

// Return FNV-1a, non-cryptographic hash function value of given content
func stringHash(s string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(s))
	return h.Sum64()
}

// Return SHA1 hash value of given content
func hashSHA1(content string) string {

	var returnSHA1String string

	h := sha1.New()
	h.Write([]byte(content))
	returnSHA1String = hex.EncodeToString(h.Sum(nil))

	return returnSHA1String

}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const (
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

var srcRand rand.Source

// Optimized string generator
// https://stackoverflow.com/questions/22892120/how-to-generate-a-random-string-of-a-fixed-length-in-go
func randStringBytes(n int) string {
	b := make([]byte, n)
	// A src.Int63() generates 63 random bits, enough for letterIdxMax characters!
	for i, cache, remain := n-1, srcRand.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = srcRand.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return *(*string)(unsafe.Pointer(&b))
}

// Get preferred outbound ip of this machine
func getOutboundIP() net.IP {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		fmt.Println("Get IP Error", err)
		return nil
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	return localAddr.IP
}

// Post data to target CAS Server
func uploadData(destFileName string, url string, dataBuffer string) {

	bodyBuf := &bytes.Buffer{}
	bodyWriter := multipart.NewWriter(bodyBuf)

	filewriter, err := bodyWriter.CreateFormFile("file", destFileName)
	if err != nil {
		fmt.Println("Error in BodyWriter")
		return
	}

	//Copy content
	_, err = io.Copy(filewriter, strings.NewReader(dataBuffer))
	if err != nil {
		fmt.Println("Error in Content copy")
		return
	}
	contentType := bodyWriter.FormDataContentType()
	bodyWriter.Close()

	resp, err := http.Post(url, contentType, bodyBuf)
	if err != nil {
		fmt.Println("Error in Post buffer")
		return
	}
	defer resp.Body.Close()
	resp_body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error in Response read ")
		return
	}
	fmt.Println(resp.Status + " Response Body:" + string(resp_body))
}

// Get data from target CAS Server
func getData(url string) string {
	response, err := http.Get(url)
	if err != nil {
		fmt.Printf("%s", err)
		os.Exit(1)
		return ""
	} else {
		defer response.Body.Close()
		contents, err := ioutil.ReadAll(response.Body)
		if err != nil {
			fmt.Printf("%s", err)
			os.Exit(1)
		}
		return string(contents)
	}
}

// Assign and check initial parameter values
func initialControls() {
	// TODO add parameter validity controls

	t := time.Now()
	timeStr := t.Format(time.RFC822)

	localIP := getOutboundIP().String()
	tmpStr := timeStr + localIP
	SEED_DIF = stringHash(tmpStr)
	srcRand = rand.NewSource(time.Now().UnixNano() + (int64)(SEED_DIF))

	fmt.Println("CAS Client Startup Info")
	fmt.Println("--------------------------------------------")
	fmt.Println("Local IP   : ", localIP)
	fmt.Println("Local Time : ", timeStr)

	getenvironment := func(data []string, getkeyval func(item string) (key, val string)) map[string]string {
		items := make(map[string]string)
		for _, item := range data {
			key, val := getkeyval(item)
			items[key] = val
		}
		return items
	}

	environment := getenvironment(os.Environ(), func(item string) (key, val string) {
		splits := strings.Split(item, "=")
		key = splits[0]
		val = splits[1]
		return
	})

	if environment["CAS_CONTENT_SIZE"] != "" {
		CAS_CONTENT_SIZE, _ = strconv.Atoi(environment["CAS_CONTENT_SIZE"])
	}

	if environment["CAS_HIT_RATIO"] != "" {
		CAS_HIT_RATIO, _ = strconv.Atoi(environment["CAS_HIT_RATIO"])
	}

	if environment["CAS_TEST_DELAY"] != "" {
		CAS_TEST_DELAY, _ = strconv.Atoi(environment["CAS_TEST_DELAY"])
	}

	if environment["CAS_TEST_PATTERN"] != "" {
		CAS_TEST_PATTERN = environment["CAS_TEST_PATTERN"]
	}

	if environment["CAS_TARGET_SERVER"] != "" {
		CAS_TARGET_SERVER = environment["CAS_TARGET_SERVER"]
	}

	if environment["CAS_TOKEN"] != "" {
		CAS_TOKEN = environment["CAS_TOKEN"]
	}

	if environment["CAS_FILES_2READ"] != "" {
		CAS_FILES_2READ = environment["CAS_FILES_2READ"]
		CAS_FILES_ARR = strings.Split(CAS_FILES_2READ, "-")
	}

	fmt.Println("CAS_CONTENT_SIZE : ", CAS_CONTENT_SIZE)
	fmt.Println("CAS_HIT_RATIO : ", CAS_HIT_RATIO)
	fmt.Println("CAS_TEST_DELAY : ", CAS_TEST_DELAY)
	fmt.Println("CAS_TEST_PATTERN : ", CAS_TEST_PATTERN)
	fmt.Println("CAS_TARGET_SERVER : ", CAS_TARGET_SERVER)
	fmt.Println("CAS_FILES_2READ : ", CAS_FILES_2READ)
	fmt.Println("-------------------------------------------------------------------")

	//Create random content to be used in cache hit scenario
	knownContent = randStringBytes(CAS_CONTENT_SIZE)
	knownContentHash = hashSHA1(knownContent)
	uploadURL := CAS_TARGET_SERVER + "/upload?token=" + CAS_TOKEN
	uploadData(knownContentHash, uploadURL, knownContent)

	// verify the content via server
	getURL := CAS_TARGET_SERVER + "/files/" + knownContentHash + "?token=" + CAS_TOKEN
	contentFromServer := getData(getURL)
	if contentFromServer != knownContent {
		fmt.Println("\nFATAL ERROR ! Uploaded and downloaded contents do not match!")
		fmt.Println("Check server address: " + getURL)
		fmt.Println("For the content given below")
		fmt.Println("------------------------------------")
		fmt.Println(knownContent)
		os.Exit(1)
	}

	i := 0
	for i < CAS_HIT_RATIO {
		scheduleArray[i] = 1 // read existing content (HIT)
		i = i + 1
	}
	for i < 100 {
		scheduleArray[i] = 0 // read other content (MISS)
		i = i + 1
	}

	rand.Seed(time.Now().UnixNano() + (int64)(SEED_DIF))
	rand.Shuffle(len(scheduleArray), func(i, j int) { scheduleArray[i], scheduleArray[j] = scheduleArray[j], scheduleArray[i] })
}

func main() {

	initialControls()

	loopForever := true
	getURL := ""
	postURL := ""
	contentFromServer := ""
	randContent := ""
	randContentHash := ""
	i := 0
	len_CAS_FILES_ARR := len(CAS_FILES_ARR)
	instanceStr := strconv.FormatUint(SEED_DIF, 10)

	for loopForever {
		i = 0
		for i < 99 {
			i = i + 1
			time.Sleep(time.Millisecond * time.Duration(CAS_TEST_DELAY))

			if CAS_TEST_PATTERN == "w" {
				// w means write only mode
				randContent = randStringBytes(CAS_CONTENT_SIZE)
				randContentHash = hashSHA1(randContent)
				postURL = CAS_TARGET_SERVER + "/upload?token=" + CAS_TOKEN
				uploadData(randContentHash, postURL, randContent)
				continue
			}

			// HIT is required
			if scheduleArray[i] == 1 {
				getURL = CAS_TARGET_SERVER + "/files/" + knownContentHash + "?token=" + CAS_TOKEN
				contentFromServer = getData(getURL)
				fmt.Println("HIT for known content: " + knownContentHash)
				// print first 20 characters of content, content size is not checked (TODO)
				fmt.Println("------ Content: " + contentFromServer[:20])

			} else {
				if len_CAS_FILES_ARR > 0 {
					// loop the predetermined content
					getURL = CAS_TARGET_SERVER + "/files/" + CAS_FILES_ARR[i%len_CAS_FILES_ARR] + "?token=" + CAS_TOKEN
					contentFromServer = getData(getURL)
					fmt.Println("READ for predetermined content: " + CAS_FILES_ARR[i%len_CAS_FILES_ARR])
					fmt.Println("------ Content: " + contentFromServer[:20])
				} else {
					// try to fetch a non-existent file
					getURL = CAS_TARGET_SERVER + "/files/" + instanceStr + "?token=" + CAS_TOKEN
					contentFromServer = getData(getURL)
					fmt.Println("MISS for non-existent content: " + instanceStr)
					fmt.Println("------ Content: " + contentFromServer[:20])
				}

			}
		}

	}
}
