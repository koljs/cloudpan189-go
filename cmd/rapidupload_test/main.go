package main

import (
	"bytes"
	"crypto/aes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/tickstep/cloudpan189-api/cloudpan"
)

const (
	PC_UPLOAD_URL = "https://upload.cloud.189.cn"
	PC_API_URL    = "https://api.cloud.189.cn"
	PC_CLIENT     = "TELEPC"
	PC_VERSION    = "6.2"
	PC_CHANNEL_ID = "web_cloud.189.cn"
)

func pkcs7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func aesECBEncrypt(data, key string) string {
	block, _ := aes.NewCipher([]byte(key))
	paddingData := pkcs7Padding([]byte(data), block.BlockSize())
	encrypted := make([]byte, len(paddingData))
	size := block.BlockSize()
	for src, dst := paddingData, encrypted; len(src) > 0; src, dst = src[size:], dst[size:] {
		block.Encrypt(dst[:size], src[:size])
	}
	return strings.ToUpper(hex.EncodeToString(encrypted))
}

func encodeParams(params map[string]string) string {
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var buf strings.Builder
	for i, k := range keys {
		if i > 0 {
			buf.WriteByte('&')
		}
		buf.WriteString(k)
		buf.WriteByte('=')
		buf.WriteString(params[k])
	}
	return buf.String()
}

func signatureOfHmac(sessionSecret, sessionKey, httpMethod, fullUrl, dateOfGmt, encryptedParams string) string {
	re := regexp.MustCompile(`://[^/]+((/[^/\s?#]+)*)`)
	matches := re.FindStringSubmatch(fullUrl)
	urlPath := ""
	if len(matches) > 1 {
		urlPath = matches[1]
	}
	mac := hmac.New(sha1.New, []byte(sessionSecret))
	data := fmt.Sprintf("SessionKey=%s&Operate=%s&RequestURI=%s&Date=%s", sessionKey, httpMethod, urlPath, dateOfGmt)
	if encryptedParams != "" {
		data += fmt.Sprintf("&params=%s", encryptedParams)
	}
	mac.Write([]byte(data))
	return strings.ToUpper(hex.EncodeToString(mac.Sum(nil)))
}

func clientSuffix() map[string]string {
	return map[string]string{
		"clientType": PC_CLIENT,
		"version":    PC_VERSION,
		"channelId":  PC_CHANNEL_ID,
		"rand":       fmt.Sprintf("%d_%d", rand.Int63n(100000), rand.Int63n(10000000000)),
	}
}

func makeEncryptedRequest(token *cloudpan.AppLoginToken, method, fullUrl string, params map[string]string) string {
	var encryptedParams string
	if params != nil {
		plainParams := encodeParams(params)
		encryptedParams = aesECBEncrypt(plainParams, token.SessionSecret[:16])
	}
	reqUrl, _ := url.Parse(fullUrl)
	query := reqUrl.Query()
	for k, v := range clientSuffix() {
		query.Set(k, v)
	}
	if encryptedParams != "" {
		query.Set("params", encryptedParams)
	}
	reqUrl.RawQuery = query.Encode()
	finalUrl := reqUrl.String()
	dateOfGmt := time.Now().UTC().Format(http.TimeFormat)
	signature := signatureOfHmac(token.SessionSecret, token.SessionKey, method, fullUrl, dateOfGmt, encryptedParams)
	req, _ := http.NewRequest(method, finalUrl, nil)
	req.Header.Set("Date", dateOfGmt)
	req.Header.Set("SessionKey", token.SessionKey)
	req.Header.Set("Signature", signature)
	req.Header.Set("X-Request-ID", fmt.Sprintf("%d", time.Now().UnixNano()))
	req.Header.Set("Accept", "application/json;charset=UTF-8")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("请求失败：", err)
		return ""
	}
	defer resp.Body.Close()
	respBody, _ := ioutil.ReadAll(resp.Body)
	fmt.Printf("HTTP Status: %d\n", resp.StatusCode)
	fmt.Printf("Response: %s\n", string(respBody))
	return string(respBody)
}

func makeOldApiRequest(token *cloudpan.AppLoginToken, method, fullUrl string, params map[string]string) string {
	reqUrl, _ := url.Parse(fullUrl)
	query := reqUrl.Query()
	for k, v := range clientSuffix() {
		query.Set(k, v)
	}
	for k, v := range params {
		query.Set(k, v)
	}
	reqUrl.RawQuery = query.Encode()
	finalUrl := reqUrl.String()
	dateOfGmt := time.Now().UTC().Format(http.TimeFormat)
	signature := signatureOfHmac(token.SessionSecret, token.SessionKey, method, fullUrl, dateOfGmt, "")
	req, _ := http.NewRequest(method, finalUrl, nil)
	req.Header.Set("Date", dateOfGmt)
	req.Header.Set("SessionKey", token.SessionKey)
	req.Header.Set("Signature", signature)
	req.Header.Set("X-Request-ID", fmt.Sprintf("%d", time.Now().UnixNano()))
	req.Header.Set("Accept", "application/json;charset=UTF-8")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("请求失败：", err)
		return ""
	}
	defer resp.Body.Close()
	respBody, _ := ioutil.ReadAll(resp.Body)
	fmt.Printf("HTTP Status: %d\n", resp.StatusCode)
	fmt.Printf("Response: %s\n", string(respBody))
	return string(respBody)
}

func calcMd5(data []byte) string {
	hash := md5.Sum(data)
	return strings.ToUpper(hex.EncodeToString(hash[:]))
}

// 计算文件的分片MD5
func calcSliceMd5ForFile(token *cloudpan.AppLoginToken, fileId string, fileSize int64) (string, string) {
	// 获取下载URL
	downloadResult := makeOldApiRequest(token, "GET", PC_API_URL+"/getFileDownloadUrl.action", map[string]string{
		"fileId": fileId,
	})
	type DownloadResp struct {
		FileDownloadUrl string `json:"fileDownloadUrl"`
	}
	var downloadResp DownloadResp
	json.Unmarshal([]byte(downloadResult), &downloadResp)
	if downloadResp.FileDownloadUrl == "" {
		fmt.Println("获取下载URL失败")
		return "", ""
	}

	sliceSize := int64(10485760) // 10MB
	totalSlices := int(fileSize / sliceSize)
	if fileSize%sliceSize > 0 {
		totalSlices++
	}

	sliceMd5Hexs := make([]string, 0, totalSlices)
	fileMd5Hash := md5.New()
	httpClient := &http.Client{}

	for i := 0; i < totalSlices; i++ {
		start := int64(i) * sliceSize
		end := start + sliceSize - 1
		if end >= fileSize {
			end = fileSize - 1
		}

		req, _ := http.NewRequest("GET", downloadResp.FileDownloadUrl, nil)
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", start, end))

		resp, err := httpClient.Do(req)
		if err != nil {
			fmt.Printf("下载分片%d失败: %v\n", i+1, err)
			return "", ""
		}
		body, _ := ioutil.ReadAll(resp.Body)
		resp.Body.Close()

		sliceMd5Hex := calcMd5(body)
		sliceMd5Hexs = append(sliceMd5Hexs, sliceMd5Hex)
		fmt.Printf("分片%d/%d MD5: %s (%d bytes)\n", i+1, totalSlices, sliceMd5Hex, len(body))
		fileMd5Hash.Write(body)
	}

	fileMd5Hex := strings.ToUpper(hex.EncodeToString(fileMd5Hash.Sum(nil)))

	var sliceMd5 string
	if fileSize <= sliceSize {
		sliceMd5 = fileMd5Hex
	} else {
		sliceMd5Input := strings.Join(sliceMd5Hexs, "\n")
		sliceMd5 = calcMd5([]byte(sliceMd5Input))
	}

	return fileMd5Hex, sliceMd5
}

func main() {
	// === 登录账号A（17789858273，文件所有者）===
	fmt.Println("=== 登录账号A（17789858273）===")
	tokenA, err := cloudpan.AppLogin("17789858273", "Luo.8682268")
	if err != nil {
		fmt.Println("账号A登录失败：", err)
		return
	}
	fmt.Printf("账号A登录成功！\n")

	// === 登录账号B（13823490590，目标账号）===
	fmt.Println("\n=== 登录账号B（13823490590）===")
	tokenB, err := cloudpan.AppLogin("13823490590", "Ljs.8682268")
	if err != nil {
		fmt.Println("账号B登录失败：", err)
		return
	}
	fmt.Printf("账号B登录成功！\n")

	// === 列出账号A的文件 ===
	fmt.Println("\n=== 列出账号A的根目录文件 ===")
	listResultA := makeOldApiRequest(tokenA, "GET", PC_API_URL+"/listFiles.action", map[string]string{
		"folderId":   "-11",
		"pageNum":    "1",
		"pageSize":   "100",
		"orderBy":    "filename",
		"descending": "false",
	})

	type FileItem struct {
		ID       int64  `json:"id"`
		Name     string `json:"name"`
		Size     int64  `json:"size"`
		Md5      string `json:"md5"`
		IsFolder int    `json:"isFolder"`
	}
	type ListResp struct {
		FileListAO struct {
			FileList []FileItem `json:"fileList"`
		} `json:"fileListAO"`
	}
	var listRespA ListResp
	json.Unmarshal([]byte(listResultA), &listRespA)

	// 找一个中文件（>10MB，来自账号A）
	var testFile *FileItem
	for i := range listRespA.FileListAO.FileList {
		f := &listRespA.FileListAO.FileList[i]
		fmt.Printf("  文件: %s (Size: %d, MD5: %s)\n", f.Name, f.Size, f.Md5)
		if f.IsFolder == 0 && f.Size > 10000000 && f.Size < 50000000 && testFile == nil {
			testFile = f
		}
	}

	if testFile == nil {
		fmt.Println("没有找到合适的中文件")
		return
	}

	fmt.Printf("\n选择账号A的测试文件: %s (Size: %d, MD5: %s, ID: %d)\n", testFile.Name, testFile.Size, testFile.Md5, testFile.ID)

	// === 用账号A下载文件分片计算sliceMd5 ===
	fmt.Println("\n=== 用账号A下载文件分片计算sliceMd5 ===")
	fileMd5, sliceMd5 := calcSliceMd5ForFile(tokenA, fmt.Sprintf("%d", testFile.ID), testFile.Size)
	if sliceMd5 == "" {
		fmt.Println("计算sliceMd5失败")
		return
	}
	fmt.Printf("文件MD5: %s\n", fileMd5)
	fmt.Printf("sliceMd5: %s\n", sliceMd5)

	// === 用账号B测试跨账号秒传（使用正确的sliceMd5）===
	fmt.Println("\n=== 用账号B测试跨账号秒传（使用正确的sliceMd5）===")
	makeEncryptedRequest(tokenB, "GET", PC_UPLOAD_URL+"/person/initMultiUpload", map[string]string{
		"parentFolderId": "-11",
		"fileName":       url.QueryEscape("test_cross_account_" + testFile.Name),
		"fileSize":       fmt.Sprintf("%d", testFile.Size),
		"fileMd5":        testFile.Md5,
		"sliceSize":      "10485760",
		"sliceMd5":       sliceMd5,
	})

	fmt.Println("\n=== 所有测试完成 ===")
}
