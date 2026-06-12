package command

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
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/tickstep/cloudpan189-api/cloudpan"
	"github.com/tickstep/cloudpan189-api/cloudpan/apiutil"
)

const (
	UploadAPIUrl = "https://upload.cloud.189.cn"
	SliceSize    = int64(10485760) // 10MB
)

// pkcs7Padding PKCS7填充
func pkcs7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

// aesECBEncrypt AES-ECB加密，结果转大写十六进制
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

// encodeParams 将参数按key排序并编码为 key=value&key=value 格式
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

// signatureOfHmacWithParams HMAC-SHA1签名（支持加密params）
func signatureOfHmacWithParams(sessionSecret, sessionKey, httpMethod, fullUrl, dateOfGmt, encryptedParams string) string {
	requestUri := strings.Split(fullUrl, "?")[0]
	requestUri = strings.ReplaceAll(requestUri, "https://", "")
	requestUri = strings.ReplaceAll(requestUri, "http://", "")
	idx := strings.Index(requestUri, "/")
	requestUri = requestUri[idx:]

	plainStr := &strings.Builder{}
	fmt.Fprintf(plainStr, "SessionKey=%s&Operate=%s&RequestURI=%s&Date=%s",
		sessionKey, httpMethod, requestUri, dateOfGmt)
	if encryptedParams != "" {
		fmt.Fprintf(plainStr, "&params=%s", encryptedParams)
	}

	key := []byte(sessionSecret)
	mac := hmac.New(sha1.New, key)
	mac.Write([]byte(plainStr.String()))
	return strings.ToUpper(hex.EncodeToString(mac.Sum(nil)))
}

// InitMultiUploadResult 新API initMultiUpload 返回结果
type InitMultiUploadResult struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Data    struct {
		UploadFileId   string `json:"uploadFileId"`
		FileDataExists int    `json:"fileDataExists"`
	} `json:"data"`
}

// CommitMultiUploadResult 新API commitMultiUploadFile 返回结果
type CommitMultiUploadResult struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Data    struct {
		FileId string `json:"id"`
	} `json:"data"`
}

// NewAPIInitMultiUpload 新API初始化上传（支持跨账号秒传）
func NewAPIInitMultiUpload(appToken *cloudpan.AppLoginToken, parentFolderId, fileName, fileSize, fileMd5, sliceSize, sliceMd5 string) (*InitMultiUploadResult, error) {
	fullUrl := UploadAPIUrl + "/person/initMultiUpload"

	params := map[string]string{
		"parentFolderId": parentFolderId,
		"fileName":       url.QueryEscape(fileName),
		"fileSize":       fileSize,
		"fileMd5":        fileMd5,
		"sliceSize":      sliceSize,
		"sliceMd5":       sliceMd5,
	}
	plainParams := encodeParams(params)
	encryptedParams := aesECBEncrypt(plainParams, appToken.SessionSecret[:16])

	reqUrl, _ := url.Parse(fullUrl)
	query := reqUrl.Query()
	query.Set("clientType", "TELEPC")
	query.Set("version", "6.2")
	query.Set("channelId", "web_cloud.189.cn")
	query.Set("rand", apiutil.Rand())
	query.Set("params", encryptedParams)
	reqUrl.RawQuery = query.Encode()
	finalUrl := reqUrl.String()

	httpMethod := "GET"
	dateOfGmt := apiutil.DateOfGmtStr()
	signature := signatureOfHmacWithParams(appToken.SessionSecret, appToken.SessionKey, httpMethod, fullUrl, dateOfGmt, encryptedParams)

	req, _ := http.NewRequest(httpMethod, finalUrl, nil)
	req.Header.Set("Date", dateOfGmt)
	req.Header.Set("SessionKey", appToken.SessionKey)
	req.Header.Set("Signature", signature)
	req.Header.Set("X-Request-ID", apiutil.XRequestId())
	req.Header.Set("Accept", "application/json;charset=UTF-8")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求失败: %v", err)
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)

	result := &InitMultiUploadResult{}
	if err := json.Unmarshal(body, result); err != nil {
		return nil, fmt.Errorf("解析响应失败: %v, body: %s", err, string(body))
	}
	return result, nil
}

// NewAPICommitMultiUpload 新API提交上传
func NewAPICommitMultiUpload(appToken *cloudpan.AppLoginToken, uploadFileId, fileMd5, sliceMd5 string, overwrite bool) (*CommitMultiUploadResult, error) {
	fullUrl := UploadAPIUrl + "/person/commitMultiUploadFile"

	opertype := "1"
	if overwrite {
		opertype = "3"
	}
	params := map[string]string{
		"uploadFileId": uploadFileId,
		"fileMd5":      fileMd5,
		"sliceMd5":     sliceMd5,
		"isLog":        "0",
		"opertype":     opertype,
	}
	plainParams := encodeParams(params)
	encryptedParams := aesECBEncrypt(plainParams, appToken.SessionSecret[:16])

	reqUrl, _ := url.Parse(fullUrl)
	query := reqUrl.Query()
	query.Set("clientType", "TELEPC")
	query.Set("version", "6.2")
	query.Set("channelId", "web_cloud.189.cn")
	query.Set("rand", apiutil.Rand())
	query.Set("params", encryptedParams)
	reqUrl.RawQuery = query.Encode()
	finalUrl := reqUrl.String()

	httpMethod := "GET"
	dateOfGmt := apiutil.DateOfGmtStr()
	signature := signatureOfHmacWithParams(appToken.SessionSecret, appToken.SessionKey, httpMethod, fullUrl, dateOfGmt, encryptedParams)

	req, _ := http.NewRequest(httpMethod, finalUrl, nil)
	req.Header.Set("Date", dateOfGmt)
	req.Header.Set("SessionKey", appToken.SessionKey)
	req.Header.Set("Signature", signature)
	req.Header.Set("X-Request-ID", apiutil.XRequestId())
	req.Header.Set("Accept", "application/json;charset=UTF-8")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求失败: %v", err)
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)

	result := &CommitMultiUploadResult{}
	if err := json.Unmarshal(body, result); err != nil {
		return nil, fmt.Errorf("解析响应失败: %v, body: %s", err, string(body))
	}
	return result, nil
}

// CalcFileSliceMd5 计算文件的分片MD5
// 通过下载文件各分片来计算 sliceMd5
// 返回 (fileMd5, sliceMd5, error)
func CalcFileSliceMd5(panClient *cloudpan.PanClient, fileId string, fileSize int64) (string, string, error) {
	// 获取下载URL
	downloadUrl, apiErr := panClient.AppGetFileDownloadUrl(fileId)
	if apiErr != nil {
		return "", "", fmt.Errorf("获取下载URL失败: %v", apiErr)
	}

	totalSlices := int(fileSize / SliceSize)
	if fileSize%SliceSize > 0 {
		totalSlices++
	}

	sliceMd5Hexs := make([]string, 0, totalSlices)
	fileMd5Hash := md5.New()
	httpClient := &http.Client{}

	for i := 0; i < totalSlices; i++ {
		start := int64(i) * SliceSize
		end := start + SliceSize - 1
		if end >= fileSize {
			end = fileSize - 1
		}

		req, _ := http.NewRequest("GET", downloadUrl, nil)
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", start, end))

		resp, err := httpClient.Do(req)
		if err != nil {
			return "", "", fmt.Errorf("下载分片%d失败: %v", i+1, err)
		}
		body, err := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return "", "", fmt.Errorf("读取分片%d失败: %v", i+1, err)
		}

		// 计算分片MD5
		hash := md5.Sum(body)
		sliceMd5Hex := strings.ToUpper(hex.EncodeToString(hash[:]))
		sliceMd5Hexs = append(sliceMd5Hexs, sliceMd5Hex)

		// 累加到文件MD5
		fileMd5Hash.Write(body)

		fmt.Printf("\r计算分片MD5: %d/%d", i+1, totalSlices)
		time.Sleep(time.Duration(50) * time.Millisecond)
	}
	fmt.Println()

	// 计算文件整体MD5
	fileMd5Hex := strings.ToUpper(hex.EncodeToString(fileMd5Hash.Sum(nil)))

	// 计算 sliceMd5
	var sliceMd5 string
	if fileSize <= SliceSize {
		sliceMd5 = fileMd5Hex
	} else {
		sliceMd5Input := strings.Join(sliceMd5Hexs, "\n")
		hash := md5.Sum([]byte(sliceMd5Input))
		sliceMd5 = strings.ToUpper(hex.EncodeToString(hash[:]))
	}

	return fileMd5Hex, sliceMd5, nil
}

// CalcSliceMd5ForSmallFile 计算小文件（<=10MB）的 sliceMd5
// 小文件的 sliceMd5 = fileMd5，大文件返回空字符串
func CalcSliceMd5ForSmallFile(fileMd5 string, fileSize int64) string {
	if fileSize <= SliceSize {
		return fileMd5
	}
	return ""
}
