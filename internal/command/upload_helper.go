package command

import (
	"bytes"
	"crypto/aes"
	"crypto/hmac"
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
	"github.com/tickstep/cloudpan189-api/cloudpan/apierror"
	"github.com/tickstep/library-go/logger"
)

const (
	API_URL    = "https://api.cloud.189.cn"
	UPLOAD_URL = "https://upload.cloud.189.cn"
	PC_CLIENT  = "TELEPC"
	VERSION    = "6.2"
	CHANNEL_ID = "web_cloud.189.cn"
)

type (
	// InitMultiUploadResp 新版分片上传初始化响应
	InitMultiUploadResp struct {
		Data struct {
			UploadType     int    `json:"uploadType"`
			UploadHost     string `json:"uploadHost"`
			UploadFileID   string `json:"uploadFileId"`
			FileDataExists int    `json:"fileDataExists"`
		} `json:"data"`
	}

	// CommitMultiUploadFileResp 新版分片上传提交响应
	CommitMultiUploadFileResp struct {
		File struct {
			UserFileID string `json:"userFileId"`
			FileName   string `json:"fileName"`
			FileSize   int64  `json:"fileSize"`
			FileMd5    string `json:"fileMd5"`
			CreateDate string `json:"createDate"`
		} `json:"file"`
	}

	// CreateUploadFileResp 旧版上传创建响应
	CreateUploadFileResp struct {
		UploadFileId   int64  `json:"uploadFileId"`
		FileUploadUrl  string `json:"fileUploadUrl"`
		FileCommitUrl  string `json:"fileCommitUrl"`
		FileDataExists int    `json:"fileDataExists"`
	}
)

// computeSliceSize 根据文件大小计算分片大小（参考AList的partSize函数）
// 10MB * 2 * 999片 = ~20GB 上限用 20MB
// 10MB * 999片 = ~10GB 上限用 10MB
func computeSliceSize(fileSize int64) int64 {
	const DEFAULT = 1024 * 1024 * 10 // 10MB
	if fileSize > DEFAULT*2*999 {
		// 计算需要的倍率，确保分片数不超过1999
		rate := fileSize / (DEFAULT * 1999)
		if rate < 5 {
			rate = 5
		}
		return rate * DEFAULT
	}
	if fileSize > DEFAULT*999 {
		return DEFAULT * 2 // 20MB
	}
	return DEFAULT // 10MB
}

// ======== AES-ECB 加密（参考AList实现） ========

// pkcs7Padding PKCS7填充
func pkcs7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

// aesECBEncrypt AES-ECB加密，返回大写十六进制字符串
func aesECBEncrypt(data, key string) string {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		logger.Verboseln("AES cipher creation failed: ", err)
		return ""
	}
	paddingData := pkcs7Padding([]byte(data), block.BlockSize())
	encrypted := make([]byte, len(paddingData))
	size := block.BlockSize()
	for src, dst := paddingData, encrypted; len(src) > 0; src, dst = src[size:], dst[size:] {
		block.Encrypt(dst[:size], src[:size])
	}
	return strings.ToUpper(hex.EncodeToString(encrypted))
}

// ======== 参数编码（参考AList的Params.Encode） ========

// encodeParams 将参数map按key排序后编码为 key=value&key=value 格式
func encodeParams(params map[string]string) string {
	if params == nil {
		return ""
	}
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

// ======== 签名（参考AList的signatureOfHmac） ========

// signatureOfHmac 计算HMAC-SHA1签名
// 签名数据格式：SessionKey={}&Operate={}&RequestURI={}&Date={}&params={encryptedParams}
func signatureOfHmac(sessionSecret, sessionKey, httpMethod, fullUrl, dateOfGmt, encryptedParams string) string {
	// 提取URL路径
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

// ======== 客户端后缀参数（参考AList的clientSuffix） ========

func clientSuffix() map[string]string {
	return map[string]string{
		"clientType": PC_CLIENT,
		"version":    VERSION,
		"channelId":  CHANNEL_ID,
		"rand":       fmt.Sprintf("%d_%d", rand.Int63n(100000), rand.Int63n(10000000000)),
	}
}

// ======== 构建加密请求 ========

// buildEncryptedRequest 构建带AES加密参数的请求
// 参考AList的request函数实现
func buildEncryptedRequest(method, fullUrl string, params map[string]string, appToken cloudpan.AppLoginToken, isFamily bool) (*http.Request, error) {
	sessionKey := appToken.SessionKey
	sessionSecret := appToken.SessionSecret
	if isFamily {
		sessionKey = appToken.FamilySessionKey
		sessionSecret = appToken.FamilySessionSecret
	}

	// 1. 加密参数
	encryptedParams := ""
	if params != nil {
		plainParams := encodeParams(params)
		encryptedParams = aesECBEncrypt(plainParams, sessionSecret[:16])
	}

	// 2. 构建URL（添加clientSuffix和加密后的params）
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

	// 3. 计算签名
	dateOfGmt := time.Now().UTC().Format(http.TimeFormat)
	signature := signatureOfHmac(sessionSecret, sessionKey, method, fullUrl, dateOfGmt, encryptedParams)

	// 4. 构建请求
	var req *http.Request
	var err error
	if method == "POST" {
		req, err = http.NewRequest(method, finalUrl, nil)
	} else {
		req, err = http.NewRequest(method, finalUrl, nil)
	}
	if err != nil {
		return nil, err
	}

	// 5. 设置请求头
	req.Header.Set("Date", dateOfGmt)
	req.Header.Set("SessionKey", sessionKey)
	req.Header.Set("Signature", signature)
	req.Header.Set("X-Request-ID", fmt.Sprintf("%d", time.Now().UnixNano()))
	req.Header.Set("Accept", "application/json;charset=UTF-8")

	logger.Verboseln("Encrypted request URL: ", finalUrl)
	logger.Verboseln("Encrypted params: ", encryptedParams)

	return req, nil
}

// ======== 旧版API秒传（参考AList的OldUploadCreate + OldUploadCommit） ========

// RapidUploadCreate 旧版API创建上传会话（使用AES加密参数，参考AList实现）
func RapidUploadCreate(appToken cloudpan.AppLoginToken, parentFolderId, fileName, fileSize, fileMd5 string) (*CreateUploadFileResp, *apierror.ApiError) {
	fullUrl := API_URL + "/createUploadFile.action"

	params := map[string]string{
		"parentFolderId": parentFolderId,
		"fileName":       fileName,
		"size":           fileSize,
		"md5":            fileMd5,
		"opertype":       "3",
		"flag":           "1",
		"resumePolicy":   "1",
		"isLog":          "0",
	}

	req, err := buildEncryptedRequest("POST", fullUrl, params, appToken, false)
	if err != nil {
		return nil, apierror.NewApiErrorWithError(err)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		logger.Verboseln("RapidUploadCreate occurs error: ", err.Error())
		return nil, apierror.NewApiErrorWithError(err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logger.Verboseln("RapidUploadCreate read body error: ", err.Error())
		return nil, apierror.NewApiErrorWithError(err)
	}
	logger.Verboseln("RapidUploadCreate response: ", string(body))

	if resp.StatusCode != 200 {
		return nil, apierror.NewFailedApiError(fmt.Sprintf("RapidUploadCreate failed: HTTP %d, %s", resp.StatusCode, string(body)))
	}

	result := &CreateUploadFileResp{}
	if jsonErr := json.Unmarshal(body, result); jsonErr != nil {
		logger.Verboseln("RapidUploadCreate parse response failed: ", jsonErr)
		return nil, apierror.NewFailedApiError(fmt.Sprintf("RapidUploadCreate parse response failed: %s", string(body)))
	}

	return result, nil
}

// RapidUploadCommit 旧版API提交秒传（使用AES加密参数，参考AList实现）
func RapidUploadCommit(appToken cloudpan.AppLoginToken, fileCommitUrl string, uploadFileId int64, overwrite bool) (*CreateUploadFileResp, *apierror.ApiError) {
	opertype := "1"
	if overwrite {
		opertype = "3"
	}

	params := map[string]string{
		"opertype":     opertype,
		"resumePolicy": "1",
		"uploadFileId": fmt.Sprintf("%d", uploadFileId),
		"isLog":        "0",
	}

	req, err := buildEncryptedRequest("POST", fileCommitUrl, params, appToken, false)
	if err != nil {
		return nil, apierror.NewApiErrorWithError(err)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		logger.Verboseln("RapidUploadCommit occurs error: ", err.Error())
		return nil, apierror.NewApiErrorWithError(err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logger.Verboseln("RapidUploadCommit read body error: ", err.Error())
		return nil, apierror.NewApiErrorWithError(err)
	}
	logger.Verboseln("RapidUploadCommit response: ", string(body))

	if resp.StatusCode != 200 {
		return nil, apierror.NewFailedApiError(fmt.Sprintf("RapidUploadCommit failed: HTTP %d, %s", resp.StatusCode, string(body)))
	}

	result := &CreateUploadFileResp{}
	if jsonErr := json.Unmarshal(body, result); jsonErr != nil {
		logger.Verboseln("RapidUploadCommit parse response failed: ", jsonErr)
		return nil, apierror.NewFailedApiError(fmt.Sprintf("RapidUploadCommit parse response failed: %s", string(body)))
	}

	return result, nil
}

// ======== 新版API秒传（参考AList的FastUpload） ========

// InitMultiUpload 新版分片上传初始化（使用AES加密参数，参考AList实现）
func InitMultiUpload(appToken cloudpan.AppLoginToken, parentFolderId, fileName, fileSize, fileMd5, sliceSize, sliceMd5 string, familyId int64) (*InitMultiUploadResp, *apierror.ApiError) {
	fullUrl := UPLOAD_URL + "/person/initMultiUpload"
	isFamily := familyId > 0
	if isFamily {
		fullUrl = UPLOAD_URL + "/family/initMultiUpload"
	}

	params := map[string]string{
		"parentFolderId": parentFolderId,
		"fileName":       url.QueryEscape(fileName),
		"fileSize":       fileSize,
		"fileMd5":        fileMd5,
		"sliceSize":      sliceSize,
		"sliceMd5":       sliceMd5,
	}
	if isFamily {
		params["familyId"] = fmt.Sprintf("%d", familyId)
	}

	req, err := buildEncryptedRequest("GET", fullUrl, params, appToken, isFamily)
	if err != nil {
		return nil, apierror.NewApiErrorWithError(err)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		logger.Verboseln("InitMultiUpload occurs error: ", err.Error())
		return nil, apierror.NewApiErrorWithError(err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logger.Verboseln("InitMultiUpload read body error: ", err.Error())
		return nil, apierror.NewApiErrorWithError(err)
	}
	logger.Verboseln("InitMultiUpload response: ", string(body))

	if resp.StatusCode != 200 {
		return nil, apierror.NewFailedApiError(fmt.Sprintf("InitMultiUpload failed: HTTP %d, %s", resp.StatusCode, string(body)))
	}

	result := &InitMultiUploadResp{}
	if jsonErr := json.Unmarshal(body, result); jsonErr != nil {
		logger.Verboseln("InitMultiUpload parse response failed: ", jsonErr)
		return nil, apierror.NewApiErrorWithError(err)
	}

	return result, nil
}

// CommitMultiUploadFile 新版分片上传提交（使用AES加密参数）
func CommitMultiUploadFile(appToken cloudpan.AppLoginToken, uploadFileId string, familyId int64, overwrite bool) (*CommitMultiUploadFileResp, *apierror.ApiError) {
	fullUrl := UPLOAD_URL + "/person/commitMultiUploadFile"
	isFamily := familyId > 0
	if isFamily {
		fullUrl = UPLOAD_URL + "/family/commitMultiUploadFile"
	}

	opertype := "1"
	if overwrite {
		opertype = "3"
	}

	params := map[string]string{
		"uploadFileId": uploadFileId,
		"isLog":        "0",
		"opertype":     opertype,
	}
	if isFamily {
		params["familyId"] = fmt.Sprintf("%d", familyId)
	}

	req, err := buildEncryptedRequest("GET", fullUrl, params, appToken, isFamily)
	if err != nil {
		return nil, apierror.NewApiErrorWithError(err)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		logger.Verboseln("CommitMultiUploadFile occurs error: ", err.Error())
		return nil, apierror.NewApiErrorWithError(err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logger.Verboseln("CommitMultiUploadFile read body error: ", err.Error())
		return nil, apierror.NewApiErrorWithError(err)
	}
	logger.Verboseln("CommitMultiUploadFile response: ", string(body))

	if resp.StatusCode != 200 {
		return nil, apierror.NewFailedApiError(fmt.Sprintf("CommitMultiUploadFile failed: HTTP %d, %s", resp.StatusCode, string(body)))
	}

	result := &CommitMultiUploadFileResp{}
	if jsonErr := json.Unmarshal(body, result); jsonErr != nil {
		logger.Verboseln("CommitMultiUploadFile parse response failed: ", jsonErr)
		return nil, apierror.NewApiErrorWithError(err)
	}

	return result, nil
}
