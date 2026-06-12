package command

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/tickstep/cloudpan189-api/cloudpan"
	"github.com/tickstep/cloudpan189-api/cloudpan/apierror"
	"github.com/tickstep/cloudpan189-api/cloudpan/apiutil"
	"github.com/tickstep/library-go/logger"
)

const (
	// UPLOAD_URL 天翼云盘上传服务器地址
	UPLOAD_URL = "https://upload.cloud.189.cn"
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
)

// computeSliceSize 根据文件大小计算分片大小
// 参考AList的实现逻辑
func computeSliceSize(fileSize int64) int64 {
	switch {
	case fileSize <= 0:
		return 0
	case fileSize <= 64*1024*1024: // 64MB
		return 4 * 1024 * 1024 // 4MB
	case fileSize <= 256*1024*1024: // 256MB
		return 8 * 1024 * 1024 // 8MB
	case fileSize <= 1024*1024*1024: // 1GB
		return 16 * 1024 * 1024 // 16MB
	case fileSize <= 4*1024*1024*1024: // 4GB
		return 32 * 1024 * 1024 // 32MB
	default:
		return 64 * 1024 * 1024 // 64MB
	}
}

// InitMultiUpload 新版分片上传初始化（支持跨账号秒传）
// 使用 upload.cloud.189.cn/person/initMultiUpload 接口
// 该接口会在全局文件池中匹配，而非仅当前账号
func InitMultiUpload(appToken cloudpan.AppLoginToken, parentFolderId, fileName, fileSize, fileMd5, sliceSize, sliceMd5 string, familyId int64) (*InitMultiUploadResp, *apierror.ApiError) {
	fullUrl := UPLOAD_URL + "/person/initMultiUpload"
	if familyId > 0 {
		fullUrl = UPLOAD_URL + "/family/initMultiUpload"
	}

	params := url.Values{}
	params.Set("parentFolderId", parentFolderId)
	params.Set("fileName", url.QueryEscape(fileName))
	params.Set("fileSize", fileSize)
	params.Set("fileMd5", fileMd5)
	params.Set("sliceSize", sliceSize)
	params.Set("sliceMd5", sliceMd5)
	if familyId > 0 {
		params.Set("familyId", fmt.Sprintf("%d", familyId))
	}

	requestUrl := fullUrl + "?" + params.Encode() + "&" + apiutil.PcClientInfoSuffixParam()

	sessionKey := appToken.SessionKey
	sessionSecret := appToken.SessionSecret
	if familyId > 0 {
		sessionKey = appToken.FamilySessionKey
		sessionSecret = appToken.FamilySessionSecret
	}

	httpMethod := "GET"
	dateOfGmt := apiutil.DateOfGmtStr()
	requestId := apiutil.XRequestId()
	headers := map[string]string{
		"Date":         dateOfGmt,
		"SessionKey":   sessionKey,
		"Signature":    apiutil.SignatureOfHmac(sessionSecret, sessionKey, httpMethod, requestUrl, dateOfGmt),
		"X-Request-ID": requestId,
		"Accept":       "application/json;charset=UTF-8",
	}

	logger.Verboseln("InitMultiUpload request url: " + requestUrl)
	req, err := http.NewRequest(httpMethod, requestUrl, nil)
	if err != nil {
		return nil, apierror.NewApiErrorWithError(err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
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
	logger.Verboseln("InitMultiUpload response: " + string(body))

	// 检查错误
	if resp.StatusCode != 200 {
		return nil, apierror.NewFailedApiError(fmt.Sprintf("InitMultiUpload failed: HTTP %d, %s", resp.StatusCode, string(body)))
	}

	result := &InitMultiUploadResp{}
	if err := json.Unmarshal(body, result); err != nil {
		logger.Verboseln("InitMultiUpload parse response failed: ", err.Error())
		return nil, apierror.NewApiErrorWithError(err)
	}

	return result, nil
}

// CommitMultiUploadFile 新版分片上传提交
func CommitMultiUploadFile(appToken cloudpan.AppLoginToken, uploadFileId string, familyId int64, overwrite bool) (*CommitMultiUploadFileResp, *apierror.ApiError) {
	fullUrl := UPLOAD_URL + "/person/commitMultiUploadFile"
	if familyId > 0 {
		fullUrl = UPLOAD_URL + "/family/commitMultiUploadFile"
	}

	opertype := "1"
	if overwrite {
		opertype = "3"
	}

	params := url.Values{}
	params.Set("uploadFileId", uploadFileId)
	params.Set("isLog", "0")
	params.Set("opertype", opertype)
	if familyId > 0 {
		params.Set("familyId", fmt.Sprintf("%d", familyId))
	}

	requestUrl := fullUrl + "?" + params.Encode() + "&" + apiutil.PcClientInfoSuffixParam()

	sessionKey := appToken.SessionKey
	sessionSecret := appToken.SessionSecret
	if familyId > 0 {
		sessionKey = appToken.FamilySessionKey
		sessionSecret = appToken.FamilySessionSecret
	}

	httpMethod := "GET"
	dateOfGmt := apiutil.DateOfGmtStr()
	requestId := apiutil.XRequestId()
	headers := map[string]string{
		"Date":         dateOfGmt,
		"SessionKey":   sessionKey,
		"Signature":    apiutil.SignatureOfHmac(sessionSecret, sessionKey, httpMethod, requestUrl, dateOfGmt),
		"X-Request-ID": requestId,
		"Accept":       "application/json;charset=UTF-8",
	}

	logger.Verboseln("CommitMultiUploadFile request url: " + requestUrl)
	req, err := http.NewRequest(httpMethod, requestUrl, nil)
	if err != nil {
		return nil, apierror.NewApiErrorWithError(err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
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
	logger.Verboseln("CommitMultiUploadFile response: " + string(body))

	if resp.StatusCode != 200 {
		return nil, apierror.NewFailedApiError(fmt.Sprintf("CommitMultiUploadFile failed: HTTP %d, %s", resp.StatusCode, string(body)))
	}

	result := &CommitMultiUploadFileResp{}
	if err := json.Unmarshal(body, result); err != nil {
		logger.Verboseln("CommitMultiUploadFile parse response failed: ", err.Error())
		return nil, apierror.NewApiErrorWithError(err)
	}

	return result, nil
}

// computeSliceMd5ForSingleSlice 当文件只有一个分片时，sliceMd5 = fileMd5
// 当文件有多个分片时，需要所有分片的md5拼接后再取md5
// 对于import场景，我们只有文件的整体md5，无法计算多分片的sliceMd5
// 但对于单分片文件（文件大小 <= sliceSize），sliceMd5 = fileMd5
func computeSliceMd5FromImport(fileMd5 string, fileSize int64) string {
	sliceSize := computeSliceSize(fileSize)
	if fileSize <= sliceSize {
		// 单分片文件，sliceMd5 = fileMd5
		return strings.ToUpper(fileMd5)
	}
	// 多分片文件，无法仅从fileMd5计算sliceMd5
	// 返回空字符串，由调用方决定如何处理
	return ""
}
