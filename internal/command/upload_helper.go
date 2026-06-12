package command

import (
	"encoding/json"
	"encoding/xml"
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

	// RapidUploadCreateResp 旧版API秒传创建响应（JSON格式，参考AList）
	RapidUploadCreateResp struct {
		UploadFileId   int64  `json:"uploadFileId"`
		FileUploadUrl  string `json:"fileUploadUrl"`
		FileCommitUrl  string `json:"fileCommitUrl"`
		FileDataExists int    `json:"fileDataExists"`
	}

	// RapidUploadCommitResp 旧版API秒传提交响应（JSON格式，参考AList）
	RapidUploadCommitResp struct {
		ID         string `json:"id"`
		Name       string `json:"name"`
		Size       int64  `json:"size"`
		Md5        string `json:"md5"`
		CreateDate string `json:"createDate"`
		Rev        string `json:"rev"`
		UserId     string `json:"userId"`
		RequestId  string `json:"requestId"`
		IsSafe     string `json:"isSafe"`
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

// RapidUploadCreate 旧版API创建上传会话（参考AList实现）
// 使用 opertype=3，与AList保持一致，可能影响服务器的文件匹配行为
func RapidUploadCreate(appToken cloudpan.AppLoginToken, parentFolderId, fileName, fileSize, fileMd5 string) (*RapidUploadCreateResp, *apierror.ApiError) {
	fullUrl := cloudpan.API_URL + "/createUploadFile.action?" + apiutil.PcClientInfoSuffixParam()

	httpMethod := "POST"
	dateOfGmt := apiutil.DateOfGmtStr()
	requestId := apiutil.XRequestId()
	sessionKey := appToken.SessionKey
	sessionSecret := appToken.SessionSecret

	headers := map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
		"Date":         dateOfGmt,
		"SessionKey":   sessionKey,
		"Signature":    apiutil.SignatureOfHmac(sessionSecret, sessionKey, httpMethod, fullUrl, dateOfGmt),
		"X-Request-ID": requestId,
	}

	// 参考AList的OldUploadCreate，使用opertype=3
	formData := url.Values{}
	formData.Set("parentFolderId", parentFolderId)
	formData.Set("fileName", fileName)
	formData.Set("size", fileSize)
	formData.Set("md5", fileMd5)
	formData.Set("opertype", "3")
	formData.Set("flag", "1")
	formData.Set("resumePolicy", "1")
	formData.Set("isLog", "0")

	logger.Verboseln("RapidUploadCreate request url: " + fullUrl)
	req, err := http.NewRequest(httpMethod, fullUrl, strings.NewReader(formData.Encode()))
	if err != nil {
		return nil, apierror.NewApiErrorWithError(err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
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
	logger.Verboseln("RapidUploadCreate response: " + string(body))

	if resp.StatusCode != 200 {
		return nil, apierror.NewFailedApiError(fmt.Sprintf("RapidUploadCreate failed: HTTP %d, %s", resp.StatusCode, string(body)))
	}

	// 先尝试JSON解析（AList使用JSON格式）
	result := &RapidUploadCreateResp{}
	if jsonErr := json.Unmarshal(body, result); jsonErr == nil && result.UploadFileId > 0 {
		return result, nil
	}

	// 再尝试XML解析（旧版API可能返回XML）
	type xmlResp struct {
		XMLName        xml.Name `xml:"uploadFile"`
		UploadFileId   int64    `xml:"uploadFileId"`
		FileUploadUrl  string   `xml:"fileUploadUrl"`
		FileCommitUrl  string   `xml:"fileCommitUrl"`
		FileDataExists int      `xml:"fileDataExists"`
	}
	xmlResult := &xmlResp{}
	if xmlErr := xml.Unmarshal(body, xmlResult); xmlErr == nil && xmlResult.UploadFileId > 0 {
		result.UploadFileId = xmlResult.UploadFileId
		result.FileUploadUrl = xmlResult.FileUploadUrl
		result.FileCommitUrl = xmlResult.FileCommitUrl
		result.FileDataExists = xmlResult.FileDataExists
		return result, nil
	}

	return nil, apierror.NewFailedApiError(fmt.Sprintf("RapidUploadCreate parse response failed: %s", string(body)))
}

// RapidUploadCommit 旧版API提交秒传（参考AList实现）
func RapidUploadCommit(appToken cloudpan.AppLoginToken, fileCommitUrl string, uploadFileId int64, overwrite bool) (*RapidUploadCommitResp, *apierror.ApiError) {
	fullUrl := fileCommitUrl + "?" + apiutil.PcClientInfoSuffixParam()

	httpMethod := "POST"
	dateOfGmt := apiutil.DateOfGmtStr()
	requestId := apiutil.XRequestId()
	sessionKey := appToken.SessionKey
	sessionSecret := appToken.SessionSecret

	opertype := "1"
	if overwrite {
		opertype = "3"
	}

	headers := map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
		"Date":         dateOfGmt,
		"SessionKey":   sessionKey,
		"Signature":    apiutil.SignatureOfHmac(sessionSecret, sessionKey, httpMethod, fullUrl, dateOfGmt),
		"X-Request-ID": requestId,
	}

	formData := url.Values{}
	formData.Set("uploadFileId", fmt.Sprintf("%d", uploadFileId))
	formData.Set("opertype", opertype)
	formData.Set("resumePolicy", "1")
	formData.Set("isLog", "0")

	logger.Verboseln("RapidUploadCommit request url: " + fullUrl)
	req, err := http.NewRequest(httpMethod, fullUrl, strings.NewReader(formData.Encode()))
	if err != nil {
		return nil, apierror.NewApiErrorWithError(err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
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
	logger.Verboseln("RapidUploadCommit response: " + string(body))

	if resp.StatusCode != 200 {
		return nil, apierror.NewFailedApiError(fmt.Sprintf("RapidUploadCommit failed: HTTP %d, %s", resp.StatusCode, string(body)))
	}

	// 先尝试JSON解析
	result := &RapidUploadCommitResp{}
	if jsonErr := json.Unmarshal(body, result); jsonErr == nil && result.ID != "" {
		return result, nil
	}

	// 再尝试XML解析
	type xmlResp struct {
		XMLName    xml.Name `xml:"file"`
		ID         string   `xml:"id"`
		Name       string   `xml:"name"`
		Size       string   `xml:"size"`
		Md5        string   `xml:"md5"`
		CreateDate string   `xml:"createDate"`
		Rev        string   `xml:"rev"`
		UserId     string   `xml:"userId"`
		RequestId  string   `xml:"requestId"`
		IsSafe     string   `xml:"isSafe"`
	}
	xmlResult := &xmlResp{}
	if xmlErr := xml.Unmarshal(body, xmlResult); xmlErr == nil && xmlResult.ID != "" {
		result.ID = xmlResult.ID
		result.Name = xmlResult.Name
		result.Md5 = xmlResult.Md5
		result.CreateDate = xmlResult.CreateDate
		return result, nil
	}

	return nil, apierror.NewFailedApiError(fmt.Sprintf("RapidUploadCommit parse response failed: %s", string(body)))
}

// InitMultiUpload 新版分片上传初始化（支持跨账号秒传）
// 使用 upload.cloud.189.cn/person/initMultiUpload 接口
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
