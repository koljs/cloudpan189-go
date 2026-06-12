package command

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/tickstep/cloudpan189-api/cloudpan"
	"github.com/tickstep/cloudpan189-api/cloudpan/apiutil"
	"github.com/tickstep/cloudpan189-go/cmder"
	"github.com/tickstep/cloudpan189-go/internal/config"
	"github.com/urfave/cli"

	"golang.org/x/crypto/pbkdf2"
)

// ============ AES-128-CTR 加密（来自 alist-encrypt-go） ============

// aesctrEncryptCreate 创建 AES-128-CTR 加密器
// 密码和文件大小决定了加密结果，同一文件加密结果完全一致
func aesctrEncryptCreate(password string, fileSize int64) (cipher.Stream, error) {
	// 与 alist-encrypt-go 的 NewAESCTR 逻辑一致
	passwdOutward := password
	if len(password) != 32 {
		key := pbkdf2.Key([]byte(password), []byte("AES-CTR"), 1000, 16, sha256.New)
		passwdOutward = hex.EncodeToString(key)
	}
	passwdSalt := passwdOutward + fmt.Sprintf("%d", fileSize)

	// Generate key: MD5(passwdSalt)
	keyHash := md5.Sum([]byte(passwdSalt))
	aesKey := keyHash[:]

	// Generate IV: MD5(fileSize)
	ivHash := md5.Sum([]byte(fmt.Sprintf("%d", fileSize)))
	iv := make([]byte, 16)
	copy(iv, ivHash[:])

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("创建AES加密器失败: %w", err)
	}

	return cipher.NewCTR(block, iv), nil
}

// ============ 文件名加密（来自 alist-encrypt-go） ============

const sourceChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-~+"

// mixBase64Encode 使用密码派生的 MixBase64 编码文件名
func mixBase64Encode(password, plainName string) string {
	passwdOutward := password
	if len(password) != 32 {
		key := pbkdf2.Key([]byte(password), []byte("AES-CTR"), 1000, 16, sha256.New)
		passwdOutward = hex.EncodeToString(key)
	}

	// KSA 洗牌生成编码表
	secret := initKSA(passwdOutward + "mix64")

	// 编码
	var result strings.Builder
	data := []byte(plainName)
	i := 0
	for ; i+3 <= len(data); i += 3 {
		b0, b1, b2 := data[i], data[i+1], data[i+2]
		result.WriteByte(secret[b0>>2])
		result.WriteByte(secret[((b0&3)<<4)|(b1>>4)])
		result.WriteByte(secret[((b1&15)<<2)|(b2>>6)])
		result.WriteByte(secret[b2&63])
	}
	remaining := len(data) - i
	paddingChar := byte('+')
	if len(secret) > 64 {
		paddingChar = secret[64]
	}
	if remaining == 1 {
		b0 := data[i]
		result.WriteByte(secret[b0>>2])
		result.WriteByte(secret[(b0&3)<<4])
		result.WriteByte(paddingChar)
		result.WriteByte(paddingChar)
	} else if remaining == 2 {
		b0, b1 := data[i], data[i+1]
		result.WriteByte(secret[b0>>2])
		result.WriteByte(secret[((b0&3)<<4)|(b1>>4)])
		result.WriteByte(secret[(b1&15)<<2])
		result.WriteByte(paddingChar)
	}

	// CRC6 校验位
	encodedName := result.String()
	checkData := encodedName + passwdOutward
	crc6Bit := crc6Checksum([]byte(checkData))
	crc6Check := sourceChars[crc6Bit]

	return encodedName + string(crc6Check)
}

func initKSA(passwd string) []byte {
	key := sha256.Sum256([]byte(passwd))

	sbox := make([]int, len(sourceChars))
	for i := range sbox {
		sbox[i] = i
	}

	K := make([]byte, len(sourceChars))
	for i := 0; i < len(sourceChars); i++ {
		K[i] = key[i%len(key)]
	}

	j := 0
	for i := 0; i < len(sourceChars); i++ {
		j = (j + sbox[i] + int(K[i])) % len(sourceChars)
		sbox[i], sbox[j] = sbox[j], sbox[i]
	}

	sourceBytes := []byte(sourceChars)
	result := make([]byte, len(sourceChars))
	for i, idx := range sbox {
		result[i] = sourceBytes[idx]
	}
	return result
}

// CRC6 校验（与 alist-encrypt-go 一致）
var crc6Table [256]byte

func init() {
	for i := 0; i < 256; i++ {
		curr := byte(i)
		for j := 0; j < 8; j++ {
			if (curr & 0x01) != 0 {
				curr = ((curr >> 1) ^ 0x30)
			} else {
				curr = curr >> 1
			}
		}
		crc6Table[i] = curr
	}
}

func crc6Checksum(data []byte) int {
	crc := byte(0)
	for _, b := range data {
		crc = crc6Table[crc^b]
	}
	return int(crc)
}

// encryptFileName 加密文件名（含扩展名），然后追加原始扩展名
func encryptFileName(password, plainFileName string) string {
	ext := filepath.Ext(plainFileName)
	encName := mixBase64Encode(password, plainFileName)
	return encName + ext
}

// ============ 加密流式 MD5 计算 ============

// encryptedFileMd5AndSliceMd5 流式读取原始文件，加密后计算 fileMd5 和 sliceMd5
// 不需要将加密文件保存到磁盘
func encryptedFileMd5AndSliceMd5(localFilePath, password string) (fileMd5 string, sliceMd5 string, fileSize int64, err error) {
	f, err := os.Open(localFilePath)
	if err != nil {
		return "", "", 0, fmt.Errorf("打开文件失败: %w", err)
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return "", "", 0, fmt.Errorf("获取文件信息失败: %w", err)
	}
	fileSize = fi.Size()

	// 创建加密器
	stream, err := aesctrEncryptCreate(password, fileSize)
	if err != nil {
		return "", "", 0, err
	}

	// 流式处理：读取 → 加密 → 计算 MD5
	bufSize := 1024 * 1024 // 1MB 缓冲
	buf := make([]byte, bufSize)

	fileMd5Hash := md5.New()
	sliceMd5Hash := md5.New()
	sliceSize := int64(SliceSize) // 10MB
	var currentSliceSize int64
	var sliceMd5Hexs []string
	var totalRead int64

	for {
		n, readErr := f.Read(buf)
		if n > 0 {
			// 加密
			stream.XORKeyStream(buf[:n], buf[:n])

			// 累加到文件MD5
			fileMd5Hash.Write(buf[:n])

			// 处理分片MD5
			remaining := int64(n)
			offset := 0
			for remaining > 0 {
				spaceInSlice := sliceSize - currentSliceSize
				if remaining <= spaceInSlice {
					sliceMd5Hash.Write(buf[offset : offset+int(remaining)])
					currentSliceSize += remaining
					remaining = 0
				} else {
					sliceMd5Hash.Write(buf[offset : offset+int(spaceInSlice)])
					currentSliceSize = sliceSize
					offset += int(spaceInSlice)
					remaining -= spaceInSlice
				}

				// 分片完成
				if currentSliceSize >= sliceSize {
					sliceMd5Hex := strings.ToUpper(hex.EncodeToString(sliceMd5Hash.Sum(nil)))
					sliceMd5Hexs = append(sliceMd5Hexs, sliceMd5Hex)
					sliceMd5Hash = md5.New()
					currentSliceSize = 0
				}
			}

			totalRead += int64(n)
			fmt.Printf("\r加密计算MD5: %d/%d bytes (%.1f%%)", totalRead, fileSize, float64(totalRead)/float64(fileSize)*100)
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return "", "", 0, fmt.Errorf("读取文件失败: %w", readErr)
		}
	}
	fmt.Println()

	// 处理最后一个不完整分片
	if currentSliceSize > 0 || len(sliceMd5Hexs) == 0 {
		sliceMd5Hex := strings.ToUpper(hex.EncodeToString(sliceMd5Hash.Sum(nil)))
		sliceMd5Hexs = append(sliceMd5Hexs, sliceMd5Hex)
	}

	// 计算文件MD5
	fileMd5Hex := strings.ToUpper(hex.EncodeToString(fileMd5Hash.Sum(nil)))

	// 计算 sliceMd5
	var sliceMd5Result string
	if fileSize <= sliceSize {
		sliceMd5Result = fileMd5Hex
	} else {
		sliceMd5Input := strings.Join(sliceMd5Hexs, "\n")
		hash := md5.Sum([]byte(sliceMd5Input))
		sliceMd5Result = strings.ToUpper(hex.EncodeToString(hash[:]))
	}

	return fileMd5Hex, sliceMd5Result, fileSize, nil
}

// ============ 命令注册 ============

func CmdEncRapidUpload() cli.Command {
	return cli.Command{
		Name:      "encrapidupload",
		Usage:     "加密秒传：加密本地原始文件后秒传到云盘",
		UsageText: cmder.App().Name + " encrapidupload -pwd=密码 -saveto=云盘目录 本地文件1 本地文件2 ...",
		Description: `
	将本地原始文件使用 AES-128-CTR 加密后秒传到天翼云盘。
	加密后的文件与之前上传的加密文件完全一致，因此可以实现秒传。
	不需要实际上传文件数据，只需计算加密后的 MD5 即可。

	适用场景：本地有原始文件，之前加密上传过，现在需要秒传到另一个账号。

	示例:

	加密秒传单个文件到默认目录
	` + cmder.App().Name + ` encrapidupload -pwd=8682268 /path/to/file.mp4

	加密秒传到指定目录
	` + cmder.App().Name + ` encrapidupload -pwd=8682268 -saveto=/我的加密资源 /path/to/file.mp4

	加密秒传多个文件
	` + cmder.App().Name + ` encrapidupload -pwd=8682268 /path/to/file1.mp4 /path/to/file2.mp4
`,
		Category: "天翼云盘",
		Before:   cmder.ReloadConfigFunc,
		Action: func(c *cli.Context) error {
			if c.NArg() < 1 {
				cli.ShowCommandHelp(c, c.Command.Name)
				return nil
			}

			password := c.String("pwd")
			if password == "" {
				fmt.Println("请指定加密密码 -pwd")
				return nil
			}

			saveTo := c.String("saveto")
			if saveTo == "" {
				saveTo = DefaultSaveToPanPath
			}

			overwrite := c.Bool("ow")

			subArgs := c.Args()
			RunEncRapidUpload(password, saveTo, overwrite, subArgs)
			return nil
		},
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "pwd",
				Usage: "加密密码（必填）",
			},
			cli.StringFlag{
				Name:  "saveto",
				Usage: "保存到云盘的目录路径",
				Value: DefaultSaveToPanPath,
			},
			cli.BoolFlag{
				Name:  "ow",
				Usage: "overwrite, 覆盖已存在的网盘文件",
			},
		},
	}
}

func RunEncRapidUpload(password, saveTo string, overwrite bool, localFilePaths cli.Args) {
	activeUser := config.Config.ActiveUser()
	panClient := activeUser.PanClient()
	appToken := activeUser.AppToken
	familyId := int64(0)

	// 确保目标目录存在
	var dirId string
	if saveTo == "/" {
		dirId = "-11"
	} else {
		rs, apierr := panClient.AppMkdirRecursive(familyId, "", "", 0, strings.Split(strings.Trim(saveTo, "/"), "/"))
		if apierr != nil || rs.FileId == "" {
			fmt.Printf("创建云盘目录失败: %v\n", apierr)
			return
		}
		dirId = rs.FileId
	}

	totalFiles := len(localFilePaths)
	fmt.Printf("加密秒传目标目录: %s (ID: %s)\n", saveTo, dirId)
	fmt.Printf("加密密码: %s\n", strings.Repeat("*", len(password)))

	successCount := 0
	failCount := 0

	for i := 0; i < totalFiles; i++ {
		localPath := localFilePaths.Get(i)
		fmt.Printf("\n=== [%d/%d] 处理: %s ===\n", i+1, totalFiles, localPath)

		// 检查本地文件
		fi, err := os.Stat(localPath)
		if err != nil {
			fmt.Printf("文件不存在: %s\n", localPath)
			failCount++
			continue
		}
		if fi.IsDir() {
			fmt.Printf("不支持目录: %s\n", localPath)
			failCount++
			continue
		}

		// 步骤1：加密文件名
		plainFileName := fi.Name()
		encFileName := encryptFileName(password, plainFileName)
		fmt.Printf("原始文件名: %s\n", plainFileName)
		fmt.Printf("加密文件名: %s\n", encFileName)

		// 步骤2：流式加密计算 MD5
		fmt.Println("正在加密计算MD5...")
		fileMd5, sliceMd5, fileSize, err := encryptedFileMd5AndSliceMd5(localPath, password)
		if err != nil {
			fmt.Printf("加密计算MD5失败: %v\n", err)
			failCount++
			continue
		}
		fmt.Printf("文件大小: %d\n", fileSize)
		fmt.Printf("文件MD5: %s\n", fileMd5)
		fmt.Printf("sliceMd5: %s\n", sliceMd5)

		// 步骤3：使用新API秒传
		fmt.Println("正在秒传...")
		initResult, err := NewAPIInitMultiUpload(
			&appToken,
			dirId,
			encFileName,
			fmt.Sprintf("%d", fileSize),
			fileMd5,
			fmt.Sprintf("%d", SliceSize),
			sliceMd5,
		)
		if err != nil {
			fmt.Printf("秒传初始化失败: %v\n", err)
			failCount++
			continue
		}

		if initResult.Data.FileDataExists == 1 {
			// 秒传成功，提交
			commitResult, commitErr := NewAPICommitMultiUpload(
				&appToken,
				initResult.Data.UploadFileId,
				fileMd5,
				sliceMd5,
				overwrite,
			)
			if commitErr != nil {
				fmt.Printf("秒传提交失败: %v\n", commitErr)
				failCount++
				continue
			}
			if commitResult.Code != "" && commitResult.Code != "SUCCESS" {
				fmt.Printf("秒传提交返回错误: %s - %s\n", commitResult.Code, commitResult.Message)
				failCount++
				continue
			}
			fmt.Printf("秒传成功! 文件ID: %s\n", commitResult.Data.FileId)
			successCount++
		} else {
			fmt.Printf("秒传失败（fileDataExists=0），云端不存在相同文件数据\n")
			failCount++
		}
	}

	fmt.Printf("\n=== 加密秒传完成 ===\n")
	fmt.Printf("成功: %d, 失败: %d\n", successCount, failCount)
}

// ============ 批量加密导出命令 ============

func CmdEncExport() cli.Command {
	return cli.Command{
		Name:      "encexport",
		Usage:     "加密导出：加密本地原始文件后导出元数据",
		UsageText: cmder.App().Name + " encexport -pwd=密码 本地文件1 本地文件2 ... 导出文件路径",
		Description: `
	将本地原始文件使用 AES-128-CTR 加密后导出元数据。
	导出的元数据包含加密后的 fileMd5、sliceMd5、加密文件名等信息。
	可以使用 import 命令导入到任何天翼云盘账号实现秒传。

	示例:

	加密导出单个文件
	` + cmder.App().Name + ` encexport -pwd=8682268 /path/to/file.mp4 /path/to/export.txt

	加密导出多个文件
	` + cmder.App().Name + ` encexport -pwd=8682268 /path/to/file1.mp4 /path/to/file2.mp4 /path/to/export.txt
`,
		Category: "天翼云盘",
		Before:   cmder.ReloadConfigFunc,
		Action: func(c *cli.Context) error {
			if c.NArg() < 2 {
				cli.ShowCommandHelp(c, c.Command.Name)
				return nil
			}

			password := c.String("pwd")
			if password == "" {
				fmt.Println("请指定加密密码 -pwd")
				return nil
			}

			subArgs := c.Args()
			totalArgs := len(subArgs)
			RunEncExport(password, subArgs[:totalArgs-1], subArgs.Get(totalArgs-1))
			return nil
		},
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "pwd",
				Usage: "加密密码（必填）",
			},
		},
	}
}

func RunEncExport(password string, localFilePaths []string, saveFilePath string) {
	saveFile, err := os.OpenFile(saveFilePath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		fmt.Printf("创建导出文件失败: %v\n", err)
		return
	}
	defer saveFile.Close()

	// 写入加密密码标记（用于 import 时识别）
	header := fmt.Sprintf("# encpwd=%s\n", password)
	saveFile.WriteString(header)

	totalCount := 0
	for i, localPath := range localFilePaths {
		fmt.Printf("\n=== [%d/%d] 处理: %s ===\n", i+1, len(localFilePaths), localPath)

		fi, err := os.Stat(localPath)
		if err != nil {
			fmt.Printf("文件不存在: %s\n", localPath)
			continue
		}
		if fi.IsDir() {
			fmt.Printf("不支持目录: %s\n", localPath)
			continue
		}

		plainFileName := fi.Name()
		encFileName := encryptFileName(password, plainFileName)

		fmt.Println("正在加密计算MD5...")
		fileMd5, sliceMd5, fileSize, err := encryptedFileMd5AndSliceMd5(localPath, password)
		if err != nil {
			fmt.Printf("加密计算MD5失败: %v\n", err)
			continue
		}

		item := ImportExportFileItem{
			FileMd5:  fileMd5,
			FileSize: fileSize,
			Path:     "/" + encFileName,
			SliceMd5: sliceMd5,
			SliceSize: SliceSize,
		}

		jstr, _ := json.Marshal(&item)
		saveFile.WriteString(string(jstr) + "\n")
		totalCount++
		fmt.Printf("文件MD5: %s, sliceMd5: %s\n", fileMd5, sliceMd5)
	}

	fmt.Printf("\n导出完成，共 %d 个文件\n", totalCount)
	fmt.Printf("导出文件: %s\n", saveFilePath)
}

// ============ 辅助：获取签名（避免 import 循环） ============

// json 在 import_file.go 中已导入，这里需要重新导入
// 但由于同包，可以直接使用

// 确保 apiutil 可用
var _ = apiutil.Rand
var _ = cloudpan.AppLoginToken{}
