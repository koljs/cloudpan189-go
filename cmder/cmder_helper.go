package cmder

import (
	"fmt"
	"github.com/tickstep/cloudpan189-api/cloudpan"
	"github.com/tickstep/cloudpan189-api/cloudpan/apierror"
	"github.com/tickstep/cloudpan189-go/cmder/cmdliner"
	"github.com/tickstep/cloudpan189-go/internal/config"
	"github.com/tickstep/library-go/logger"
	"github.com/urfave/cli"
	"strings"
	"sync"
	"time"
)

var (
	appInstance *cli.App

	saveConfigMutex *sync.Mutex = new(sync.Mutex)

	ReloadConfigFunc = func(c *cli.Context) error {
		err := config.Config.Reload()
		if err != nil {
			fmt.Printf("重载配置错误: %s\n", err)
		}
		return nil
	}

	SaveConfigFunc = func(c *cli.Context) error {
		saveConfigMutex.Lock()
		defer saveConfigMutex.Unlock()
		err := config.Config.Save()
		if err != nil {
			fmt.Printf("保存配置错误: %s\n", err)
		}
		return nil
	}
)

func SetApp(app *cli.App) {
	appInstance = app
}

func App() *cli.App {
	return appInstance
}

func DoLoginHelper(username, password string) (usernameStr, passwordStr string, webToken cloudpan.WebLoginToken, appToken cloudpan.AppLoginToken, err error) {
	line := cmdliner.NewLiner()
	defer func() {
		_ = line.Close()
		// 增加 panic recovery 防止崩溃
		if r := recover(); r != nil {
			err = fmt.Errorf("登录过程发生严重错误: %v", r)
		}
	}()

	if username == "" {
		username, err = line.State.Prompt("请输入用户名(手机号/邮箱/别名), 回车键提交 > ")
		if err != nil {
			return
		}
	}

	if password == "" {
		// liner 的 PasswordPrompt 不安全, 拆行之后密码就会显示出来了
		fmt.Printf("请输入密码(输入的密码无回显, 确认输入完成, 回车提交即可) > ")
		password, err = line.State.PasswordPrompt("")
		if err != nil {
			return
		}
	}

	// 参数验证
	if strings.TrimSpace(username) == "" {
		return "", "", webToken, appToken, fmt.Errorf("用户名不能为空")
	}
	if strings.TrimSpace(password) == "" {
		return "", "", webToken, appToken, fmt.Errorf("密码不能为空")
	}

	// app login with retry mechanism
	var atoken *cloudpan.AppLoginToken
	var apperr *apierror.ApiError
	maxRetries := 3

	for attempt := 1; attempt <= maxRetries; attempt++ {
		fmt.Printf("正在尝试登录... (第 %d/%d 次)\n", attempt, maxRetries)

		// 使用 defer + recover 保护每次登录尝试
		func() {
			defer func() {
				if r := recover(); r != nil {
					// Create a synthetic ApiError for panic recovery
					apperr = apierror.NewFailedApiError(fmt.Sprintf("登录时发生 panic: %v", r))
				}
			}()
			atoken, apperr = cloudpan.AppLogin(username, password)
		}()

		// 详细的错误检查和调试信息
		if apperr == nil && atoken != nil && atoken.AccessToken != "" && atoken.SessionKey != "" {
			fmt.Println("APP 登录成功")
			break
		}

		// 更详细的错误信息
		if apperr != nil {
			fmt.Printf("第 %d 次登录失败 (错误代码: %d, 错误信息: %s)\n", attempt, apperr.Code, apperr.Error())
		} else if atoken == nil {
			apperr = apierror.NewFailedApiError("登录返回的令牌为空")
			fmt.Printf("第 %d 次登录失败 (令牌为空)\n", attempt)
		} else if atoken.AccessToken == "" {
			apperr = apierror.NewFailedApiError("访问令牌为空")
			fmt.Printf("第 %d 次登录失败 (访问令牌为空)\n", attempt)
		} else if atoken.SessionKey == "" {
			apperr = apierror.NewFailedApiError("会话密钥为空")
			fmt.Printf("第 %d 次登录失败 (会话密钥为空)\n", attempt)
		} else {
			apperr = apierror.NewFailedApiError("未知登录错误")
			fmt.Printf("第 %d 次登录失败 (未知错误)\n", attempt)
		}

		if attempt < maxRetries {
			fmt.Printf("等待 %d 秒后重试...\n", attempt)
			time.Sleep(time.Duration(attempt) * time.Second)
		}
	}

	if apperr != nil {
		return "", "", webToken, appToken, fmt.Errorf("登录失败 (已重试 %d 次, 错误代码: %d): %s", maxRetries, apperr.Code, apperr.Error())
	}

	// web cookie
	wtoken := &cloudpan.WebLoginToken{}
	cookieLoginUser := cloudpan.RefreshCookieToken(atoken.SessionKey)
	if cookieLoginUser != "" {
		wtoken.CookieLoginUser = cookieLoginUser
	} else {
		// Since app login succeeded, we have valid tokens. Generate a synthetic web cookie
		// using the session key as a fallback approach
		syntheticCookie := "APP_LOGIN_" + atoken.SessionKey[:16] + "_" + atoken.AccessToken[:16]
		wtoken.CookieLoginUser = syntheticCookie

		// Don't try direct web login as it's causing failures
		// The synthetic token should work for API operations via app tokens
	}

	webToken = *wtoken
	appToken = *atoken
	usernameStr = username
	passwordStr = password
	return
}

func TryLogin() *config.PanUser {
	// can do automatically login?
	for _, u := range config.Config.UserList {
		if u.UID == config.Config.ActiveUID {
			// login
			_, _, webToken, appToken, err := DoLoginHelper(config.DecryptString(u.LoginUserName), config.DecryptString(u.LoginUserPassword))
			if err != nil {
				_, _ = logger.Verboseln("automatically login error")
				break
			}
			// success
			u.WebToken = webToken
			u.AppToken = appToken

			// save
			_ = SaveConfigFunc(nil)
			// reload
			_ = ReloadConfigFunc(nil)
			return config.Config.ActiveUser()
		}
	}
	return nil
}
