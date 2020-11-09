/*
自动续期免费域名示例
*/

package main

import (
	"log"
	"time"

	"github.com/tzwsoho/go-freenom/freenom"
)

const (
	checkInterval time.Duration = time.Hour * 24 // 每天检查一遍所有域名是否可续期

	renewDays   time.Duration = 14 // 域名过期时间在 14 天内才能续期
	renewMonths int           = 12 // 每次续期月份数

	freenomUser string = "freenomapi@gmail.com"
	freenomPwd  string = "AaBbCc!1@2#3"
)

func main() {
	var err error
	for {
		// 登录账号
		err = freenom.Login(freenomUser, freenomPwd)
		if nil != err {
			log.Println(err.Error())
			return
		}

		// 开始续期
		_, err = freenom.RenewFreeDomain("", renewMonths)
		if nil != err {
			log.Println(err.Error())
		}

		<-time.After(checkInterval)
	}
}
