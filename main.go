package main

import (
	"bufio"
	"fmt"
	"os"
	"path"
	"strings"
	"time"

	aesv1 "github.com/gavintan/gopkg/aes"
	"github.com/glebarez/sqlite"
	"github.com/spf13/viper"
	"gorm.io/gorm"
)

type User struct {
	ID         uint      `gorm:"primarykey" json:"id" form:"id"`
	Username   string    `gorm:"uniqueIndex;column:username" json:"username" form:"username"`
	Password   string    `form:"password" json:"password"`
	IsEnable   *bool     `gorm:"default:true" form:"isEnable" json:"isEnable"`
	Name       string    `json:"name" form:"name"`
	ExpireDate string    `gorm:"default:NULL" json:"expireDate" form:"expireDate"`
	IpAddr     string    `gorm:"uniqueIndex;default:NULL" json:"ipAddr" form:"ipAddr"`
	OvpnConfig string    `json:"ovpnConfig" form:"ovpnConfig"`
	MfaSecret  string    `json:"mfaSecret" form:"mfaSecret"`
	CreatedAt  time.Time `json:"createdAt,omitempty" form:"createdAt,omitempty"`
	UpdatedAt  time.Time `json:"updatedAt,omitempty" form:"updatedAt,omitempty"`
}

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("Usage: %s <openvpn data path>\n", os.Args[0])
		os.Exit(1)
	}

	viper.SetConfigName("config")
	viper.SetConfigType("json")
	viper.AddConfigPath(os.Args[1])

	err := viper.ReadInConfig()
	if err != nil {
		fmt.Println("读取config.json配置文件失败", err)
		os.Exit(1)
	}

	db, err := gorm.Open(sqlite.Open(path.Join(os.Args[1], "ovpn.db")), &gorm.Config{})
	if err != nil {
		panic("连接数据库失败")
	}

	var u []User
	result := db.Table("user").Find(&u)
	if result.Error != nil {
		fmt.Println("查询失败", result.Error)
		os.Exit(1)
	}

	file, err := os.Open(path.Join(os.Args[1], ".vars"))
	if err != nil {
		fmt.Println("无法打开.vars文件:", err)
		os.Exit(1)
	}
	defer file.Close()

	vars := make(map[string]string)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		vars[key] = value
	}
	if err := scanner.Err(); err != nil {
		fmt.Println("读取.vars文件出错:", err)
		os.Exit(1)
	}

	if vars["SECRET_KEY"] == "" {
		fmt.Println("未找到SECRET_KEY，请检查.vars文件")
		os.Exit(1)
	}

	if vars["SERVER_NAME"] == "" {
		fmt.Println("未找到SERVER_NAME，请检查.vars文件")
		os.Exit(1)
	}

	if vars["SERVER_CN"] == "" {
		fmt.Println("未找到SERVER_CN，请检查.vars文件")
		os.Exit(1)
	}

	secretKey := vars["SECRET_KEY"]

	viper.Set("system.base.secret_key", secretKey)
	viper.Set("system.base.server_name", vars["SERVER_NAME"])
	viper.Set("system.base.server_cn", vars["SERVER_CN"])

	eap, _ := aesv1.AesEncrypt("admin", secretKey)
	viper.Set("system.base.admin_password", eap)
	viper.WriteConfig()

	for _, user := range u {
		dp, _ := AesDecrypt(user.Password, secretKey)
		epv1, _ := aesv1.AesEncrypt(dp, secretKey)
		db.Table("user").Model(&User{}).Where("username = ?", user.Username).Update("password", epv1)
	}

	fmt.Println("升级完成，web登录密码：admin")
}
