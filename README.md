# gofreenom
GO语言管理Freenom的库

[Freenom](https://www.freenom.com)是一个海外域名管理网站，也是全球唯一的免费域名提供商，
但它并没有提供相关的API对域名进行管理，为此我将Freenom上一些较为常用的管理功能封装成库，
方便他人使用本库对Freenom上的域名进行管理。

本库具有以下功能：
- [x] 登录
- [x] 列出已购买的域名
- [x] 列出域名的所有 DNS 记录
- [x] 往域名添加 DNS 记录
- [x] 修改域名的 DNS 记录
- [x] 删除域名的 DNS 记录
- [x] 免费域名续期
- [x] 检查免费域名是否可购买
- [ ] 购买免费域名（网站做了 GOOGLE 的反机器人校验，较难突破）
