package freenom

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Freenom 支持的记录类型
// 各种记录类型：https://deepzz.com/post/dns-recording-type.html
const (
	RecordTypeA     string = "A"     // 将主机名（或域名）指向一个 IPv4 地址
	RecordTypeAAAA  string = "AAAA"  // 将主机名（或域名）指向一个 IPv6 地址
	RecordTypeCNAME string = "CNAME" // 别名记录，如果将域名指向一个域名，实现与被指向域名相同的访问效果，需要增加 CNAME 记录
	RecordTypeLOC   string = "LOC"   // Location Information，位置记录，将一个域名指定地理位置
	RecordTypeMX    string = "MX"    // 邮件交换记录，用于指定负责处理发往收件人域名的邮件服务器
	RecordTypeNAPTR string = "NAPTR" // 命名管理指针，允许基于正则表达式的域名重写使其能够作为 URI、进一步域名查找等。主要是为 SIP 协议提供 DNS 服务
	RecordTypeRP    string = "RP"    // Responsible Person 负责人，有关域名负责人的信息，电邮地址的 @ 通常写为 .。
	RecordTypeTXT   string = "TXT"   // 文本记录，一般指为某个主机名或域名设置的说明。一般做某种验证时会用到。
)

// DomainRecord 域名记录
type DomainRecord struct {
	Type     string
	Name     string
	TTL      int
	Value    string
	Priority int
}

// DomainInfo 域名信息
type DomainInfo struct {
	Domain   string
	DomainID string
	RegDate  string
	ExpDate  string
	Records  []*DomainRecord
}

// DomainStatus 可购买的域名状态
type DomainStatus struct {
	Status   string `json:"status"`
	Domain   string `json:"domain"`
	TLD      string `json:"tld"`
	Type     string `json:"type"`
	IsInCart int    `json:"is_in_cart"`
}

// DomainListResult 可购买的免费域名列表
type DomainListResult struct {
	Status      string          `json:"status"`
	FreeDomains []*DomainStatus `json:"free_domains"`
}

const retryTimes int = 5
const timeout time.Duration = time.Second * 20

const renewableDays int = 14 // 免费域名只允许到期前 14 天内续期
const freenomHost string = "https://my.freenom.com/"
const loginURL string = freenomHost + "clientarea.php"
const doLoginURL string = freenomHost + "dologin.php"
const domainsURL string = freenomHost + "domains.php"
const checkAvailableURL string = freenomHost + "includes/domains/fn-available.php"

// cookie 容器
var jar *cookiejar.Jar

// 会话令牌
var token string

// 域名信息缓存表
var domainInfoMap map[string]*DomainInfo

// Login 登录
func Login(user, pwd string) (err error) {
	var re, reOK *regexp.Regexp
	re, err = regexp.Compile(`(?is:class="form-stacked".+?value="([^"]+?)")`)
	if nil != err {
		jar = nil
		err = fmt.Errorf("Login re Compile err: %s", err.Error())
		return
	}

	reOK, err = regexp.Compile(`(?is:<span class="hidden-sm">Hello.+?</span>)`)
	if nil != err {
		jar = nil
		err = fmt.Errorf("Login reOK Compile err: %s", err.Error())
		return
	}

	retries := 0
	for {
		retries++

		jar, err = cookiejar.New(nil)
		if nil != err {
			jar = nil
			err = fmt.Errorf("Login New Jar err: %s", err.Error())
			return
		}

		var req *http.Request
		req, err = http.NewRequest("GET", loginURL, nil)
		if nil != err {
			if retries < retryTimes {
				continue
			} else {
				jar = nil
				err = fmt.Errorf("Login NewRequest Login err: %s", err.Error())
				return
			}
		}

		tr := &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		}
		client := http.Client{
			Jar:       jar,
			Transport: tr,
			Timeout:   timeout,
		}

		var res *http.Response
		res, err = client.Do(req)
		if nil != err {
			if retries < retryTimes {
				continue
			} else {
				jar = nil
				err = fmt.Errorf("Login Do Login err: %s", err.Error())
				return
			}
		} else if http.StatusOK != res.StatusCode {
			if retries < retryTimes {
				continue
			} else {
				jar = nil
				err = fmt.Errorf("Login Do Login errCode: %d", res.StatusCode)
				return
			}
		}

		var all []byte
		all, err = ioutil.ReadAll(res.Body)
		if nil != err {
			if retries < retryTimes {
				continue
			} else {
				jar = nil
				err = fmt.Errorf("Login ReadAll Login err: %s", err.Error())
				return
			}
		}

		allMatches := re.FindSubmatch(all)
		if 2 != len(allMatches) {
			jar = nil
			err = fmt.Errorf("Login FindSubmatch len err: %+v", allMatches)
			return
		}

		token = string(allMatches[1])

		////////////////////////////////////////////////////////////////////////////////////////

		params := url.Values{}
		params.Add("token", token)
		params.Add("username", user)
		params.Add("password", pwd)

		buf := bytes.NewBuffer(make([]byte, 0))
		buf.WriteString(params.Encode())
		req, err = http.NewRequest("POST", doLoginURL, buf)
		if nil != err {
			if retries < retryTimes {
				continue
			} else {
				jar = nil
				err = fmt.Errorf("Login NewRequest DoLogin err: %s", err.Error())
				return
			}
		}

		tr = &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		}
		client = http.Client{
			Jar:       jar,
			Transport: tr,
			Timeout:   timeout,
		}

		req.Header.Add("Referer", loginURL)
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")

		res, err = client.Do(req)
		if nil != err {
			if retries < retryTimes {
				continue
			} else {
				jar = nil
				err = fmt.Errorf("Login Do DoLogin err: %s", err.Error())
				return
			}
		} else if http.StatusOK != res.StatusCode {
			if retries < retryTimes {
				continue
			} else {
				jar = nil
				err = fmt.Errorf("Login Do DoLogin errCode: %d", res.StatusCode)
				return
			}
		}

		all, err = ioutil.ReadAll(res.Body)
		if nil != err {
			if retries < retryTimes {
				continue
			} else {
				jar = nil
				err = fmt.Errorf("Login ReadAll DoLogin err: %s", err.Error())
				return
			}
		}

		if !reOK.Match(all) {
			jar = nil
			err = fmt.Errorf("Login failed")
			return
		}

		break
	}

	return nil
}

// ListDomains 列出用户拥有的所有域名
// 返回 域名与到期时间
func ListDomains() (domains map[string]string, err error) {
	domains = make(map[string]string)
	if nil == jar {
		err = fmt.Errorf("NOT LOGGED IN")
		return
	}

	var re *regexp.Regexp
	re, err = regexp.Compile(`(?is:class="second"><[^>]+?>(.+?)\s+.+?class="third">(\d{4}-\d{2}-\d{2}).+?class="fourth">(\d{4}-\d{2}-\d{2}).+?id=(\d+?)")`)
	if nil != err {
		err = fmt.Errorf("ListDomains Compile err: %s", err.Error())
		return
	}

	retries := 0
	for {
		retries++

		var req *http.Request
		req, err = http.NewRequest("GET", loginURL+"?action=domains", nil)
		if nil != err {
			if retries < retryTimes {
				continue
			} else {
				err = fmt.Errorf("ListDomains NewRequest err: %s", err.Error())
				return
			}
		}

		tr := &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		}
		client := http.Client{
			Jar:       jar,
			Transport: tr,
			Timeout:   timeout,
		}

		req.Header.Add("Referer", loginURL)

		var res *http.Response
		res, err = client.Do(req)
		if nil != err {
			if retries < retryTimes {
				continue
			} else {
				err = fmt.Errorf("ListDomains Do err: %s", err.Error())
				return
			}
		} else if http.StatusOK != res.StatusCode {
			if retries < retryTimes {
				continue
			} else {
				err = fmt.Errorf("ListDomains Do errCode: %d", res.StatusCode)
				return
			}
		}

		var all []byte
		all, err = ioutil.ReadAll(res.Body)
		if nil != err {
			if retries < retryTimes {
				continue
			} else {
				err = fmt.Errorf("ListDomains ReadAll err: %s", err.Error())
				return
			}
		}

		if nil == domainInfoMap {
			domainInfoMap = make(map[string]*DomainInfo)
		}

		allMatches := re.FindAllSubmatch(all, -1)
		for _, match := range allMatches {
			if 5 != len(match) {
				continue
			}

			domain := string(match[1])
			domainID := string(match[4])
			regDate := string(match[2])
			expDate := string(match[3])

			domains[domain] = expDate

			if v, ok := domainInfoMap[domain]; ok { // 缓存已存在，保留 DNS 记录
				v.Domain = domain
				v.DomainID = domainID
				v.RegDate = regDate
				v.ExpDate = expDate
			} else {
				domainInfoMap[domain] = &DomainInfo{
					Domain:   domain,
					DomainID: domainID,
					RegDate:  regDate,
					ExpDate:  expDate,
				}
			}
		}

		break
	}

	return
}

// GetDomainInfo 获取指定域名的信息
// 返回 域名信息
func GetDomainInfo(domain string) (info *DomainInfo, err error) {
	info = nil

	if nil == jar {
		return nil, fmt.Errorf("NOT LOGGED IN")
	}

	var domainID string
	if v, ok := domainInfoMap[domain]; ok {
		domainID = v.DomainID
	} else {
		_, err = ListDomains()
		if nil != err {
			return
		}

		if v, ok := domainInfoMap[domain]; !ok {
			err = fmt.Errorf("Domain not exists")
			return
		} else {
			domainID = v.DomainID
		}
	}

	var re *regexp.Regexp
	re, err = regexp.Compile(`(?is:records\[\d+\]\[type\]" value="([^"]*)".+?records\[\d+\]\[name\]" value="([^"]*)".+?records\[\d+\]\[ttl\]" value="(\d+)".+?records\[\d+\]\[value\]" value="([^"]*)".+?(?:records\[\d+\]\[priority\]" value="(\d+)".+?)?</td>)`)
	if nil != err {
		err = fmt.Errorf("GetDomainInfo Compile err: %s", err.Error())
		return
	}

	params := url.Values{}
	params.Add("managedns", domain)
	params.Add("domainid", domainID)

	retries := 0
	for {
		retries++

		var req *http.Request
		req, err = http.NewRequest("GET", loginURL+"?"+params.Encode(), nil)
		if nil != err {
			if retries < retryTimes {
				continue
			} else {
				err = fmt.Errorf("GetDomainInfo NewRequest err: %s", err.Error())
				return
			}
		}

		tr := &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		}
		client := http.Client{
			Jar:       jar,
			Transport: tr,
			Timeout:   timeout,
		}

		req.Header.Add("Referer", loginURL)

		var res *http.Response
		res, err = client.Do(req)
		if nil != err {
			if retries < retryTimes {
				continue
			} else {
				err = fmt.Errorf("GetDomainInfo Do err: %s", err.Error())
				return
			}
		} else if http.StatusOK != res.StatusCode {
			if retries < retryTimes {
				continue
			} else {
				err = fmt.Errorf("GetDomainInfo Do errCode: %d", res.StatusCode)
				return
			}
		}

		var all []byte
		all, err = ioutil.ReadAll(res.Body)
		if nil != err {
			if retries < retryTimes {
				continue
			} else {
				err = fmt.Errorf("GetDomainInfo ReadAll err: %s", err.Error())
				return
			}
		}

		allMatches := re.FindAllSubmatch(all, -1)
		info = domainInfoMap[domain]
		info.Records = make([]*DomainRecord, len(allMatches))

		for n, match := range allMatches {
			if 6 != len(match) {
				continue
			}

			var ttl, priority int
			ttl, err = strconv.Atoi(string(match[3]))
			if nil != err {
				err = fmt.Errorf("GetDomainInfo Atoi ttl %+v err: %s", match[3], err.Error())
				continue
			}

			if 0 == len(match[5]) {
				priority = 0
			} else {
				priority, err = strconv.Atoi(string(match[5]))
				if nil != err {
					err = fmt.Errorf("GetDomainInfo Atoi priority %+v err: %s", match[5], err.Error())
					continue
				}
			}

			info.Records[n] = &DomainRecord{
				Type:     string(match[1]),
				Name:     string(match[2]),
				TTL:      ttl,
				Value:    string(match[4]),
				Priority: priority,
			}
		}

		break
	}

	return
}

// AddRecord 增加域名记录
func AddRecord(domain string, records []DomainRecord) (err error) {
	if nil == jar {
		err = fmt.Errorf("NOT LOGGED IN")
		return
	}

	if 0 == len(records) {
		err = fmt.Errorf("Empty records")
		return
	}

	var info *DomainInfo
	if v, ok := domainInfoMap[domain]; ok {
		info = v
	} else {
		_, err = ListDomains()
		if nil != err {
			return
		}

		if v, ok := domainInfoMap[domain]; !ok {
			err = fmt.Errorf("Domain not exists")
			return
		} else {
			info = v
		}
	}

	var reError, reSuccess *regexp.Regexp
	reError, err = regexp.Compile(`(?is:class="dnserror">(.+?)</li>)`)
	if nil != err {
		err = fmt.Errorf("AddRecord Compile reError err: %s", err.Error())
		return
	}

	reSuccess, err = regexp.Compile(`(?is:class="dnssuccess")`)
	if nil != err {
		err = fmt.Errorf("AddRecord Compile reSuccess err: %s", err.Error())
		return
	}

	paramsURL := url.Values{}
	paramsURL.Add("managedns", domain)
	paramsURL.Add("domainid", info.DomainID)

	paramsPost := url.Values{}
	paramsPost.Add("token", token)
	paramsPost.Add("dnsaction", "add")

	for i, record := range records {
		ttlStr := strconv.Itoa(record.TTL)

		priorityStr := ""
		if 0 == strings.Compare("mx", strings.ToLower(record.Type)) {
			priorityStr = strconv.Itoa(record.Priority)
		}

		paramsPost.Add(fmt.Sprintf("addrecord[%d][name]", i), record.Name)
		paramsPost.Add(fmt.Sprintf("addrecord[%d][type]", i), strings.ToUpper(record.Type))
		paramsPost.Add(fmt.Sprintf("addrecord[%d][ttl]", i), ttlStr)
		paramsPost.Add(fmt.Sprintf("addrecord[%d][value]", i), record.Value)
		paramsPost.Add(fmt.Sprintf("addrecord[%d][priority]", i), priorityStr)
		paramsPost.Add(fmt.Sprintf("addrecord[%d][port]", i), "")
		paramsPost.Add(fmt.Sprintf("addrecord[%d][weight]", i), "")
		paramsPost.Add(fmt.Sprintf("addrecord[%d][forward_type]", i), "1")
	}

	retries := 0
	for {
		retries++

		buf := bytes.NewBuffer(make([]byte, 0))
		buf.WriteString(paramsPost.Encode())

		var req *http.Request
		req, err = http.NewRequest("POST", loginURL+"?"+paramsURL.Encode(), buf)
		if nil != err {
			if retries < retryTimes {
				continue
			} else {
				err = fmt.Errorf("AddRecord NewRequest err: %s", err.Error())
				return
			}
		}

		tr := &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		}
		client := http.Client{
			Jar:       jar,
			Transport: tr,
			Timeout:   timeout,
		}

		req.Header.Add("Referer", loginURL+"?"+paramsURL.Encode())
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")

		var res *http.Response
		res, err = client.Do(req)
		if nil != err {
			if retries < retryTimes {
				continue
			} else {
				err = fmt.Errorf("AddRecord Do err: %s", err.Error())
				return
			}
		} else if http.StatusOK != res.StatusCode {
			if retries < retryTimes {
				continue
			} else {
				err = fmt.Errorf("AddRecord Do errCode: %d", res.StatusCode)
				return
			}
		}

		var all []byte
		all, err = ioutil.ReadAll(res.Body)
		if nil != err {
			if retries < retryTimes {
				continue
			} else {
				err = fmt.Errorf("AddRecord ReadAll err: %s", err.Error())
				return
			}
		}

		if !reSuccess.Match(all) {
			allMatches := reError.FindSubmatch(all)
			if 2 != len(allMatches) {
				err = fmt.Errorf("AddRecord not success")
				return
			}

			err = fmt.Errorf("%s", string(allMatches[1]))
			return
		}

		// 刷新缓存信息
		GetDomainInfo(domain)

		break
	}

	return
}

// ModifyRecord 修改一条域名记录
func ModifyRecord(domain string, oldRecord, newRecord *DomainRecord) (err error) {
	if nil == jar {
		err = fmt.Errorf("NOT LOGGED IN")
		return
	}

	var info *DomainInfo
	if v, ok := domainInfoMap[domain]; ok {
		info = v
	} else {
		_, err = ListDomains()
		if nil != err {
			return
		}

		if v, ok := domainInfoMap[domain]; !ok {
			err = fmt.Errorf("Domain not exists")
			return
		} else {
			info = v
		}
	}
	var reError, reSuccess *regexp.Regexp
	reError, err = regexp.Compile(`(?is:class="dnserror">(.+?)</li>)`)
	if nil != err {
		err = fmt.Errorf("ModifyRecord Compile reError err: %s", err.Error())
		return
	}

	reSuccess, err = regexp.Compile(`(?is:class="dnssuccess")`)
	if nil != err {
		err = fmt.Errorf("ModifyRecord Compile reSuccess err: %s", err.Error())
		return
	}

	paramsURL := url.Values{}
	paramsURL.Add("managedns", domain)
	paramsURL.Add("domainid", info.DomainID)

	paramsPost := url.Values{}
	paramsPost.Add("token", token)
	paramsPost.Add("dnsaction", "modify")

	newTTLStr := strconv.Itoa(newRecord.TTL)

	newPriorityStr := ""
	if 0 == strings.Compare("mx", strings.ToLower(newRecord.Type)) {
		newPriorityStr = strconv.Itoa(newRecord.Priority)
	}

	for i, record := range info.Records {
		if 0 == strings.Compare(strings.ToLower(oldRecord.Type), strings.ToLower(record.Type)) &&
			0 == strings.Compare(strings.ToLower(oldRecord.Name), strings.ToLower(record.Name)) &&
			0 == strings.Compare(strings.ToLower(oldRecord.Value), strings.ToLower(record.Value)) &&
			oldRecord.TTL == record.TTL &&
			oldRecord.Priority == record.Priority {
			paramsPost.Add(fmt.Sprintf("records[%d][line]", i), "")
			paramsPost.Add(fmt.Sprintf("records[%d][type]", i), strings.ToUpper(newRecord.Type))
			paramsPost.Add(fmt.Sprintf("records[%d][name]", i), newRecord.Name)
			paramsPost.Add(fmt.Sprintf("records[%d][ttl]", i), newTTLStr)
			paramsPost.Add(fmt.Sprintf("records[%d][value]", i), newRecord.Value)
			paramsPost.Add(fmt.Sprintf("records[%d][priority]", i), newPriorityStr)
		} else {
			ttlStr := strconv.Itoa(record.TTL)

			priorityStr := ""
			if 0 == strings.Compare("mx", strings.ToLower(record.Type)) {
				priorityStr = strconv.Itoa(record.Priority)
			}

			paramsPost.Add(fmt.Sprintf("records[%d][line]", i), "")
			paramsPost.Add(fmt.Sprintf("records[%d][type]", i), strings.ToUpper(record.Type))
			paramsPost.Add(fmt.Sprintf("records[%d][name]", i), record.Name)
			paramsPost.Add(fmt.Sprintf("records[%d][ttl]", i), ttlStr)
			paramsPost.Add(fmt.Sprintf("records[%d][value]", i), record.Value)
			paramsPost.Add(fmt.Sprintf("records[%d][priority]", i), priorityStr)
		}
	}

	retries := 0
	for {
		retries++

		buf := bytes.NewBuffer(make([]byte, 0))
		buf.WriteString(paramsPost.Encode())

		var req *http.Request
		req, err = http.NewRequest("POST", loginURL+"?"+paramsURL.Encode(), buf)
		if nil != err {
			if retries < retryTimes {
				continue
			} else {
				err = fmt.Errorf("ModifyRecord NewRequest err: %s", err.Error())
				return
			}
		}

		tr := &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		}
		client := http.Client{
			Jar:       jar,
			Transport: tr,
			Timeout:   timeout,
		}

		req.Header.Add("Referer", loginURL+"?"+paramsURL.Encode())
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")

		var res *http.Response
		res, err = client.Do(req)
		if nil != err {
			if retries < retryTimes {
				continue
			} else {
				err = fmt.Errorf("ModifyRecord Do err: %s", err.Error())
				return
			}
		} else if http.StatusOK != res.StatusCode {
			if retries < retryTimes {
				continue
			} else {
				err = fmt.Errorf("ModifyRecord Do errCode: %d", res.StatusCode)
				return
			}
		}

		var all []byte
		all, err = ioutil.ReadAll(res.Body)
		if nil != err {
			if retries < retryTimes {
				continue
			} else {
				err = fmt.Errorf("ModifyRecord ReadAll err: %s", err.Error())
				return
			}
		}

		if !reSuccess.Match(all) {
			allMatches := reError.FindSubmatch(all)
			if 2 != len(allMatches) {
				err = fmt.Errorf("ModifyRecord not success")
				return
			}

			err = fmt.Errorf("%s", string(allMatches[1]))
			return
		}

		// 刷新缓存信息
		GetDomainInfo(domain)

		break
	}

	return
}

// DeleteRecordByIndex 根据缓存的信息删除一条域名记录
func DeleteRecordByIndex(domain string, recordIndex int) (err error) {
	if nil == jar {
		err = fmt.Errorf("NOT LOGGED IN")
		return
	}

	if recordIndex < 0 {
		err = fmt.Errorf("recordIndex must greater or equal to 0")
		return
	}

	var info *DomainInfo
	if v, ok := domainInfoMap[domain]; !ok {
		err = fmt.Errorf("domain not exsits")
		return
	} else {
		info = v
	}

	var record *DomainRecord
	if recordIndex >= len(info.Records) {
		err = fmt.Errorf("recordIndex out of bounds")
		return
	}

	record = info.Records[recordIndex]

	return DeleteRecord(domain, record)
}

// DeleteRecord 根据参数删除一条域名记录
func DeleteRecord(domain string, record *DomainRecord) (err error) {
	if nil == jar {
		err = fmt.Errorf("NOT LOGGED IN")
		return
	}

	var info *DomainInfo
	if v, ok := domainInfoMap[domain]; ok {
		info = v
	} else {
		_, err = ListDomains()
		if nil != err {
			return
		}

		if v, ok := domainInfoMap[domain]; !ok {
			err = fmt.Errorf("Domain not exists")
			return
		} else {
			info = v
		}
	}

	var reError, reSuccess *regexp.Regexp
	reError, err = regexp.Compile(`(?is:class="dnserror")`)
	if nil != err {
		err = fmt.Errorf("DeleteRecord Compile reError err: %s", err.Error())
		return
	}

	reSuccess, err = regexp.Compile(`(?is:class="dnssuccess")`)
	if nil != err {
		err = fmt.Errorf("DeleteRecord Compile reSuccess err: %s", err.Error())
		return
	}

	ttl := strconv.Itoa(record.TTL)

	priority := ""
	if 0 == strings.Compare("mx", strings.ToLower(record.Type)) {
		priority = strconv.Itoa(record.Priority)
	}

	params := url.Values{}
	params.Add("managedns", domain)
	params.Add("domainid", info.DomainID)
	params.Add("dnsaction", "delete")
	params.Add("records", record.Type)
	params.Add("name", record.Name)
	params.Add("value", record.Value)
	params.Add("line", "")
	params.Add("ttl", ttl)
	params.Add("priority", priority)
	params.Add("weight", "")
	params.Add("port", "")
	params.Add("page", "")

	retries := 0
	for {
		retries++

		var req *http.Request
		req, err = http.NewRequest("GET", loginURL+"?"+params.Encode(), nil)
		if nil != err {
			if retries < retryTimes {
				continue
			} else {
				err = fmt.Errorf("DeleteRecord NewRequest err: %s", err.Error())
				return
			}
		}

		tr := &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		}
		client := http.Client{
			Jar:       jar,
			Transport: tr,
			Timeout:   timeout,
		}

		req.Header.Add("Referer", loginURL)

		var res *http.Response
		res, err = client.Do(req)
		if nil != err {
			if retries < retryTimes {
				continue
			} else {
				err = fmt.Errorf("DeleteRecord Do err: %s", err.Error())
				return
			}
		} else if http.StatusOK != res.StatusCode {
			if retries < retryTimes {
				continue
			} else {
				err = fmt.Errorf("DeleteRecord Do errCode: %d", res.StatusCode)
				return
			}
		}

		var all []byte
		all, err = ioutil.ReadAll(res.Body)
		if nil != err {
			if retries < retryTimes {
				continue
			} else {
				err = fmt.Errorf("DeleteRecord ReadAll err: %s", err.Error())
				return
			}
		}

		if reError.Match(all) {
			err = fmt.Errorf("DeleteRecord failed")
			return
		}

		if !reSuccess.Match(all) {
			err = fmt.Errorf("DeleteRecord not success")
			return
		}

		// 刷新缓存信息
		GetDomainInfo(domain)

		break
	}

	return
}

// RenewFreeDomain 免费域名续期
// 参数 domain 若为空字符串，则续期所有域名，否则只续期指定域名
// 参数 months 要续期的月份数，最少 1 个月，最多 12 个月
// 返回 免费域名和其续期结果
func RenewFreeDomain(domain string, months int) (renewedDomains map[string]string, err error) {
	renewedDomains = make(map[string]string)

	if nil == jar {
		err = fmt.Errorf("NOT LOGGED IN")
		return
	}

	if months < 1 || months > 12 {
		err = fmt.Errorf("months should be between 1 and 12")
		return
	}

	var re *regexp.Regexp
	re, err = regexp.Compile(`(?is:<tr><td>([^<]+?)</td><td>[^<]+</td><td>[^<]+<span class="[^"]+">(\d+)[^&]+&domain=(\d+)")`)
	if nil != err {
		err = fmt.Errorf("RenewFreeDomain Compile re err: %s", err.Error())
		return
	}

	retries := 0
	for {
		retries++

		var req *http.Request
		req, err = http.NewRequest("GET", domainsURL+"?a=renewals", nil)
		if nil != err {
			if retries < retryTimes {
				continue
			} else {
				err = fmt.Errorf("RenewFreeDomain NewRequest Renewals err: %s", err.Error())
				return
			}
		}

		tr := &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		}
		client := http.Client{
			Jar:       jar,
			Transport: tr,
			Timeout:   timeout,
		}

		req.Header.Add("Referer", loginURL)

		var res *http.Response
		res, err = client.Do(req)
		if nil != err {
			if retries < retryTimes {
				continue
			} else {
				err = fmt.Errorf("RenewFreeDomain Do Renewals err: %s", err.Error())
				return
			}
		} else if http.StatusOK != res.StatusCode {
			if retries < retryTimes {
				continue
			} else {
				err = fmt.Errorf("RenewFreeDomain Do Renewals errCode: %d", res.StatusCode)
				return
			}
		}

		var all []byte
		all, err = ioutil.ReadAll(res.Body)
		if nil != err {
			if retries < retryTimes {
				continue
			} else {
				err = fmt.Errorf("RenewFreeDomain ReadAll Renewals err: %s", err.Error())
				return
			}
		}

		// 需要续期的域名及 ID
		domains := make(map[string]string)

		allMatches := re.FindAllSubmatch(all, -1)
		for _, match := range allMatches {
			if 4 != len(match) {
				continue
			}

			domainName := string(match[1])
			expDays, _ := strconv.Atoi(string(match[2]))
			domainID := string(match[3])

			if expDays > renewableDays { // 未到续期有效期内
				renewedDomains[domainName] = "not in renewable day"
				continue
			}

			if "" != domain && 0 != strings.Compare(strings.ToLower(domain), strings.ToLower(domainName)) {
				renewedDomains[domainName] = "not in renew plan"
				continue
			}

			domains[domainName] = domainID
		}

		//////////////////////////////////////////////////////////////////////////////////////////////////////////////

		for domainName, domainID := range domains {
			params := url.Values{}
			params.Add("token", token)
			params.Add("renewalid", domainID)
			params.Add(fmt.Sprintf("renewalperiod[%s]", domainID), fmt.Sprintf("%dM", months))
			params.Add("paymentmethod", "credit")

			buf := bytes.NewBuffer(make([]byte, 0))
			buf.WriteString(params.Encode())

			req, err = http.NewRequest("POST", domainsURL+"?submitrenewals=true", buf)
			if nil != err {
				err = fmt.Errorf("RenewFreeDomain NewRequest SubmitRenewals %s err: %s", domainName, err.Error())
				return
			}

			tr = &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			}
			client = http.Client{
				Jar:       jar,
				Transport: tr,
				Timeout:   timeout,
			}

			req.Header.Add("Referer", domainsURL+"?a=renewdomain&domain="+domainID)
			req.Header.Add("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")

			res, err = client.Do(req)
			if nil != err {
				err = fmt.Errorf("RenewFreeDomain Do SubmitRenewals %s err: %s", domainName, err.Error())
				return
			} else if http.StatusOK != res.StatusCode {
				err = fmt.Errorf("RenewFreeDomain Do SubmitRenewals %s errCode: %d", domainName, res.StatusCode)
				return
			}

			all, err = ioutil.ReadAll(res.Body)
			if nil != err {
				err = fmt.Errorf("RenewFreeDomain ReadAll SubmitRenewals %s err: %s", domainName, err.Error())
				return
			}

			if bytes.Contains(all, []byte("Order Confirmation")) { // 续期失败
				renewedDomains[domainName] = "renew failed"
				continue
			}

			renewedDomains[domainName] = "renew success"
		}

		break
	}

	return
}

// CheckFreeDomainPurchasable 检查免费域名是否可购买
// 返回 可注册免费域名列表
func CheckFreeDomainPurchasable(domainPrefix string) (availableDomains []string, err error) {
	availableDomains = make([]string, 0)

	params := url.Values{}
	params.Add("domain", domainPrefix)
	params.Add("tld", "")

	retries := 0
	for {
		retries++

		buf := bytes.NewBuffer(make([]byte, 0))
		buf.WriteString(params.Encode())

		var req *http.Request
		req, err = http.NewRequest("POST", checkAvailableURL, buf)
		if nil != err {
			if retries < retryTimes {
				continue
			} else {
				err = fmt.Errorf("CheckFreeDomainPurchasable NewRequest err: %s", err.Error())
				return
			}
		}

		tr := &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		}
		client := http.Client{
			Transport: tr,
			Timeout:   timeout,
		}

		req.Header.Add("Referer", domainsURL)
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")

		var res *http.Response
		res, err = client.Do(req)
		if nil != err {
			if retries < retryTimes {
				continue
			} else {
				err = fmt.Errorf("CheckFreeDomainPurchasable Do err: %s", err.Error())
				return
			}
		} else if http.StatusOK != res.StatusCode {
			if retries < retryTimes {
				continue
			} else {
				err = fmt.Errorf("CheckFreeDomainPurchasable Do errCode: %d", res.StatusCode)
				return
			}
		}

		var all []byte
		all, err = ioutil.ReadAll(res.Body)
		if nil != err {
			if retries < retryTimes {
				continue
			} else {
				err = fmt.Errorf("CheckFreeDomainPurchasable ReadAll err: %s", err.Error())
				return
			}
		}

		var domainList DomainListResult
		err = json.Unmarshal(all, &domainList)
		if nil != err {
			err = fmt.Errorf("CheckFreeDomainPurchasable Unmarshal err: %s", err.Error())
			return
		}

		if 0 != strings.Compare("OK", strings.ToUpper(domainList.Status)) {
			err = fmt.Errorf("CheckFreeDomainPurchasable status err: %s", domainList.Status)
			return
		}

		for _, domain := range domainList.FreeDomains {
			if 0 != strings.Compare("AVAILABLE", strings.ToUpper(domain.Status)) ||
				0 != strings.Compare("FREE", strings.ToUpper(domain.Type)) {
				continue
			}

			availableDomains = append(availableDomains, domain.Domain+domain.TLD)
		}

		break
	}

	return
}

// PurchaseFreeDomain 购买免费域名（网站做了 GOOGLE 的反机器人校验，较难突破）
// 需要注意：Freenom 账号的区域要与发起购买请求的 IP 的地理位置保持一致
// 可以访问 http://my.freenom.com/details/js/dynamiccountry.php 获取当前 IP 的地区名称英文缩写
func PurchaseFreeDomain(domain string) (err error) {
	err = fmt.Errorf("To be implemented")
	return
}
