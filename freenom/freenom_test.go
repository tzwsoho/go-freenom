package freenom

import (
	"io/ioutil"
	"log"
	"regexp"
	"strings"
	"testing"
)

const (
	freenomUser   string = "freenomapi@gmail.com"
	freenomPwd    string = "AaBbCc!1@2#3"
	freenomDomain string = "freenom-api.tk"
)

func TestRegExp(t *testing.T) {
	re, err := regexp.Compile(`(?is:(records\[\d+\]\[type\])" value="([^"]*)".+?(records\[\d+\]\[name\])" value="([^"]*)".+?(records\[\d+\]\[ttl\])" value="(\d+)".+?(records\[\d+\]\[value\])" value="([^"]*)".+?(?:(records\[\d+\]\[priority\])" value="(\d+)".+?)?</td>)`)
	// re, err := regexp.Compile(`(?is:(records\[\d+\]\[type\]).+?</td>)`)
	if nil != err {
		t.Error(err.Error())
		return
	}

	allBytes, _ := ioutil.ReadFile("D:\\abc.txt")
	allM := re.FindAllSubmatch(allBytes, -1)
	for _, m := range allM {
		log.Printf("%+v\n", m)
	}

	return
}

func TestLogin(t *testing.T) {
	if err := Login(freenomUser, freenomPwd); nil != err {
		t.Error(err.Error())
		return
	}
}

func TestListDomains(t *testing.T) {
	TestLogin(t)

	if domains, err := ListDomains(); nil != err {
		t.Error(err.Error())
		return
	} else {
		for domain, expDate := range domains {
			log.Printf("Domain = %s Expiry Date = %s\n", domain, expDate)
		}
	}
}

func showRecords(domain string, t *testing.T) {
	if info, err := GetDomainInfo(domain); nil != err {
		t.Error(err.Error())
		return
	} else {
		log.Printf("DomainID = %s DomainName = %s Registration Date = %s Expiry Date = %s\n",
			info.DomainID, info.Domain, info.RegDate, info.ExpDate)
		for j, record := range info.Records {
			log.Printf("Record %d: Type = %s, Name = %s, TTL = %d, Value = %s, Priority = %d\n",
				j, record.Type, record.Name, record.TTL, record.Value, record.Priority)
		}
	}
}

func TestGetDomainInfo(t *testing.T) {
	TestLogin(t)

	showRecords(freenomDomain, t)
}

func TestAddRecord(t *testing.T) {
	TestLogin(t)

	var records []DomainRecord = []DomainRecord{
		DomainRecord{
			Type:     "A",
			Name:     "",
			Value:    "123.123.123.123",
			TTL:      1111,
			Priority: 0,
		},
		DomainRecord{
			Type:     "A",
			Name:     "ipv4",
			Value:    "127.0.0.1",
			TTL:      2222,
			Priority: 0,
		},
		DomainRecord{
			Type:     "AAAA",
			Name:     "ipv6",
			Value:    "::1",
			TTL:      3333,
			Priority: 0,
		},
		DomainRecord{
			Type:     "CNAME",
			Name:     "alias",
			Value:    "aliasdomain.com",
			TTL:      4444,
			Priority: 0,
		},
		DomainRecord{
			Type:     "LOC",
			Name:     "location",
			Value:    "23 06 32 N 113 15 53 E 10m",
			TTL:      5555,
			Priority: 0,
		},
		DomainRecord{
			Type:     "MX",
			Name:     "mymail",
			Value:    "maildomain.com",
			TTL:      6666,
			Priority: 10,
		},
		DomainRecord{
			Type:     "NAPTR",
			Name:     "mynaptr",
			Value:    `1 2 "" "" "" cidserver.example.com`,
			TTL:      7777,
			Priority: 0,
		},
		DomainRecord{
			Type:     "RP",
			Name:     "myrp",
			Value:    "username1.maildomain.com username2.maildomain.com",
			TTL:      8888,
			Priority: 0,
		},
		DomainRecord{
			Type:     "TXT",
			Name:     "mytxt",
			Value:    "enter some text here",
			TTL:      9999,
			Priority: 0,
		},
	}

	// 列出原有的记录列表
	showRecords(freenomDomain, t)

	log.Println(strings.Repeat("*", 80))
	log.Printf("Adding %d records\n", len(records))
	if err := AddRecord(freenomDomain, records); nil != err {
		t.Error(err.Error())
		return
	}
	log.Printf("%d Records successfully added\n", len(records))
	log.Println(strings.Repeat("*", 80))

	// 列出现有的记录列表
	showRecords(freenomDomain, t)
}

func TestModifyRecord(t *testing.T) {
	TestLogin(t)

	const (
		oldRecordType     string = "MX"
		oldRecordName     string = "mymail"
		oldRecordValue    string = "maildomain.com"
		oldRecordTTL      int    = 6666
		oldRecordPriority int    = 10

		newRecordType     string = "MX"
		newRecordName     string = "yourmail"
		newRecordValue    string = "mail.domain.com"
		newRecordTTL      int    = 9999
		newRecordPriority int    = 99
	)

	// 列出原有的记录列表
	showRecords(freenomDomain, t)

	log.Println(strings.Repeat("*", 80))
	log.Printf("Modifying record %s\n", oldRecordName)
	if err := ModifyRecord(freenomDomain,
		&DomainRecord{
			Type:     oldRecordType,
			Name:     oldRecordName,
			Value:    oldRecordValue,
			TTL:      oldRecordTTL,
			Priority: oldRecordPriority,
		},
		&DomainRecord{
			Type:     newRecordType,
			Name:     newRecordName,
			Value:    newRecordValue,
			TTL:      newRecordTTL,
			Priority: newRecordPriority,
		}); nil != err {
		t.Error(err.Error())
		return
	}
	log.Printf("Record %s successfully modified\n", oldRecordName)
	log.Println(strings.Repeat("*", 80))

	// 列出现有的记录列表
	showRecords(freenomDomain, t)
}

func TestDeleteRecordByIndex(t *testing.T) {
	TestLogin(t)

	const (
		recordIndex int = 0
	)

	// 列出原有的记录列表
	showRecords(freenomDomain, t)

	log.Println(strings.Repeat("*", 80))
	log.Printf("Deleting record %d\n", recordIndex)
	if err := DeleteRecordByIndex(freenomDomain, recordIndex); nil != err {
		t.Error(err.Error())
		return
	}
	log.Printf("Record %d successfully deleted\n", recordIndex)
	log.Println(strings.Repeat("*", 80))

	// 列出现有的记录列表
	showRecords(freenomDomain, t)
}

func TestDeleteRecord(t *testing.T) {
	TestLogin(t)

	const (
		recordType     string = "MX"
		recordName     string = "mymail"
		recordValue    string = "maildomain.com"
		recordTTL      int    = 6666
		recordPriority int    = 10
	)

	// 列出原有的记录列表
	showRecords(freenomDomain, t)

	log.Println(strings.Repeat("*", 80))
	log.Printf("Deleting record %s\n", recordName)
	if err := DeleteRecord(freenomDomain,
		&DomainRecord{
			Type:     recordType,
			Name:     recordName,
			Value:    recordValue,
			TTL:      recordTTL,
			Priority: recordPriority,
		}); nil != err {
		t.Error(err.Error())
		return
	}
	log.Printf("Record %s successfully deleted\n", recordName)
	log.Println(strings.Repeat("*", 80))

	// 列出现有的记录列表
	showRecords(freenomDomain, t)
}

func TestRenewFreeDomain(t *testing.T) {
	TestLogin(t)

	if domains, err := RenewFreeDomain(freenomDomain, 12); nil != err {
		t.Error(err.Error())
		return
	} else {
		for domain, result := range domains {
			log.Println(domain, result)
		}
	}
}

func TestCheckFreeDomainPurchasable(t *testing.T) {
	const (
		domainToCheck string = "freenom-api"
	)

	if domains, err := CheckFreeDomainPurchasable(domainToCheck); nil != err {
		t.Error(err.Error())
		return
	} else {
		for i, domain := range domains {
			log.Println(i, domain)
		}
	}
}
