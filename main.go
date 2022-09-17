package main

import(
	"os"
	"fmt"
	"flag"
	"bufio"
	"net/http"
	"io/ioutil"
	"encoding/json"
	"path/filepath"
	"github.com/fatih/color"
	"github.com/fbiville/markdown-table-formatter/pkg/markdown"
)

const (
	CIRCL string = "https://cve.circl.lu/api/cve/"
	NIST string = "https://nvd.nist.gov/vuln/detail/"
)

type Vulnerability struct {
    CVEID string `json:"id"`
    CVSS float32  `json:"cvss"`
	CWE	string `json:"cwe"`
	SUMMARY string `json:"summary"`
	LINK string
}

func (v *Vulnerability) GetAsArray(nosum bool) []string {
	if nosum {
		return []string{v.CVEID, fmt.Sprintf("%.1f", v.CVSS), v.CWE, v.LINK}
	}
	return []string{v.CVEID, fmt.Sprintf("%.1f", v.CVSS), v.CWE, v.SUMMARY, v.LINK}
}

func checkAndCreateDir(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		err := os.MkdirAll(path, os.ModePerm)
		if err != nil {
			return err
		}
	}
	return nil
}

func Write2File(path, filename, table string) error {
	if err := checkAndCreateDir(path); err != nil {
		return err
	}
	f, err := os.Create(filepath.Join(path, filename))
	defer f.Close()
	if _, err = f.WriteString(table); err != nil {
		return err
	}
	return nil
}

func requestJSONData(cve string) *Vulnerability {
	client := &http.Client{}
	target :=  string(CIRCL + cve)

	req, _ := http.NewRequest(http.MethodGet, target, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.181 Safari/537.36")

	response, err := client.Do(req)

    if err != nil {
        color.Red("[-]" + err.Error())
		return nil
    }

	defer response.Body.Close()

    responseData, err := ioutil.ReadAll(response.Body)
    
	if err != nil {
		color.Red("[-]" + err.Error())
		return nil
    }

	responsestring := string(responseData)

	vuln := Vulnerability{}
    json.Unmarshal([]byte(responsestring), &vuln)
	vuln.LINK = string(NIST+cve)

	return &vuln
}

func main() {
	var file = flag.String("f", "", "File to read and search through.")
	var target = flag.String("t", "", "Target directory.")
	var filename = flag.String("to", "", "Target file to put the table in.")

	var nosummary = flag.Bool("nosum", false, "Dont print the summary.")

	flag.Parse()

	if *file == "" {
		color.Red("[-] You need to provide atleast the file argument.")
		flag.Usage()
		os.Exit(1)
	}

	readFile, err := os.Open(*file)
  
    if err != nil {
        color.Red("[-] The file cannot be opened or does not exist.")
    }

	defer readFile.Close()
    fileScanner := bufio.NewScanner(readFile)
    fileScanner.Split(bufio.ScanLines)

	var cves [][]string

    for fileScanner.Scan() {
		t := fileScanner.Text()
        v := requestJSONData(t)
		cves = append(cves, v.GetAsArray(*nosummary))
    }

	var basicTable string
	var terr error

	if *nosummary {
		basicTable, terr = markdown.NewTableFormatterBuilder().WithCustomSort(markdown.DESCENDING_ORDER.StringCompare(0)).Build("CVE", "CVSS", "CWE", "Further reading").Format(cves)
		if terr != nil {
			color.Red(terr.Error())
		} 
	} else {
		basicTable, terr = markdown.NewTableFormatterBuilder().WithCustomSort(markdown.DESCENDING_ORDER.StringCompare(0)).Build("CVE", "CVSS", "CWE", "Summary", "Further reading").Format(cves)
		if terr != nil {
			color.Red(terr.Error())
		} 
	}

	if err != nil {
		color.Red("[-] Cannot create a table")
	}

	if *target != "" && *filename != "" {
		Write2File(*target, *filename, fmt.Sprint(basicTable))
	} else {
		if *target != "" || *filename != "" {
			color.Yellow("[!] You need to provide a filename and a target directory to use the output feature.")
			flag.Usage()
			fmt.Print("\n\n\n")
		}
	}

	fmt.Print(basicTable)
}