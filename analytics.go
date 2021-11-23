package analytics

import (
	"bytes"
	"compress/zlib"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type Analyzer interface {
	Dashboard(w http.ResponseWriter, r *http.Request)
	InsertRequest(r *http.Request)
}

type AnalyticsConfiguration struct {
	HashIPSecret         string
	GroupByURLSegment    int
	EntriesByURLSegment  int
	WriteScheduleSeconds int
	Name                 string
	Password             string
	Directory            string
	UserAgentBlackList   []string
}

type analytics struct {
	HashIPSecret         string
	groupBy              int
	entriesBy            int
	WriteScheduleSeconds int
	Password             string
	Name                 string
	Directory            string
	Mux                  *sync.RWMutex
	logger               func(...interface{}) (int, error)
	UserAgentBlackList   []string
	IPEntries            map[string]map[string][]action
}

func NewAnalytics(config AnalyticsConfiguration, logger func(...interface{}) (int, error)) Analyzer {
	if logger == nil {
		logger = fmt.Println
	}
	ana := &analytics{
		Name:                 config.Name,
		Password:             config.Password,
		groupBy:              config.GroupByURLSegment,
		entriesBy:            config.EntriesByURLSegment,
		HashIPSecret:         config.HashIPSecret,
		WriteScheduleSeconds: config.WriteScheduleSeconds,
		Directory:            config.Directory,
		UserAgentBlackList:   config.UserAgentBlackList,
		Mux:                  &sync.RWMutex{},
		logger:               logger,
	}
	ana.IPEntries = map[string]map[string][]action{}
	ana.IPEntries[time.Now().Local().Format("2006-01-02")] = ana.readSavedData(time.Now().Local())
	ana.scheduleWrite()
	return ana
}

func (a analytics) scheduleWrite() {
	ticker := time.NewTicker(time.Duration(a.WriteScheduleSeconds) * time.Second)
	quit := make(chan struct{})
	go func() {
		for {
			select {
			case <-ticker.C:
				err := a.writeFile()
				if err != nil {
					a.logger(err)
				}
			case <-quit:
				ticker.Stop()
				return
			}
		}
	}()
}

var DefaultUserAgentBlacklist = []string{
	"wget", "python", "perl", "msnbot", "netresearch", "bot",
	"archive", "crawl", "googlebot", "msn", "archive", "php",
	"panscient", "berry", "yandex", "bing", "fluffy",
}

func (a analytics) InsertRequest(r *http.Request) {
	ua := strings.ToLower(r.UserAgent())
	bots := a.UserAgentBlackList
	for _, b := range bots {
		if strings.Contains(strings.ToLower(ua), b) {
			return
		}
	}
	act := action{Page: r.URL.Path, Query: r.URL.RawQuery}
	a.Mux.Lock()
	defer a.Mux.Unlock()
	a.insert(r.RemoteAddr, act)
}

func (a analytics) Dashboard(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if len(a.Password) > 0 && (len(q["k"]) == 0 || len(q["k"][0]) == 0 || q["k"][0] != a.Password) {
		a.logger(fmt.Errorf("Unauthorized"))
		w.WriteHeader(http.StatusUnauthorized)
		w.Write(nil)
		return
	}

	date := time.Now()
	var err error
	if len(q["date"]) > 0 {
		date, err = time.Parse("2006-01-02", q["date"][0])
		if err != nil {
			a.logger(err)
			w.WriteHeader(http.StatusBadRequest)
			w.Write(nil)
			return
		}
	}
	var data map[string][]action
	if date.Format("2006-01-02") == time.Now().Format("2006-01-02") {
		data = a.IPEntries[date.Format("2006-01-02")]
	} else {
		data = a.readSavedData(date)
	}

	entries := len(data)
	urlHits := map[string]map[string]int{}
	for _, actions := range data {
		for _, act := range actions {
			pParts := strings.Split(act.Page, "/")
			groupBy := pParts[a.groupBy]
			dataEntry := strings.Join(pParts[a.entriesBy:], "/")
			_, ok := urlHits[groupBy]
			if !ok {
				urlHits[groupBy] = map[string]int{}
			}

			urlHits[groupBy][dataEntry] = urlHits[groupBy][dataEntry] + 1
		}
	}

	dd := dashData{SessionCount: entries, URLHits: urlHits, Date: date.Format("2006-01-02")}
	t, err := template.New("").Parse(HTML)
	if err != nil {
		a.logger(err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write(nil)
		return
	}
	err = t.ExecuteTemplate(w, "layout", dd)
	if err != nil {
		a.logger(err)
	}
}

type dashData struct {
	SessionCount int
	Date         string
	URLHits      map[string]map[string]int
}

type action struct {
	Page  string
	Query string
}

func (a analytics) readSavedData(td time.Time) map[string][]action {
	fileName := a.Directory + td.Format("/2006/01/02/") + a.Name + td.Format("2006-01-02")

	entries := map[string][]action{}
	if _, err := os.Stat(fileName); os.IsNotExist(err) {

	} else {
		bs, err := ioutil.ReadFile(fileName)
		if err != nil {
			a.logger(err)
			return entries
		}
		r, err := zlib.NewReader(bytes.NewReader(bs))
		if err != nil {
			a.logger(err)
			return entries
		}
		jsonBytes := bytes.NewBuffer([]byte{})
		_, err = io.Copy(jsonBytes, r)
		if err != nil {
			a.logger(err)
			return entries
		}
		r.Close()
		err = json.Unmarshal(jsonBytes.Bytes(), &entries)
		if err != nil {
			a.logger(err)
		}
	}
	return entries
}

func (a analytics) insert(ip string, act action) {
	ts := time.Now().Format("2006-01-02")
	stamps := a.IPEntries[ts]
	if stamps == nil {
		a.IPEntries[ts] = map[string][]action{}
	}
	if len(a.HashIPSecret) > 0 {
		hash := sha256.New()
		ip = ts + ip + a.HashIPSecret
		inpIP := strings.NewReader(ip)
		if _, err := io.Copy(hash, inpIP); err != nil {
			a.logger(err)
		}
		sum := hash.Sum(nil)
		ip = string(sum)
	}
	entries := stamps[ip]
	if entries == nil {
		entries = []action{}
	}
	entries = append(entries, act)

	a.IPEntries[ts][ip] = entries
}

func (a analytics) writeFile() error {
	ts := time.Now().Format("/2006/01/02")
	err := os.MkdirAll(a.Directory+ts, os.ModePerm)
	if err != nil {
		return err
	}
	a.Mux.Lock()
	defer a.Mux.Unlock()
	for k, e := range a.IPEntries {
		data, err := json.Marshal(e)
		if err != nil {
			return err
		}
		f, err := os.Create(a.Directory + ts + "/" + a.Name + k)
		if err != nil {
			return err
		}
		var b bytes.Buffer
		w := zlib.NewWriter(&b)
		w.Write(data)
		w.Close()
		defer f.Close()
		_, err = f.Write(b.Bytes())
		if err != nil {
			return err
		}
	}
	return nil
}

const HTML = `
{{ define "layout" }}
<!DOCTYPE html>
<html lang="en">
    <head></head>
    <body>
        <style type="text/css">
            .tg  {border-collapse:collapse;border-spacing:0;}
            .tg td{border-color:black;border-style:solid;border-width:1px;font-family:Arial, sans-serif;font-size:14px; overflow:hidden;padding:10px 5px;word-break:normal;}
            .tg th{border-color:black;border-style:solid;border-width:1px;font-family:Arial, sans-serif;font-size:14px; font-weight:normal;overflow:hidden;padding:10px 5px;word-break:normal;}
            .tg .tg-0lax{text-align:left;vertical-align:top}
        </style>
        <script>
           function UpdateQueryString(key, value, url) {
                if (!url) url = window.location.href;
                var re = new RegExp("([?&])" + key + "=.*?(&|#|$)(.*)", "gi"),
                    hash;

                if (re.test(url)) {
                    if (typeof value !== 'undefined' && value !== null) {
                        return url.replace(re, '$1' + key + "=" + value + '$2$3');
                    } 
                    else {
                        hash = url.split('#');
                        url = hash[0].replace(re, '$1$3').replace(/(&|\?)$/, '');
                        if (typeof hash[1] !== 'undefined' && hash[1] !== null) {
                            url += '#' + hash[1];
                        }
                        return url;
                    }
                }
                else {
                    if (typeof value !== 'undefined' && value !== null) {
                        var separator = url.indexOf('?') !== -1 ? '&' : '?';
                        hash = url.split('#');
                        url = hash[0] + separator + key + '=' + value;
                        if (typeof hash[1] !== 'undefined' && hash[1] !== null) {
                            url += '#' + hash[1];
                        }
                        return url;
                    }
                    else {
                        return url;
                    }
                }
            }

            function chooseDate(object) {
               window.location.href = UpdateQueryString("date", object.value, window.location.href)
            }
        </script>
        <section id="about">
            <div class="container-fluid align-self-center">
                <div class="row d-flex justify-content-center">
                    <div class="col-12 text-center align-self-center">
                        <h1>{{.Date}}</h1>
                        <input type="date" id="date" value="{{.Date}}" onchange="chooseDate(this)">
                        <h2>Unique Sessions Today: {{.SessionCount}}</h2>
                        <h3>Page Views</h3>
                        {{range $Category, $URLS := .URLHits}}
                            <h5> /{{$Category}}</h5>
                            <table class="tg" style="undefined;table-layout: fixed; width: 320px">
                                <colgroup>
                                    <col style="width: 70px">
                                    <col style="width: 250px">
                                </colgroup>
                                <thead>
                                    <tr>
                                        <th class="tg-0lax">Page Views</th>
                                        <th class="tg-0lax">URL</th>
                                    </tr>
                                </thead>
                                <tbody>
                                {{range $URL, $count := $URLS}}
                                    <tr>
                                            <td class="tg-0lax">{{$count}} </td>
                                            <td class="tg-0lax">{{$URL}}</td>
                                    </tr>
                                {{end}}
                                </tbody>
                            </table>
                        {{ end }}
                    </div>
                </div>
            </div>
        </section>
    </body>
</html>
{{ end }}
`
