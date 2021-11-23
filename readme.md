# go-web-analytics

A minimal analytics package to start collecting traffic data without client dependencies.

# Logging incoming requests

    analytics := NewAnalytics(AnalyticsConfiguration{
    			Name:                 "sanjuanpuertorico",
    			Password:             os.Getenv("DASHBOARD_KEY"),
    			GroupByURLSegment:    1,
    			EntriesByURLSegment:  2,
    			WriteScheduleSeconds: 30,
    			Directory:            "logs",
    			HashIPSecret:         os.Getenv("HASH_IP_KEY"),
    			UserAgentBlackList:   DefaultUserAgentBlacklist,
    		}, fmt.Println)


    router.Use(func(next http.Handler) http.Handler {
    	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    		analytics.InsertRequest(r)
    		next.ServeHTTP(w, r)
    	})
    })

# Dashboard

    router.HandleFunc("/analytics", analytics.Dashboard).Methods("GET")

# Configuration

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

> `HashIPSecret` is a seed that if provided will be used to hash 
> the IP so you don't have plaintext user IPs stored

> `GroupByURLSegment` index in the URL split by `/` to group the results

> `EntriesByURLSegment` index in the URL split by `/` to count as results

> `WriteScheduleSeconds` how often we write to the file
> Name of file 

> `Directory` parent directory for the log files

> `Password` for a dashboard if it's used /analytics?k=mypassword

> `UserAgentBlacklist` entries to check if the user agent contains in order to avoid things like bots or automated tests
