package main

import (
    "fmt"
    "io"
    "log"
    "net/http"
    "os"
    "time"
)

var client = &http.Client{Timeout: 2 * time.Second}

func getenv(key, def string) string {
    if v := os.Getenv(key); v != "" {
        return v
    }
    return def
}

func proxy(target string) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        log.Println("gateway: proxy to", target)

        resp, err := client.Get(target)
        if err != nil {
            log.Println("gateway: upstream error:", err)
            http.Error(w, "upstream error", http.StatusBadGateway)
            return
        }
        defer resp.Body.Close()

        body, _ := io.ReadAll(resp.Body)
        w.WriteHeader(resp.StatusCode)
        w.Write(body)
    }
}

func main() {
    mux := http.NewServeMux()

    mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
        fmt.Fprintln(w, "ok")
    })

    userURL := getenv("USER_SERVICE_URL", "http://127.0.0.1:8001/user/info")
    orderURL := getenv("ORDER_SERVICE_URL", "http://127.0.0.1:8002/order/create")

    mux.HandleFunc("/api/user", proxy(userURL))
    mux.HandleFunc("/api/order", proxy(orderURL))

	srv := &http.Server{
		Addr:         ":8003",
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}

	log.Println("svc-payment listening on :8003")
	log.Fatal(srv.ListenAndServe())
}
