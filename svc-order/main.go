package main

import (
    "fmt"
    "io"
    "log"
    "net/http"
    "os"
    "time"
)

func getenv(key, def string) string {
    if v := os.Getenv(key); v != "" {
        return v
    }
    return def
}

var httpClient = &http.Client{Timeout: 2 * time.Second}


func main() {
    mux := http.NewServeMux()

    mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
        fmt.Fprintln(w, "ok")
    })

    paymentURL := getenv("PAYMENT_URL", "http://127.0.0.1:8003/payment/charge")

    mux.HandleFunc("/order/create", func(w http.ResponseWriter, r *http.Request) {
        log.Println("order: /order/create called")

        resp, err := httpClient.Post(paymentURL, "text/plain", nil)
        if err != nil {
            log.Println("order: payment call failed:", err)
            http.Error(w, "payment failed", http.StatusInternalServerError)
            return
        }
        defer resp.Body.Close()

        body, _ := io.ReadAll(resp.Body)
        fmt.Fprintf(w, "order-ok -> %s", string(body))
    })

	srv := &http.Server{
		Addr:         ":8002",
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}

	log.Println("svc-order listening on :8002")
	log.Fatal(srv.ListenAndServe())
}
