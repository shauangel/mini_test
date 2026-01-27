package main

import (
    "fmt"
    "log"
    "net/http"
    "time"
)

func main() {
    mux := http.NewServeMux()

    mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
        fmt.Fprintln(w, "ok")
    })

    mux.HandleFunc("/payment/charge", func(w http.ResponseWriter, r *http.Request) {
        log.Println("payment: /payment/charge called")
        fmt.Fprintln(w, "payment-ok")
    })

    srv := &http.Server{
        Addr:         ":8000",      // 這裡要是 8000
        Handler:      mux,
        ReadTimeout:  5 * time.Second,
        WriteTimeout: 5 * time.Second,
    }

    log.Println("svc-payment listening on :8000")
    log.Fatal(srv.ListenAndServe())
}
