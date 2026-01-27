package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

var client = &http.Client{Timeout: 2 * time.Second}

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

	mux.HandleFunc("/api/user", proxy("http://127.0.0.1:8001/user/info"))
	mux.HandleFunc("/api/order", proxy("http://127.0.0.1:8002/order/create"))

	srv := &http.Server{
		Addr:         ":8000",
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}

	log.Println("svc-gateway listening on :8000")
	log.Fatal(srv.ListenAndServe())
}
