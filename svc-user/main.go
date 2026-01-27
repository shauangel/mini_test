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

	mux.HandleFunc("/user/info", func(w http.ResponseWriter, r *http.Request) {
		log.Println("user: /user/info called")
		fmt.Fprintln(w, "user-ok")
	})

	srv := &http.Server{
		Addr:         ":8001",
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}

	log.Println("svc-user listening on :8001")
	log.Fatal(srv.ListenAndServe())
}
