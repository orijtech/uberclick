package main

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/odeke-em/uberclick"
)

func main() {
	http.Handle("/", http.FileServer(http.Dir("./static")))
	http.HandleFunc("/init", func(rw http.ResponseWriter, req *http.Request) {
		defer req.Body.Close()
		subm, err := uberclick.FparseSubmission(req.Body)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusBadRequest)
			return
		}
		nonceSubm, werr := uberclick.GenerateNonce(subm)
log.Printf("generated nonce; %+v err: %v\n", nonceSubm, werr)
		if werr != nil {
			blob, _ := json.MarshalIndent(werr, "", "  ")
			http.Error(rw, string(blob), http.StatusBadRequest)
			return
		}
		blob, _ := json.MarshalIndent(nonceSubm, "", "  ")
		rw.Write(blob)
	})

	if err := http.ListenAndServe(":9899", nil); err != nil {
		log.Fatal(err)
	}
}
