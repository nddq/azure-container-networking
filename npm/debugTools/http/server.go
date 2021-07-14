package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"

	converter "github.com/Azure/azure-container-networking/hack/dataplaneConverter"
	"github.com/Azure/azure-container-networking/log"
	"github.com/Azure/azure-container-networking/npm/http/api"
	"github.com/Azure/azure-container-networking/npm/iptm"
	"github.com/Azure/azure-container-networking/npm/util"
	"github.com/gorilla/mux"
	"google.golang.org/protobuf/proto"
)

var (
	DefaultHTTPListeningAddress = fmt.Sprintf("%s:%s", api.DefaultListeningIP, api.DefaultHttpPort)
	iptableBuffer               = bytes.NewBuffer(nil)
	tableName                   = "filter"
)

type Pod struct {
	Name      string
	Namespace string
	IPAddr    string
	Ports     string
	Age       string
}

func SaveIntoBuffer(tableName string, buffer *bytes.Buffer) error {
	l, err := iptm.GrabIptablesLocks()
	if err != nil {
		return err
	}

	defer func(l *os.File) {
		if err = l.Close(); err != nil {
			log.Logf("Failed to close iptables locks")
		}
	}(l)

	cmdArgs := []string{"-t", string(tableName)}
	cmd := exec.Command(util.IptablesSave, cmdArgs...)

	cmd.Stdout = buffer
	stderrBuffer := bytes.NewBuffer(nil)
	cmd.Stderr = stderrBuffer

	err = cmd.Run()

	if err != nil {
		stderrBuffer.WriteTo(buffer) // ignore error, since we need to return the original error
	}
	return err
}

func redirectToDashboard(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/dashboard/", http.StatusFound)
}

func getIptableRules(w http.ResponseWriter, r *http.Request) {
	var (
	// If required, we can move this buffer one stage up
	// and built as required overtime
	)
	if err := SaveIntoBuffer(tableName, iptableBuffer); err != nil {
		// metrics.SendErrorLogAndMetric(util.IptmID, "[BulkUpdateIPtables] Error: failed to get iptables-save command output with err: %s", err.Error())
		fmt.Println(err.Error())
	}

	c := &converter.Converter{}
	data := c.GetRulesFromIptable(tableName, iptableBuffer)
	resp, err := proto.Marshal(data)
	if err != nil {
		w.Write([]byte(err.Error()))
		return
	}
	w.Write(resp)

}

func getPodList(w http.ResponseWriter, r *http.Request) {
	log.Logf("Endpoint Hit: getPodList")
	dummyRes := []Pod{{Name: "azure-cni-networkmonitor-7jgsx", Namespace: "kube-system", IPAddr: "10.0.0.01", Ports: "80-UDP, 80-TCP", Age: "14d"},
		{Name: "azure-cni-networkmonitor-lbmdx", Namespace: "kube-system", IPAddr: "10.0.0.01", Ports: "80-UDP, 80-TCP", Age: "14d"},
		{Name: "azure-cni-networkmonitor-vtlxv", Namespace: "kube-system", IPAddr: "10.0.0.01", Ports: "80-UDP, 80-TCP", Age: "14d"}}

	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	json.NewEncoder(w).Encode(dummyRes)

}

func main() {
	// Init HTTP Router - mux
	router := mux.NewRouter()

	// map directory to server static files
	router.PathPrefix("/dashboard/").Handler(http.StripPrefix("/dashboard/", http.FileServer(http.Dir("./static/"))))
	router.HandleFunc("/", redirectToDashboard).Methods("GET")
	router.HandleFunc("/getRules/", getIptableRules).Methods("GET")
	router.HandleFunc("/podList/", getPodList).Methods("GET", "OPTIONS")

	srv := &http.Server{
		Handler: router,
		Addr:    DefaultHTTPListeningAddress,
	}

	log.Logf("Starting server on %s... ", DefaultHTTPListeningAddress)
	log.Errorf("Failed to start server with error: %+v", srv.ListenAndServe())
}
