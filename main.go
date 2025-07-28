package main

import (
	pam "authspeedtracker/pam_go"
	"io/ioutil"
	"fmt"
	"time"
)

func main() {
	filename := "/home/kaho/develop/AuthSpeedTracker/log/pamlog/pass.log"

	backupFilename := filename + time.Now().Format("20060102150405") + ".log"
	input, err := ioutil.ReadFile(filename)
	if err != nil {
		fmt.Println("Error reading file :", err)
		return
	}
	err = ioutil.WriteFile(backupFilename, input, 0644)
	if err != nil {
		fmt.Println("Bacup creation Error:", err)
	}

	pam.WatchFileForUpdates(filename)
}

