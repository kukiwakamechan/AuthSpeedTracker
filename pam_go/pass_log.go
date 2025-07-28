package pam

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"regexp"
	"time"

	tcpdump "authspeedtracker/package"

	"github.com/fsnotify/fsnotify"
)

func WatchFileForUpdates(filename string) {
	var lastSize int64
	ipRegex := regexp.MustCompile(`IP: ([\d\.]+) \| Time: (\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+)`)

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		fmt.Println("Error creating watcher:", err)
		return
	}
	defer watcher.Close()

	
	if err = ioutil.WriteFile(filename, []byte{}, 0644); err != nil {
		fmt.Println("Error clearing file:", err)
		return
	}
	

	done := make(chan bool)
	go func() {
		for {
			select {
			case event := <-watcher.Events:
				if event.Op&fsnotify.Write == fsnotify.Write {
					fileInfo, err := os.Stat(filename)
					if err != nil {
						fmt.Println("Error getting file info:", err)
						continue
					}

					currentSize := fileInfo.Size()
					if currentSize > lastSize {
						data, err := ioutil.ReadFile(filename)
						if err != nil {
							fmt.Println("Error reading file:", err)
							continue
						}

						newContent := data[lastSize:]
						matches := ipRegex.FindAllSubmatch(newContent, -1)
						for _, match := range matches {
							if len(match) < 3 {
								fmt.Println("不正なログ、スキップ:", match)
								continue
							}

							ipAddress := string(match[1])
							arrivalTimeString := string(match[2])

							arrivalTime, err := time.Parse("2006-01-02T15:04:05.999999999", arrivalTimeString)
							if err != nil {
								fmt.Println("Error parsing time:", err)
								continue
							}

							clientIP := net.ParseIP(ipAddress)
							if clientIP == nil {
								fmt.Println("Invalid IP, skip:", ipAddress)
								continue
							}


							//serverIP
							serverIPStr := os.Getenv("SERVER_IP")
							if serverIPStr == "" {
								serverIPStr = "10.1.181.10"
							}
							serverIP := net.ParseIP(serverIPStr)

							time.Sleep(10 * time.Second)
							fmt.Println("GetPasswordEnterTime 呼ばれた")
							tcpdump.GetPasswordEnterTime(serverIP, net.ParseIP(ipAddress), arrivalTime)

							fmt.Println("IP Address:", ipAddress, "Arrival Time:", arrivalTime)
						}
						lastSize = currentSize
					}
				}
			case err := <-watcher.Errors:
				fmt.Println("Error:", err)
			}
		}
	}()

	err = watcher.Add(filename)
	if err != nil {
		fmt.Println("Error watching file:", err)
		return
	}
	<-done
}



