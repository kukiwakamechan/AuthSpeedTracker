package tcpdump

import (
    "fmt"
    "log"
    "net"
    "os"
    "path/filepath"
    "time"

    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap"
)

func GetPasswordEnterTime(serverIP net.IP, clientIP net.IP, pamTimestamp time.Time) {
    const dirpath = "ログ出力先パス"

    var requestPasswordPacket gopacket.Packet 
    var sendPasswordPacket gopacket.Packet

    // (1) 最新の .dump ファイルを探索
    var newestFile string
    var newestTime time.Time
    err := filepath.Walk(dirpath, func(path string, info os.FileInfo, err error) error {
        if err != nil {
            return err
        }
        if !info.IsDir() && info.ModTime().After(newestTime) {
            newestFile = path
            newestTime = info.ModTime()
        }
        return nil
    })
    if err != nil {
        log.Fatal("pcap ファイル探索エラー：", err)
    }
    if newestFile == "" {
        log.Fatal("No files found in the directory:", dirpath)
    }
    log.Printf("DEBUG: using pcap => %s", newestFile)

    handle, err := pcap.OpenOffline(newestFile)
    if err != nil {
        log.Fatal("pcap オープンエラー：", err)
    }
    defer handle.Close()

    // パケット収集と振り分け
    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    var serverPkts, clientPkts []gopacket.Packet
    for pkt := range packetSource.Packets() {
        ipLayer := pkt.Layer(layers.LayerTypeIPv4)
        tcpLayer := pkt.Layer(layers.LayerTypeTCP)
        if ipLayer == nil || tcpLayer == nil {
            continue
        }
        ip := ipLayer.(*layers.IPv4)
        if ip.SrcIP.Equal(serverIP) && ip.DstIP.Equal(clientIP) {
            serverPkts = append(serverPkts, pkt)
        }
        if ip.SrcIP.Equal(clientIP) && ip.DstIP.Equal(serverIP) {
            clientPkts = append(clientPkts, pkt)
        }
    }
    log.Printf("DEBUG: serverPkts=%d, clientPkts=%d", len(serverPkts), len(clientPkts)) 

    //サーバ→クライアントで pamTimestamp より前の最良パケット
    requestBestDelta := time.Duration(1<<63 - 1)
    for _, pkt := range serverPkts {
        t := pkt.Metadata().Timestamp
        if t.After(pamTimestamp) {
            continue
        }
        d := pamTimestamp.Sub(t)
        if d < requestBestDelta {
            requestBestDelta = d
            requestPasswordPacket = pkt //requestPasswordPacket に格納
        }
    }
    if requestPasswordPacket == nil {
        log.Println("⚠️ サーバ→クライアントパケットが見つかりません")
        return
    }
    log.Printf("DEBUG: prompt @ %s (Δ %s)",
        requestPasswordPacket.Metadata().Timestamp.Format(time.RFC3339Nano),
        requestBestDelta,
    ) 

    // クライアント→サーバで prompt 直後の最良パケット
    sendBestDelta := time.Duration(1<<63 - 1)
    promptTime := requestPasswordPacket.Metadata().Timestamp
    for _, pkt := range clientPkts {
        t := pkt.Metadata().Timestamp
        if t.Before(promptTime) || t.After(pamTimestamp) {
            continue
        }
        d := t.Sub(promptTime)
        if d < sendBestDelta {
            sendBestDelta = d
            sendPasswordPacket = pkt // sendPasswordPacket に格納
        }
    }
    if sendPasswordPacket == nil {
        log.Println("⚠️ クライアント→サーバパケットが見つかりません")
        return
    }
    log.Printf("DEBUG: response @ %s (Δ %s)",
        sendPasswordPacket.Metadata().Timestamp.Format(time.RFC3339Nano),
        sendBestDelta,
    ) 

    // 差分計算・ログ書き込み
    diff := sendPasswordPacket.Metadata().Timestamp.Sub(requestPasswordPacket.Metadata().Timestamp) 

    logPath := "絶対パス/diff.log" // ログ出力先
    f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    if err != nil {
        log.Println("ログファイルのオープンに失敗：", err)
        return
    }
    defer f.Close()

    entry := fmt.Sprintf(
        "Diff: %v | ClientIP: %s | ServerIP: %s | Time: %s\n",
        diff, clientIP.String(), serverIP.String(), pamTimestamp.Format(time.RFC3339),
    )
    if _, err := f.WriteString(entry); err != nil {
        log.Println("ログ書き込み失敗：", err)
    }
}
