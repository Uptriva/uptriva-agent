package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"
)

type GameServerSettings struct {
	GameType    string `json:"game_type"`
	QueryMethod string `json:"query_method"`
	QueryPort   int    `json:"query_port"`
}

var gameServerHTTPClient = &http.Client{
	Timeout: 8 * time.Second,
	Transport: &http.Transport{
		DialContext: checkedDialContext,
	},
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

func checkGameServer(target string, settings json.RawMessage) (string, int, string) {
	s := GameServerSettings{GameType: "custom", QueryMethod: "tcp_connect"}
	if len(settings) > 0 {
		json.Unmarshal(settings, &s)
	}
	if s.GameType == "" {
		s.GameType = "custom"
	}
	if s.QueryMethod == "" {
		s.QueryMethod = "tcp_connect"
	}

	host, portStr, err := net.SplitHostPort(target)
	if err != nil || host == "" {
		return "down", 0, "Invalid target, expected host:port"
	}
	serverPort, err := strconv.Atoi(portStr)
	if err != nil || serverPort < 1 || serverPort > 65535 {
		return "down", 0, "Invalid target port"
	}

	queryPort := s.QueryPort
	if queryPort == 0 {
		queryPort = serverPort
	}

	start := time.Now()
	latency := func() int { return int(time.Since(start).Milliseconds()) }

	switch s.QueryMethod {
	case "query":
		switch s.GameType {
		case "minecraft":
			return queryMinecraft(host, serverPort, latency)
		case "fivem":
			return queryFiveM(host, serverPort, latency)
		default:
			return queryA2S(host, queryPort, latency)
		}
	case "rest_api":
		if s.GameType == "fivem" {
			return queryFiveM(host, serverPort, latency)
		}
		return queryGenericJSON(host, serverPort, latency)
	case "tcp_connect":
		conn, err := checkedDialTimeout("tcp", target, 10*time.Second)
		lat := latency()
		if err != nil {
			return "down", lat, err.Error()
		}
		conn.Close()
		return "up", lat, "Game server port open"
	case "push":
		return "down", 0, "Push-based game server monitors are not queried by agents"
	default:
		return "down", 0, "Unsupported query method: " + s.QueryMethod
	}
}

var a2sInfoRequest = append([]byte{0xFF, 0xFF, 0xFF, 0xFF, 'T'}, []byte("Source Engine Query\x00")...)

func queryA2S(host string, port int, latency func() int) (string, int, string) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := checkedDialTimeout("udp", addr, 8*time.Second)
	if err != nil {
		return "down", latency(), err.Error()
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(8 * time.Second))

	if _, err := conn.Write(a2sInfoRequest); err != nil {
		return "down", latency(), "A2S send failed"
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	lat := latency()
	if err != nil {
		return "down", lat, err.Error()
	}

	data := buf[:n]
	if len(data) < 5 {
		return "down", lat, "A2S response too short"
	}

	header := binary.LittleEndian.Uint32(data[:4])
	if header == 0xFFFFFFFE {
		return "down", lat, "A2S split response not supported"
	}

	payload := data[4:]
	if len(payload) == 0 {
		return "down", lat, "A2S empty response"
	}

	if payload[0] == 0x41 {
		if len(payload) < 5 {
			return "down", lat, "A2S challenge too short"
		}
		challenge := binary.LittleEndian.Uint32(payload[1:5])
		req := append(append([]byte{0xFF, 0xFF, 0xFF, 0xFF, 'T'}, []byte("Source Engine Query\x00")...),
			byte(challenge), byte(challenge>>8), byte(challenge>>16), byte(challenge>>24))
		if _, err := conn.Write(req); err != nil {
			return "down", latency(), "A2S challenge resend failed"
		}
		n, err = conn.Read(buf)
		lat = latency()
		if err != nil {
			return "down", lat, err.Error()
		}
		data = buf[:n]
		if len(data) < 5 {
			return "down", lat, "A2S response too short"
		}
		payload = data[4:]
		if len(payload) == 0 || payload[0] != 0x49 {
			return "down", lat, "Unexpected A2S response type"
		}
	} else if payload[0] != 0x49 {
		return "down", lat, "Unexpected A2S response type"
	}

	info, err := parseA2SInfo(payload[1:])
	if err != nil {
		return "down", lat, "A2S parse failed: " + err.Error()
	}

	return "up", lat, fmt.Sprintf("%d/%d players on %s", info.Players, info.MaxPlayers, info.Map)
}

type a2sInfo struct {
	Name       string
	Map        string
	Game       string
	Players    int
	MaxPlayers int
	Bots       int
}

func readA2SString(payload []byte, offset int) (string, int, error) {
	idx := bytes.IndexByte(payload[offset:], 0x00)
	if idx < 0 {
		return "", offset, fmt.Errorf("unterminated string at %d", offset)
	}
	return string(payload[offset : offset+idx]), offset + idx + 1, nil
}

func parseA2SInfo(payload []byte) (*a2sInfo, error) {
	if len(payload) < 1 {
		return nil, fmt.Errorf("empty payload")
	}
	offset := 1
	var err error
	info := &a2sInfo{}
	if info.Name, offset, err = readA2SString(payload, offset); err != nil {
		return nil, err
	}
	if info.Map, offset, err = readA2SString(payload, offset); err != nil {
		return nil, err
	}
	if _, offset, err = readA2SString(payload, offset); err != nil {
		return nil, err
	}
	if info.Game, offset, err = readA2SString(payload, offset); err != nil {
		return nil, err
	}
	if offset+2 > len(payload) {
		return nil, fmt.Errorf("payload truncated")
	}
	offset += 2
	if offset+3 > len(payload) {
		return nil, fmt.Errorf("payload truncated")
	}
	info.Players = int(payload[offset])
	info.MaxPlayers = int(payload[offset+1])
	info.Bots = int(payload[offset+2])
	return info, nil
}

func queryMinecraft(host string, port int, latency func() int) (string, int, string) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := checkedDialTimeout("tcp", addr, 8*time.Second)
	if err != nil {
		return "down", latency(), err.Error()
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(8 * time.Second))

	handshake := buildMCPacket(0x00, append(append(writeMCVarint(-1), writeMCString(host)...), byte(port>>8), byte(port), 0x01))
	if _, err := conn.Write(handshake); err != nil {
		return "down", latency(), "Minecraft handshake failed"
	}
	if _, err := conn.Write(buildMCPacket(0x00, nil)); err != nil {
		return "down", latency(), "Minecraft status request failed"
	}

	packet, err := readMCPacket(conn)
	lat := latency()
	if err != nil {
		return "down", lat, err.Error()
	}
	if len(packet) < 1 || packet[0] != 0x00 {
		return "down", lat, "Unexpected Minecraft response"
	}

	jsonLen, n := readMCVarint(packet[1:])
	if n == 0 || 1+n+int(jsonLen) > len(packet) {
		return "down", lat, "Malformed Minecraft response"
	}
	jsonBytes := packet[1+n : 1+n+int(jsonLen)]

	var status struct {
		Version struct {
			Name     string `json:"name"`
			Protocol int    `json:"protocol"`
		} `json:"version"`
		Players struct {
			Online int `json:"online"`
			Max    int `json:"max"`
		} `json:"players"`
		Description json.RawMessage `json:"description"`
	}
	if err := json.Unmarshal(jsonBytes, &status); err != nil {
		return "down", lat, "Minecraft JSON parse failed"
	}

	return "up", lat, fmt.Sprintf("%d/%d players (%s)", status.Players.Online, status.Players.Max, status.Version.Name)
}

func writeMCVarint(v int32) []byte {
	var buf []byte
	uv := uint32(v)
	for {
		b := byte(uv & 0x7F)
		uv >>= 7
		if uv != 0 {
			b |= 0x80
		}
		buf = append(buf, b)
		if uv == 0 {
			break
		}
	}
	return buf
}

func readMCVarint(data []byte) (int32, int) {
	var result int32
	for i := 0; i < len(data) && i < 5; i++ {
		result |= int32(data[i]&0x7F) << (7 * i)
		if data[i]&0x80 == 0 {
			return result, i + 1
		}
	}
	return 0, 0
}

func writeMCString(s string) []byte {
	b := []byte(s)
	return append(writeMCVarint(int32(len(b))), b...)
}

func buildMCPacket(id byte, payload []byte) []byte {
	body := append([]byte{id}, payload...)
	return append(writeMCVarint(int32(len(body))), body...)
}

func readMCPacket(conn net.Conn) ([]byte, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(conn, header[:1]); err != nil {
		return nil, err
	}
	varintBytes := []byte{header[0]}
	for i := 0; header[i]&0x80 != 0 && i < 4; i++ {
		if _, err := io.ReadFull(conn, header[i+1:i+2]); err != nil {
			return nil, err
		}
		varintBytes = append(varintBytes, header[i+1])
	}
	pktLen, _ := readMCVarint(varintBytes)
	if pktLen <= 0 || pktLen > 1<<20 {
		return nil, fmt.Errorf("invalid packet length")
	}
	body := make([]byte, pktLen)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, err
	}
	return body, nil
}

func queryFiveM(host string, port int, latency func() int) (string, int, string) {
	url := fmt.Sprintf("http://%s:%d/dynamic.json", host, port)
	resp, err := gameServerHTTPClient.Get(url)
	lat := latency()
	if err != nil {
		return "down", lat, err.Error()
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 65536))
	if err != nil || resp.StatusCode >= 400 {
		return "down", lat, fmt.Sprintf("FiveM query failed: HTTP %d", resp.StatusCode)
	}

	var info struct {
		Clients    int      `json:"clients"`
		MaxClients int      `json:"sv_maxclients"`
		Hostname   string   `json:"hostname"`
		MapName    string   `json:"mapname"`
		GameType   string   `json:"gametype"`
		Resources  []string `json:"resources"`
	}
	if err := json.Unmarshal(body, &info); err != nil {
		return "down", lat, "FiveM response parse failed"
	}

	return "up", lat, fmt.Sprintf("%d/%d players on %s", info.Clients, info.MaxClients, info.MapName)
}

func queryGenericJSON(host string, port int, latency func() int) (string, int, string) {
	url := fmt.Sprintf("http://%s:%d/", host, port)
	resp, err := gameServerHTTPClient.Get(url)
	lat := latency()
	if err != nil {
		return "down", lat, err.Error()
	}
	defer resp.Body.Close()

	if _, err := io.ReadAll(io.LimitReader(resp.Body, 65536)); err != nil {
		return "down", lat, "REST query read failed"
	}
	if resp.StatusCode >= 400 {
		return "down", lat, fmt.Sprintf("REST query failed: HTTP %d", resp.StatusCode)
	}

	return "up", lat, "REST endpoint reachable"
}
