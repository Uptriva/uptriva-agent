package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

type protoAuthSettings struct {
	Username   string `json:"username"`
	Password   string `json:"password"`
	PrivateKey string `json:"private_key"`
	TLSMode    string `json:"tls_mode"`
}

func parseProtoAuth(settings json.RawMessage) protoAuthSettings {
	var s protoAuthSettings
	if len(settings) > 0 {
		_ = json.Unmarshal(settings, &s)
	}
	return s
}

type loginAuthMech struct{ username, password string }

func (a *loginAuthMech) Start(server *smtp.ServerInfo) (string, []byte, error) {
	return "LOGIN", []byte(a.username), nil
}

func (a *loginAuthMech) Next(fromServer []byte, more bool) ([]byte, error) {
	if more {
		return []byte(a.password), nil
	}
	return nil, nil
}

func splitHostPortDefault(target, defaultPort string) (string, string, error) {
	if !strings.Contains(target, ":") {
		return target, defaultPort, nil
	}
	host, port, err := net.SplitHostPort(target)
	if err != nil || host == "" || port == "" {
		return "", "", fmt.Errorf("invalid host:port")
	}
	return host, port, nil
}

func truncErr(err error) string {
	msg := err.Error()
	if len(msg) > 120 {
		msg = msg[:120]
	}
	return msg
}

func checkFTP(target string, settings json.RawMessage, verifySSL bool) (string, int, string) {
	start := time.Now()
	host, port, err := splitHostPortDefault(target, "21")
	if err != nil {
		return "down", 0, "invalid host:port"
	}
	s := parseProtoAuth(settings)
	addr := net.JoinHostPort(host, port)

	tlsConfig := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12, InsecureSkipVerify: !verifySSL}

	var conn net.Conn
	if s.TLSMode == "tls" {
		raw, err := checkedDialTimeout("tcp", addr, 10*time.Second)
		if err != nil {
			return "down", int(time.Since(start).Milliseconds()), truncErr(err)
		}
		tlsConn := tls.Client(raw, tlsConfig)
		if err := tlsConn.Handshake(); err != nil {
			raw.Close()
			return "down", int(time.Since(start).Milliseconds()), "TLS handshake failed: " + truncErr(err)
		}
		conn = tlsConn
	} else {
		conn, err = checkedDialTimeout("tcp", addr, 10*time.Second)
		if err != nil {
			return "down", int(time.Since(start).Milliseconds()), truncErr(err)
		}
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(12 * time.Second))

	reader := bufio.NewReader(conn)
	readReply := func() (int, string, error) {
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return 0, "", err
			}
			line = strings.TrimRight(line, "\r\n")
			if len(line) < 4 {
				continue
			}
			code := 0
			fmt.Sscanf(line[:3], "%d", &code)
			if line[3] == '-' {
				continue
			}
			return code, line, nil
		}
	}
	send := func(cmd string) (int, string, error) {
		if _, err := fmt.Fprintf(conn, "%s\r\n", cmd); err != nil {
			return 0, "", err
		}
		return readReply()
	}

	code, greeting, err := readReply()
	latency := int(time.Since(start).Milliseconds())
	if err != nil {
		return "down", latency, "no greeting received"
	}
	if code != 220 {
		return "down", latency, "unexpected greeting: " + greeting
	}

	if s.TLSMode == "starttls" {
		code, reply, err := send("AUTH TLS")
		if err != nil {
			return "down", int(time.Since(start).Milliseconds()), "AUTH TLS failed"
		}
		if code != 234 {
			return "down", int(time.Since(start).Milliseconds()), "server does not support AUTH TLS: " + reply
		}
		conn = tls.Client(conn, tlsConfig)
		if err := conn.(*tls.Conn).Handshake(); err != nil {
			return "down", int(time.Since(start).Milliseconds()), "TLS handshake failed: " + truncErr(err)
		}
		reader = bufio.NewReader(conn)
		send("PBSZ 0")
		send("PROT P")
	}

	if s.Username != "" {
		scrub := strings.NewReplacer("\r", "", "\n", "")
		code, _, err := send("USER " + scrub.Replace(s.Username))
		if err != nil {
			return "down", int(time.Since(start).Milliseconds()), "FTP USER failed"
		}
		switch {
		case code == 230:
		case code == 331:
			code, _, err = send("PASS " + scrub.Replace(s.Password))
			if err != nil || code != 230 {
				return "down", int(time.Since(start).Milliseconds()), "FTP login rejected (check credentials)"
			}
		default:
			return "down", int(time.Since(start).Milliseconds()), "FTP USER rejected"
		}
		if code, _, err := send("PWD"); err != nil || code != 257 {
			return "down", int(time.Since(start).Milliseconds()), "FTP PWD failed after login"
		}
		send("QUIT")
		return "up", int(time.Since(start).Milliseconds()), "FTP login OK"
	}
	send("QUIT")
	switch s.TLSMode {
	case "tls", "starttls":
		return "up", latency, "FTPS handshake OK"
	default:
		return "up", latency, "FTP greeting OK"
	}
}

func buildSSHClientConfig(s protoAuthSettings) (*ssh.ClientConfig, error) {
	user := s.Username
	if user == "" {
		user = "root"
	}
	auths := []ssh.AuthMethod{}
	if s.Password != "" {
		auths = append(auths, ssh.Password(s.Password))
	}
	if s.PrivateKey != "" {
		signer, err := ssh.ParsePrivateKey([]byte(s.PrivateKey))
		if err != nil {
			return nil, fmt.Errorf("invalid private key")
		}
		auths = append(auths, ssh.PublicKeys(signer))
	}
	if len(auths) == 0 {
		return nil, fmt.Errorf("credentials required (password or private key)")
	}
	return &ssh.ClientConfig{
		User:            user,
		Auth:            auths,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}, nil
}

func dialSSHClient(addr string, config *ssh.ClientConfig) (*ssh.Client, error) {
	conn, err := checkedDialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return nil, err
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, config)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return ssh.NewClient(c, chans, reqs), nil
}

func sshErrMessage(err error) string {
	msg := err.Error()
	if strings.Contains(msg, "unable to authenticate") || strings.Contains(msg, "no supported methods") {
		return "SSH authentication failed — credentials rejected"
	}
	return truncErr(err)
}

func checkSSHAuth(target string, settings json.RawMessage) (string, int, string) {
	start := time.Now()
	host, port, err := splitHostPortDefault(target, "22")
	if err != nil {
		return "down", 0, "invalid host:port"
	}
	config, err := buildSSHClientConfig(parseProtoAuth(settings))
	if err != nil {
		return "down", 0, err.Error()
	}
	client, err := dialSSHClient(net.JoinHostPort(host, port), config)
	latency := int(time.Since(start).Milliseconds())
	if err != nil {
		return "down", latency, sshErrMessage(err)
	}
	defer client.Close()
	return "up", latency, fmt.Sprintf("SSH login OK (%s)", strings.TrimSpace(string(client.ServerVersion())))
}

func checkSFTPAuth(target string, settings json.RawMessage) (string, int, string) {
	start := time.Now()
	host, port, err := splitHostPortDefault(target, "22")
	if err != nil {
		return "down", 0, "invalid host:port"
	}
	config, err := buildSSHClientConfig(parseProtoAuth(settings))
	if err != nil {
		return "down", 0, err.Error()
	}
	client, err := dialSSHClient(net.JoinHostPort(host, port), config)
	latency := int(time.Since(start).Milliseconds())
	if err != nil {
		return "down", latency, sshErrMessage(err)
	}
	defer client.Close()

	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		return "down", int(time.Since(start).Milliseconds()), "SFTP subsystem unavailable"
	}
	defer sftpClient.Close()
	if _, err := sftpClient.ReadDir("."); err != nil {
		return "down", int(time.Since(start).Milliseconds()), "SFTP directory listing failed"
	}
	return "up", int(time.Since(start).Milliseconds()), "SFTP login + listing OK"
}

func checkMailAuth(kind, target string, settings json.RawMessage, verifySSL bool) (string, int, string) {
	start := time.Now()
	host, _, err := net.SplitHostPort(target)
	if err != nil || host == "" {
		return "down", 0, "target must include port (e.g. host:993)"
	}
	s := parseProtoAuth(settings)

	tlsConfig := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12, InsecureSkipVerify: !verifySSL}
	var conn net.Conn
	if s.TLSMode == "tls" {
		raw, err := checkedDialTimeout("tcp", target, 10*time.Second)
		if err != nil {
			return "down", int(time.Since(start).Milliseconds()), truncErr(err)
		}
		tlsConn := tls.Client(raw, tlsConfig)
		if err := tlsConn.Handshake(); err != nil {
			raw.Close()
			return "down", int(time.Since(start).Milliseconds()), "TLS handshake failed: " + truncErr(err)
		}
		conn = tlsConn
	} else {
		conn, err = checkedDialTimeout("tcp", target, 10*time.Second)
		if err != nil {
			return "down", int(time.Since(start).Milliseconds()), truncErr(err)
		}
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	if kind == "smtp" {
		smtpClient, err := smtp.NewClient(conn, host)
		if err != nil {
			return "down", int(time.Since(start).Milliseconds()), "SMTP greeting failed"
		}
		defer smtpClient.Close()
		latency := int(time.Since(start).Milliseconds())
		if err := smtpClient.Hello("agent.uptriva.local"); err != nil {
			return "down", latency, "SMTP EHLO failed"
		}
		if s.TLSMode == "starttls" {
			if ok, _ := smtpClient.Extension("STARTTLS"); !ok {
				return "down", latency, "server does not support STARTTLS"
			}
			if err := smtpClient.StartTLS(tlsConfig); err != nil {
				return "down", int(time.Since(start).Milliseconds()), "STARTTLS failed: " + truncErr(err)
			}
		}
		if s.Username != "" {
			authed := false
			mechs := []smtp.Auth{
				smtp.PlainAuth("", s.Username, s.Password, host),
				smtp.CRAMMD5Auth(s.Username, s.Password),
			}
			if s.TLSMode == "none" {
				mechs = append(mechs, &loginAuthMech{username: s.Username, password: s.Password})
			}
			for _, mech := range mechs {
				if err := smtpClient.Auth(mech); err == nil {
					authed = true
					break
				}
			}
			if !authed {
				return "down", int(time.Since(start).Milliseconds()), "SMTP authentication failed — credentials rejected"
			}
			smtpClient.Quit()
			return "up", int(time.Since(start).Milliseconds()), "SMTP login OK"
		}
		smtpClient.Quit()
		switch s.TLSMode {
		case "tls":
			return "up", latency, "SMTP over TLS OK"
		case "starttls":
			return "up", latency, "SMTP STARTTLS OK"
		default:
			return "up", latency, "SMTP greeting OK"
		}
	}

	reader := bufio.NewReader(conn)
	greeting, err := reader.ReadString('\n')
	latency := int(time.Since(start).Milliseconds())
	if err != nil {
		return "down", latency, "no greeting received"
	}
	greeting = strings.TrimSpace(greeting)

	var greetOK bool
	var startTLSCmd, startTLSReply string
	switch kind {
	case "pop3":
		greetOK = strings.HasPrefix(greeting, "+OK")
		startTLSCmd, startTLSReply = "STLS", "+OK"
	case "imap":
		greetOK = strings.HasPrefix(greeting, "* OK") || strings.HasPrefix(greeting, "* PREAUTH")
		startTLSCmd, startTLSReply = "a001 STARTTLS", "a001 OK"
	}
	if !greetOK {
		return "down", latency, "invalid " + strings.ToUpper(kind) + " greeting: " + greeting
	}

	if s.TLSMode == "starttls" {
		if _, err := fmt.Fprintf(conn, "%s\r\n", startTLSCmd); err != nil {
			return "down", int(time.Since(start).Milliseconds()), "STARTTLS command failed"
		}
		reply, err := reader.ReadString('\n')
		if err != nil || !strings.HasPrefix(strings.TrimSpace(reply), startTLSReply) {
			return "down", int(time.Since(start).Milliseconds()), "server does not support STARTTLS"
		}
		conn = tls.Client(conn, tlsConfig)
		if err := conn.(*tls.Conn).Handshake(); err != nil {
			return "down", int(time.Since(start).Milliseconds()), "TLS handshake failed: " + truncErr(err)
		}
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		reader = bufio.NewReader(conn)
	}

	if s.Username != "" {
		scrub := strings.NewReplacer("\r", "", "\n", "")
		user, pass := scrub.Replace(s.Username), scrub.Replace(s.Password)
		switch kind {
		case "pop3":
			if _, err := fmt.Fprintf(conn, "USER %s\r\n", user); err != nil {
				return "down", int(time.Since(start).Milliseconds()), "POP3 USER failed"
			}
			reply, err := reader.ReadString('\n')
			if err != nil || !strings.HasPrefix(strings.TrimSpace(reply), "+OK") {
				return "down", int(time.Since(start).Milliseconds()), "POP3 USER rejected"
			}
			if _, err := fmt.Fprintf(conn, "PASS %s\r\n", pass); err != nil {
				return "down", int(time.Since(start).Milliseconds()), "POP3 PASS failed"
			}
			reply, err = reader.ReadString('\n')
			if err != nil || !strings.HasPrefix(strings.TrimSpace(reply), "+OK") {
				return "down", int(time.Since(start).Milliseconds()), "POP3 authentication failed — credentials rejected"
			}
		case "imap":
			if _, err := fmt.Fprintf(conn, "a002 LOGIN \"%s\" \"%s\"\r\n", user, pass); err != nil {
				return "down", int(time.Since(start).Milliseconds()), "IMAP LOGIN failed"
			}
			reply, err := reader.ReadString('\n')
			if err != nil || !strings.HasPrefix(strings.TrimSpace(reply), "a002 OK") {
				return "down", int(time.Since(start).Milliseconds()), "IMAP authentication failed — credentials rejected"
			}
		}
		return "up", int(time.Since(start).Milliseconds()), strings.ToUpper(kind) + " login OK"
	}

	proto := strings.ToUpper(kind)
	switch s.TLSMode {
	case "tls":
		return "up", latency, proto + " over TLS OK"
	case "starttls":
		return "up", latency, proto + " STARTTLS OK"
	default:
		return "up", latency, proto + " greeting OK"
	}
}
