package session

import "fmt"

type Session struct {
	TlsClient *TLSClient
	SSHClient *SSHClient
}

func NewTLSSessionClient(ip string) (*Session, error) {
	sessionClient, err := NewTLSClientSession(ip)
	if err != nil {
		return nil, fmt.Errorf("Error creating session:", err)
	}
	return &Session{
		TlsClient: sessionClient,
	}, nil
}

func NewSSHSessionClient(ip, user, pass string) (*Session, error) {
	sessionClient, err := NewSSHClientSession(ip, user, pass)
	if err != nil {
		return nil, fmt.Errorf("Error creating session:", err)
	}
	return &Session{
		SSHClient: sessionClient,
	}, nil
}
