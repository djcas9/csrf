// Package provides methods for generating and validating secure XSRF (CSRF) tokens.
//	Copyright (C) 2013  Janis N Vizulis
// Copyright 2012 The Gorilla Authors. All rights reserved.
// license that can be found in the LICENSE file.


package csrf

import (
  "bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/gob"
	"fmt"
	"os"
	"time"
)

//Default values 
var (
	now     = time.Now()
	Timeout = 24 * time.Hour
	Key     []byte
)

type Token struct {
	ActionID  string //I.e POST /form
	Id        string // User session ID  
	IssueTime int64  // Time token issued
	Hmac      string //sha1 hmac
}

func Rand16() []byte {
	f, _ := os.Open("/dev/urandom")
	defer f.Close()
	b := make([]byte, 16)
	f.Read(b)
	return b
}

func newToken(actionID string, id string) string {
	x := new(Token)
	x.ActionID = actionID
	x.Id = id
	x.IssueTime = time.Time.UnixNano(now)
	x.Hmac = x.tokenHmac()
	return x.encode()
}

func (x *Token) tokenHmac() string {
	h := hmac.New(sha1.New, Key)
	fmt.Fprintf(h, "%s:%s:%d", x.ActionID, x.Id, x.IssueTime)
	tokBuf := bytes.NewBuffer(make([]byte, 0, sha1.Size))
	fmt.Fprintf(tokBuf, "%s", h.Sum(nil))
	return base64.URLEncoding.EncodeToString(tokBuf.Bytes())
}

func (x *Token) encode() string {
	buf := new(bytes.Buffer)
	encoder := gob.NewEncoder(buf)
	encoder.Encode(x)
	ebuf := base64.URLEncoding.EncodeToString(buf.Bytes())
	return ebuf
}

func (x *Token) decode(s string) error {
	bd, err := base64.URLEncoding.DecodeString(s)
	if err != nil {
		return err
	}

	buf := bytes.NewBuffer(bd)
	decoder := gob.NewDecoder(buf)
	err = decoder.Decode(&x)
	if err != nil {
		return err
	}

	return nil
}

func Valid(s string, actionID string, id string) bool {
	x := new(Token)
	err := x.decode(s)
	if err != nil {
		return false
	}
	if actionID != x.ActionID {
		return false
	}
	if id != x.Id {
		return false
	}
	issueTime := time.Unix(0, x.IssueTime)
	if now.Sub(issueTime) >= Timeout {
		return false
	}
	// Check that the token is not from the future. Allow 1 minute grace period 
	if issueTime.After(now.Add(1 * time.Minute)) {
		return false
	}
	return x.Hmac == x.tokenHmac()
}
