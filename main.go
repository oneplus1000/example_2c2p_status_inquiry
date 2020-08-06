package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"

	"github.com/oneplus1000/pkcs7"
)

const paymentActionURL = "https://demo2.2c2p.com/2C2PFrontend/PaymentActionV2/PaymentAction.aspx"
const fileInputPath = "./input/input.txt"
const fileCrtPath = "./keys/demo2.crt"
const filePemPath = "./keys/demo2.pem"
const password = "2c2p"

func main() {

	//อ่าน input file
	input, err := readInputText(fileInputPath)
	if err != nil {
		log.Panicf("%+v", err)
	}
	//อ่านไฟล์ CRT
	certs, err := readCRT(fileCrtPath)
	if err != nil {
		log.Panicf("%+v", err)
	}

	//request ไปยัง 2c2p
	resp, err := call2C2PPaymentAction(certs, input)
	if err != nil {
		log.Panicf("%+v", err)
	}

	//load private key
	privateKey, err := loadPrivateKey(filePemPath, password)
	if err != nil {
		log.Panicf("%+v", err)
	}

	//process response
	result, err := processResponse(certs, privateKey, resp)
	if err != nil {
		log.Panicf("%+v", err)
	}

	fmt.Printf("%s\n", result)
}

func readCRT(path string) ([]*x509.Certificate, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("ioutil.ReadFile(%s) fail %w", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("pem.Decode(data) fail block is nil")
	}
	certs, err := x509.ParseCertificates(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("x509.ParseCertificate fail : %w", err)
	}
	return certs, nil
}

func readInputText(path string) ([]byte, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("ioutil.ReadFile fail %s %w", path, err)
	}
	return data, nil
}

func call2C2PPaymentAction(certs []*x509.Certificate, input []byte) ([]byte, error) {
	encrypted, err := pkcs7.Encrypt(input, certs)
	if err != nil {
		return nil, fmt.Errorf("pkcs7.Encrypt(input, certs) fail %w", err)
	}
	encryptedBase64 := base64.StdEncoding.EncodeToString(encrypted)

	httpResp, err := http.PostForm(paymentActionURL, url.Values{"paymentRequest": {encryptedBase64}})
	if err != nil {
		return nil, fmt.Errorf("http.PostForm(%s,...) fail %w", paymentActionURL, err)
	}
	defer httpResp.Body.Close()

	out, err := ioutil.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("ioutil.ReadAll(httpResp.Body) fail %w", err)
	}
	return out, nil
}

func loadPrivateKey(path string, password string) (*rsa.PrivateKey, error) {

	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("ioutil.ReadFile(%s) fail %w", path, err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	byteout, err := x509.DecryptPEMBlock(block, []byte(password))
	if err != nil {
		return nil, fmt.Errorf("x509.DecryptPEMBlock(...) fail %w", err)
	}

	priv, err := x509.ParsePKCS1PrivateKey(byteout)
	if err != nil {
		return nil, fmt.Errorf("x509.ParsePKCS1PrivateKey(...) fail %w", err)
	}

	return priv, nil
}

func processResponse(certs []*x509.Certificate, privateKey *rsa.PrivateKey, resp []byte) ([]byte, error) {

	if len(certs) <= 0 {
		return nil, fmt.Errorf(" len(certs) <= 0")
	}

	decoded, err := base64.StdEncoding.DecodeString(string(resp))
	if err != nil {
		return nil, fmt.Errorf("base64.StdEncoding.DecodeString(...) fail %w", err)
	}

	p7, err := pkcs7.Parse(decoded)
	if err != nil {
		return nil, fmt.Errorf("pkcs7.Parse fail: %w", err)
	}

	out, err := p7.Decrypt(certs[0], privateKey)
	if err != nil {
		return nil, fmt.Errorf("p7.Decrypt(...) fail: %w", err)
	}

	return out, nil
}
