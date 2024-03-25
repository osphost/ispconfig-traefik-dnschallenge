package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	ISPCUser     = os.Getenv("ISPC_User")
	ISPCPassword = os.Getenv("ISPC_Password")
	ISPCApi      = os.Getenv("ISPC_Api")
	ISPCLogPath  = os.Getenv("ISPC_Log_Path")
)

type loginResponse struct {
	Code     string `json:"code"`
	Response string `json:"response"`
}

func login(logger *zap.Logger) (sessionId string, err error) {
	// Perform login
	logger.Info("Getting Session ID")
	loginData := map[string]interface{}{
		"username":     ISPCUser,
		"password":     ISPCPassword,
		"client_login": false,
	}
	jsonData, err := json.Marshal(loginData)
	if err != nil {
		return "", err
	}

	resp, err := http.Post(ISPCApi+"?login", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var loginResp loginResponse
	err = json.NewDecoder(resp.Body).Decode(&loginResp)
	if err != nil {
		return "", err
	}

	if loginResp.Code != "ok" {
		return "", fmt.Errorf("failed to retrieve session ID")
	}

	sessionID := strings.Trim(loginResp.Response, "\"")
	logger.Info("Retrieved Session ID")
	logger.Debug("Session ID: " + sessionID)

	return sessionID, nil
}

type zoneApiResponse struct {
	Code     string             `json:"code"`
	Message  string             `json:"message"`
	Response []zoneInfoResponse `json:"response"`
}

type zoneInfoResponse struct {
	ID        string `json:"id"`
	ServerID  string `json:"server_id"`
	SysUserID string `json:"sys_userid"`
	ClientId  int
}

func getZoneInfo(logger *zap.Logger, sessionId string, domain string) (*zoneInfoResponse, error) {
	// example domain: osphost.net.
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid domain format")
	}
	sld := parts[len(parts)-3]
	tld := parts[len(parts)-2]
	domainWithTLD := sld + "." + tld + "."

	var serverID, zoneID, sysUserID string

	data := map[string]interface{}{
		"session_id": sessionId,
		"primary_id": map[string]string{"origin": domainWithTLD},
	}
	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	logger.Debug("POSTing", zap.Any("body", data), zap.String("endpoint", "?dns_zone_get"))

	resp, err := http.Post(ISPCApi+"?dns_zone_get", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Check HTTP response status code
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to retrieve zone information: %s", resp.Status)
	}

	// Parse the response JSON
	var zoneInfoResp zoneApiResponse
	if err := json.NewDecoder(resp.Body).Decode(&zoneInfoResp); err != nil {
		return nil, err
	}

	// Check if zone information is found
	if zoneInfoResp.Response[0].ID != "" {
		// store retrieved information
		serverID = zoneInfoResp.Response[0].ServerID
		zoneID = zoneInfoResp.Response[0].ID
		sysUserID = zoneInfoResp.Response[0].SysUserID
	}

	// Retrieve client ID
	data = map[string]interface{}{
		"session_id": sessionId,
		"sys_userid": sysUserID,
	}
	jsonData, err = json.Marshal(data)
	if err != nil {
		return nil, err
	}

	resp, err = http.Post(ISPCApi+"?client_get_id", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Check HTTP response status code
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to retrieve client ID: %s", resp.Status)
	}

	var clientIDResponse struct {
		Response int `json:"response"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&clientIDResponse); err != nil {
		return nil, err
	}

	return &zoneInfoResponse{
		ServerID:  serverID,
		ID:        zoneID,
		SysUserID: sysUserID,
		ClientId:  clientIDResponse.Response,
	}, nil
}

func addTxt(logger *zap.Logger, sessionID string, clientID int, serverID, zone, fulldomain, txtValue string) (recordId string, err error) {
	curSerial := fmt.Sprintf("%d", time.Now().Unix())
	curStamp := time.Now().Format("2006-01-02 15:04:05")

	// Prepare parameters
	params := map[string]interface{}{
		"server_id": serverID,
		"zone":      zone,
		"name":      fulldomain,
		"type":      "txt",
		"data":      txtValue,
		"aux":       "0",
		"ttl":       "3600",
		"active":    "y",
		"stamp":     curStamp,
		"serial":    curSerial,
	}

	data := map[string]interface{}{
		"session_id":    sessionID,
		"client_id":     clientID,
		"params":        params,
		"update_serial": true,
	}

	logger.Debug("POSTing", zap.Any("data", data), zap.String("endpoint", "?dns_txt_add"))

	jsonData, err := json.Marshal(data)
	if err != nil {
		return "", err
	}

	resp, err := http.Post(ISPCApi+"?dns_txt_add", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP request failed with status code: %d", resp.StatusCode)
	}

	var response map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return "", err
	}

	recordID, ok := response["response"].(string)
	if !ok {
		return "", fmt.Errorf("failed to extract record ID from response")
	}

	return recordID, nil
}

func removeTxt(sessionID, fulldomain string) error {
	// Prepare data for POST request to retrieve TXT record
	curData := map[string]interface{}{
		"session_id": sessionID,
		"primary_id": map[string]string{
			"name": fulldomain,
			"type": "TXT",
		},
	}
	jsonData, err := json.Marshal(curData)
	if err != nil {
		return err
	}

	// Perform HTTP POST request to retrieve TXT record
	resp, err := http.Post(ISPCApi+"?dns_txt_get", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Check response status code
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP request failed with status code: %d", resp.StatusCode)
	}

	// Decode response JSON
	var response map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return err
	}

	// Check if record exists
	if code, ok := response["code"].(string); ok && code == "ok" {
		// Extract record ID
		records, ok := response["response"].([]interface{})
		if !ok || len(records) == 0 {
			return errors.New("No TXT record found")
		}
		record, ok := records[0].(map[string]interface{})
		if !ok {
			return errors.New("Invalid record format")
		}
		recordID, ok := record["id"].(string)
		if !ok {
			return errors.New("Failed to extract record ID")
		}

		// Prepare data for POST request to delete TXT record
		curData = map[string]interface{}{
			"session_id":    sessionID,
			"primary_id":    recordID,
			"update_serial": true,
		}
		jsonData, err = json.Marshal(curData)
		if err != nil {
			return err
		}

		// Perform HTTP POST request to delete TXT record
		resp, err = http.Post(ISPCApi+"?dns_txt_delete", "application/json", bytes.NewBuffer(jsonData))
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		// Check response status code
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("HTTP request failed with status code: %d", resp.StatusCode)
		}

		// Decode response JSON
		if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
			return err
		}

		// Check if record deletion was successful
		if code, ok := response["code"].(string); ok && code == "ok" {
			return nil
		}
		return errors.New("Failed to delete TXT record")
	}
	return errors.New("Failed to retrieve TXT record")
}

func createLogger() *zap.Logger {
	encoderCfg := zap.NewProductionEncoderConfig()
	encoderCfg.TimeKey = "timestamp"
	encoderCfg.EncodeTime = zapcore.ISO8601TimeEncoder

	dirPath := ISPCLogPath + "/"

	// Create the directory and its parent directories if they don't exist
	err := os.MkdirAll(dirPath, 0755)
	if err != nil {
		fmt.Println("Error creating directory:", err)
		os.Exit(1)
	}

	config := zap.Config{
		Level:             zap.NewAtomicLevelAt(zap.InfoLevel),
		Development:       false,
		DisableCaller:     false,
		DisableStacktrace: false,
		Sampling:          nil,
		Encoding:          "json",
		EncoderConfig:     encoderCfg,
		OutputPaths: []string{
			"stderr",
			dirPath + "/" + time.Now().Format("2006-01-02") + ".log",
		},
		ErrorOutputPaths: []string{
			"stderr",
		},
		InitialFields: map[string]interface{}{
			"pid": os.Getpid(),
		},
	}

	return zap.Must(config.Build())
}

func main() {
	logger := createLogger()

	args := os.Args
	if len(args) < 3 {
		logger.Fatal("Invalid number of arguments", zap.Int("minimum", 2), zap.Int("provided", len(args)))
	}

	action := args[1]
	domain := args[2]
	if action == "present" && len(args) < 4 {
		logger.Fatal("Not enough arguments for 'present' action", zap.Int("minimum", 3), zap.Int("provided", len(args)))
	}

	if domain == "" {
		logger.Fatal("Empty domain")
	}

	// login
	sessionId, err := login(logger)

	if err != nil {
		logger.Fatal("Failed to login", zap.Error(err))
	}

	zoneInfo, err := getZoneInfo(logger, sessionId, domain)

	if err != nil {
		logger.Fatal("Failed to get zone info", zap.Error(err))
	}

	logger.Debug("zoneinfo", zap.Any("data", zoneInfo))

	switch action {
	case "present":
		value := args[3]

		recordId, err := addTxt(logger, sessionId, zoneInfo.ClientId, zoneInfo.ServerID, zoneInfo.ID, domain, value)

		if err != nil {
			logger.Fatal("Failed to add record", zap.Error(err))
		}

		logger.Info("Created TXT record", zap.String("id", recordId))
		return
	case "cleanup":
		err = removeTxt(sessionId, domain)

		if err != nil {
			logger.Fatal("Failed to remove record", zap.Error(err))
		}
		logger.Info("Removed TXT record")
	}
}
