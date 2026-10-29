package connect

import (
	"encoding/json"
	"errors"
	"regexp"
)

// FirefoxID is the extension's id in Firefox.
const FirefoxID = "passzit@maxzit.com"

var chromeIDRE = regexp.MustCompile(`^[a-p]{32}$`)

// ValidChromeID checks a Chromium extension id (32 letters a–p).
func ValidChromeID(id string) bool { return chromeIDRE.MatchString(id) }

// ChromeManifest is the native-messaging manifest for Chromium browsers.
func ChromeManifest(exe string, ids []string) ([]byte, error) {
	if len(ids) == 0 {
		return nil, errors.New("give the id of the PassZit extension (shown in its settings)")
	}
	origins := make([]string, 0, len(ids))
	for _, id := range ids {
		if !ValidChromeID(id) {
			return nil, errors.New("not an extension id: " + id)
		}
		origins = append(origins, "chrome-extension://"+id+"/")
	}
	return json.MarshalIndent(map[string]any{"name": HostName, "description": "PassZit helper: opens RDP, SSH and WinBox connections",
		"path": exe, "type": "stdio", "allowed_origins": origins}, "", "  ")
}

// FirefoxManifest is the native-messaging manifest for Firefox.
func FirefoxManifest(exe string) ([]byte, error) {
	return json.MarshalIndent(map[string]any{"name": HostName, "description": "PassZit helper: opens RDP, SSH and WinBox connections",
		"path": exe, "type": "stdio", "allowed_extensions": []string{FirefoxID}}, "", "  ")
}
