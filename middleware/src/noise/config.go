package noisemanager

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/digitalbitbox/bitbox-wallet-app/util/config"
	"github.com/flynn/noise"
)

const configFilename = "base.json"
const configDir = ".base"

type noiseKeypair struct {
	Private []byte `json:"private"`
	Public  []byte `json:"public"`
}

type configuration struct {
	MiddlewareNoiseStaticKeypair *noiseKeypair `json:"appNoiseStaticKeypair"`
	ClientNoiseStaticPubkeys     [][]byte      `json:"deviceNoiseStaticPubkeys"`
}

func (noiseConfig *NoiseConfig) readConfig() *configuration {
	configFile := config.NewFile(configDir, configFilename)
	if !configFile.Exists() {
		return &configuration{}
	}
	var conf configuration
	if err := configFile.ReadJSON(&conf); err != nil {
		return &configuration{}
	}
	return &conf
}

func (noiseConfig *NoiseConfig) storeConfig(conf *configuration) error {
	configFile := config.NewFile(configDir, configFilename)
	return configFile.WriteJSON(conf)
}

func (noiseConfig *NoiseConfig) containsClientStaticPubkey(pubkey []byte) bool {
	for _, configPubkey := range noiseConfig.readConfig().ClientNoiseStaticPubkeys {
		if bytes.Equal(configPubkey, pubkey) {
			return true
		}
	}
	return false
}

func (noiseConfig *NoiseConfig) addClientStaticPubkey(pubkey []byte) error {
	if noiseConfig.containsClientStaticPubkey(pubkey) {
		// Don't add again if already present.
		return nil
	}

	config := noiseConfig.readConfig()
	config.ClientNoiseStaticPubkeys = append(config.ClientNoiseStaticPubkeys, pubkey)
	return noiseConfig.storeConfig(config)
}

func (noiseConfig *NoiseConfig) getMiddlewareNoiseStaticKeypair() *noise.DHKey {
	key := noiseConfig.readConfig().MiddlewareNoiseStaticKeypair
	if key == nil {
		return nil
	}
	return &noise.DHKey{
		Private: key.Private,
		Public:  key.Public,
	}
}

func (noiseConfig *NoiseConfig) setMiddlewareNoiseStaticKeypair(key *noise.DHKey) error {
	config := noiseConfig.readConfig()
	config.MiddlewareNoiseStaticKeypair = &noiseKeypair{
		Private: key.Private,
		Public:  key.Public,
	}
	return noiseConfig.storeConfig(config)
}

// File models a config file in the application's directory.
// Callers can use MiddlewareDir function to obtain the default app config dir.
type File struct {
	dir  string
	name string
}

// NewFile creates a new config file with the given name in a directory dir.
func NewFile(dir, name string) *File {
	return &File{dir: dir, name: name}
}

// Path returns the absolute path to the config file.
func (file *File) Path() string {
	return filepath.Join(file.dir, file.name)
}

// Exists checks whether the file exists with suitable permissions as a file and not as a directory.
func (file *File) Exists() bool {
	info, err := os.Stat(file.Path())
	return err == nil && !info.IsDir()
}

// Remove removes the file.
func (file *File) Remove() error {
	return os.Remove(file.Path())
}

// read reads the config file and returns its data (or an error if the config file does not exist).
func (file *File) read() ([]byte, error) {
	return ioutil.ReadFile(file.Path())
}

// ReadJSON reads the config file as JSON to the given object. Make sure the config file exists!
func (file *File) ReadJSON(object interface{}) error {
	data, err := file.read()
	if err != nil {
		return err
	}
	return json.Unmarshal(data, object)
}

// write writes the given data to the config file (and creates parent directories if necessary).
func (file *File) write(data []byte) error {
	if err := os.MkdirAll(file.dir, 0700); err != nil {
		return err
	}
	return ioutil.WriteFile(file.Path(), data, 0600)
}

// WriteJSON writes the given object as JSON to the config file.
func (file *File) WriteJSON(object interface{}) error {
	data, err := json.Marshal(object)
	if err != nil {
		return err
	}
	return file.write(data)
}
