package core

import (
	"fmt"
	"sync"
	"time"

	"github.com/TheManticoreProject/Manticore/network/dns"
	"github.com/TheManticoreProject/Manticore/network/ldap"
	smbclient "github.com/TheManticoreProject/Manticore/network/smb/client"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
	"manticore-FindGPPPasswords/logger"

	"manticore-FindGPPPasswords/config"
	"manticore-FindGPPPasswords/gpp"
)

type gppResultCollector struct {
	mu      sync.Mutex
	results *gpp.GroupPolicyPreferencePasswordsFound
}

func (c *gppResultCollector) merge(results *gpp.GroupPolicyPreferencePasswordsFound) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for path, entries := range results.Entries {
		c.results.Entries[path] = append(c.results.Entries[path], entries...)
	}
}

// SMBListFilesRecursivelyAndCallback lists files recursively in a given directory on the client's current tree and executes a callback function for each file found.
//
// Parameters:
// - client: an active SMB client whose current tree is the share to walk.
// - share: the name of the SMB share, passed through to the callback.
// - dir: the share-relative directory to start listing files from ("" is the share root).
// - callback: a function to be called for each file found. The callback function takes the SMB client, the share name, and the file path as arguments and returns an error.
//
// Returns:
// - err: an error if any occurs during the process.
//
// The function performs the following steps:
// 1. Lists files in the specified directory.
// 2. Recursively explores subdirectories and applies the callback function to each file found.
//
// If listing a directory fails (e.g. access is denied), it skips that directory and continues processing siblings.
func SMBListFilesRecursivelyAndCallback(client *smbclient.Client, share string, dir string, callback func(*smbclient.Client, string, string) error) (err error) {
	DEBUG := false

	// List files
	if DEBUG {
		logger.Debug(fmt.Sprintf("Listing files of '%s'", dir))
	}
	entries, err := client.ListDirectory(dir, "*")
	if err != nil {
		if DEBUG {
			fmt.Printf("[SMBListFilesRecursivelyAndCallback] Could not list files in directory (%s): %s\n", dir, err)
		}
		return nil
	}

	// Explore further and callback
	for _, entry := range entries {
		// Skip the self and parent pseudo-entries returned by the server.
		if entry.Name == "." || entry.Name == ".." {
			continue
		}

		fullPath := entry.Name
		if dir != "" {
			fullPath = dir + "\\" + entry.Name
		}

		if entry.IsDir() {
			if DEBUG {
				logger.Debug(fmt.Sprintf("Found Directory '%s'", fullPath))
			}
			err = SMBListFilesRecursivelyAndCallback(client, share, fullPath, callback)
			if err != nil {
				if DEBUG {
					fmt.Printf("[SMBListFilesRecursivelyAndCallback] Failed to list files in directory %s with error: %s\n", fullPath, err)
				}
				return fmt.Errorf("error walking %s: %w", fullPath, err)
			}
		} else {
			if DEBUG {
				logger.Debug(fmt.Sprintf("Found file '%s'", fullPath))
			}
			if err := callback(client, share, fullPath); err != nil {
				return fmt.Errorf("error processing %s: %w", fullPath, err)
			}
		}
	}

	return nil
}

// FindCPasswords searches for Group Policy Preference Passwords (GPP Passwords) in the SYSVOL share of a given domain controller.
// It performs the following steps:
// 1. Resolves the DNS hostname to an IP address.
// 2. Establishes an SMB connection to the target IP address.
// 3. Recursively searches for XML files in the SYSVOL share.
// 4. Processes the found XML files to extract GPP Passwords.
//
// Parameters:
// - dnsHostname: A slice of strings containing the DNS hostnames of the domain controller.
// - config: The configuration settings for the connection and search.
// - testResults: A pointer to the structure that holds the found Group Policy Preference Passwords.
//
// Returns:
// - An error if any step of the process fails, otherwise nil.
func FindCPasswords(dnsHostname []string, config config.Config, testResults *gpp.GroupPolicyPreferencePasswordsFound) error {
	targetIp := dns.DNSLookup(dnsHostname[0], config.DnsNameServer)

	if len(targetIp) == 0 {
		return fmt.Errorf("could not resolve host %s", dnsHostname[0])
	}

	// Build the credentials used to authenticate the SMB session. When NT/LM
	// hashes are supplied (-H), the Manticore client authenticates with the NT
	// hash (pass-the-hash) instead of the password.
	creds, err := credentials.NewCredentials(
		config.Credentials.Domain,
		config.Credentials.Username,
		config.Credentials.Password,
		config.Credentials.Hashes,
	)
	if err != nil {
		return err
	}

	// Dial the target with the generic SMB client, letting it negotiate the
	// highest dialect the server supports.
	client, err := smbclient.Dial(targetIp[0], 445, smbclient.Options{
		DialTimeout: time.Millisecond * time.Duration(5000),
	})
	if err != nil {
		return err
	}
	defer client.Disconnect()

	if err := client.Login(creds); err != nil {
		return err
	}
	defer client.Logoff()

	// Connect to the SYSVOL share before walking it.
	if err := client.TreeConnect("SYSVOL"); err != nil {
		return err
	}
	defer client.TreeDisconnect()

	// Find all XML files in the root directory
	return SMBListFilesRecursivelyAndCallback(client, "SYSVOL", "", testResults.CallbackFunctionCPassword)
}

// RunWorkers starts a specified number of worker goroutines to process tasks from the channel.
// It takes a slice of LDAP entries, a configuration, and a pointer to the found Group Policy Preference Passwords.
func RunWorkers(maxThreads int, domainControllersResults []*ldap.Entry, config config.Config, gpppfound *gpp.GroupPolicyPreferencePasswordsFound) {
	sem := make(chan struct{}, config.Threads)
	collector := gppResultCollector{results: gpppfound}

	maxLenOfAdvancementString := len(fmt.Sprintf("%d", len(domainControllersResults)))
	advancementFormatString := fmt.Sprintf("(%%0%dd/%%0%dd)", maxLenOfAdvancementString, maxLenOfAdvancementString)

	var wg sync.WaitGroup

	for k, entry := range domainControllersResults {
		wg.Add(1)

		// acquire semaphore
		sem <- struct{}{}

		// start long running go routine
		go func(id int, entry *ldap.Entry) {
			defer wg.Done()
			workerResults := gpp.GroupPolicyPreferencePasswordsFound{
				Entries: make(map[string][]*gpp.CPasswordEntry),
			}

			advancementString := fmt.Sprintf(advancementFormatString, k+1, len(domainControllersResults))

			logger.Info(fmt.Sprintf("%s Searching for GPPPasswords in '\\\\%s\\SYSVOL\\' ... ", advancementString, entry.GetEqualFoldAttributeValues("dnsHostname")[0]))

			err := FindCPasswords(
				entry.GetEqualFoldAttributeValues("dnsHostname"),
				config,
				&workerResults,
			)
			collector.merge(&workerResults)

			if err != nil {
				logger.Warn(fmt.Sprintf("%s Error: %s", advancementString, err))
			} else {
				logger.Info(fmt.Sprintf("%s Search in '\\\\%s\\SYSVOL\\' has finished successfully. ", advancementString, entry.GetEqualFoldAttributeValues("dnsHostname")[0]))
			}

			// release semaphore
			<-sem
		}(k, entry)
	}

	wg.Wait()
}
