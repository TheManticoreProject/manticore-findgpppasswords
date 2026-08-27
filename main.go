package main

import (
	"fmt"
	"os"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/TheManticoreProject/Manticore/network/ldap"
	"github.com/TheManticoreProject/Manticore/network/ldap/ldap_attributes"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
	"github.com/p0dalirius/goopts/parser"
	"manticore-FindGPPPasswords/logger"

	"manticore-FindGPPPasswords/config"
	"manticore-FindGPPPasswords/core"
	"manticore-FindGPPPasswords/exporter"
	"manticore-FindGPPPasswords/gpp"
)

var (
	// Configuration
	useLdaps        bool
	quiet           bool
	debug           bool
	nocolors        bool
	numberOfThreads int

	// Network
	dnsNameServer    string
	domainController string
	ldapPort         int

	// Authentication
	authDomain   string
	authUsername string
	authPassword string
	authHashes   string

	// Additional Options
	outputExcel     string
	testCredentials bool
)

func defaultLDAPPort(port int, useLdaps bool) int {
	if port != 0 {
		return port
	}
	if useLdaps {
		return 636
	}
	return 389
}

func credentialTestMessage(success bool, domain string, username string, password string, noColors bool) string {
	identity := username
	if domain != "" {
		identity = fmt.Sprintf("%s\\%s", domain, username)
	}
	message := fmt.Sprintf("   [!] %s : %s", identity, password)
	color := "\x1b[91m"
	if success {
		message = fmt.Sprintf("   [+] %s : %s", identity, password)
		color = "\x1b[1;92m"
	}
	if noColors {
		return message
	}
	return color + message + "\x1b[0m"
}

func parseArgs() {
	quietRequested := slices.Contains(os.Args[1:], "-q") || slices.Contains(os.Args[1:], "--quiet")
	banner := "FindGPPPasswords - by Remi GASCOU (Podalirius) @ TheManticoreProject - v1.2"
	if quietRequested {
		banner = ""
	}
	ap := parser.ArgumentsParser{Banner: banner}

	ap.NewBoolArgument(&quiet, "-q", "--quiet", false, "Show no information at all.")
	ap.NewBoolArgument(&debug, "", "--debug", false, "Debug mode.")
	ap.NewBoolArgument(&nocolors, "-nc", "--no-colors", false, "No colors mode.")

	group_ldapSettings, err := ap.NewArgumentGroup("LDAP Connection Settings")
	if err != nil {
		fmt.Printf("[error] Error creating ArgumentGroup: %s\n", err)
	} else {
		group_ldapSettings.NewStringArgument(&domainController, "-dc", "--dc-ip", "", true, "IP Address of the domain controller or KDC (Key Distribution Center) for Kerberos. If omitted, it will use the domain part (FQDN) specified in the identity parameter.")
		group_ldapSettings.NewTcpPortArgument(&ldapPort, "-lp", "--ldap-port", 0, false, "Port number to connect to LDAP server. Defaults to 389 for LDAP and 636 for LDAPS.")
		group_ldapSettings.NewBoolArgument(&useLdaps, "-L", "--use-ldaps", false, "Use LDAPS instead of LDAP.")
	}

	group_dnsSettings, err := ap.NewArgumentGroup("DNS Settings")
	if err != nil {
		fmt.Printf("[error] Error creating ArgumentGroup: %s\n", err)
	} else {
		group_dnsSettings.NewStringArgument(&dnsNameServer, "-ns", "--nameserver", "", false, "IP Address of the DNS server to use in the queries. If omitted, it will use the IP of the domain controller specified in the -dc parameter.")
	}

	group_auth, err := ap.NewArgumentGroup("Authentication")
	if err != nil {
		fmt.Printf("[error] Error creating ArgumentGroup: %s\n", err)
	} else {
		group_auth.NewStringArgument(&authDomain, "-d", "--domain", "", true, "Active Directory domain to authenticate to.")
		group_auth.NewStringArgument(&authUsername, "-u", "--username", "", true, "User to authenticate as.")
		group_auth.NewStringArgument(&authPassword, "-p", "--password", "", false, "Password to authenticate with.")
		group_auth.NewStringArgument(&authHashes, "-H", "--hashes", "", false, "NT/LM hashes, format is LMhash:NThash.")
		group_auth.NewIntArgument(&numberOfThreads, "-T", "--threads", 0, false, "Number of threads to use.")
	}

	group_extraOptions, err := ap.NewArgumentGroup("Additional Options")
	if err != nil {
		fmt.Printf("[error] Error creating ArgumentGroup: %s\n", err)
	} else {
		group_extraOptions.NewStringArgument(&outputExcel, "-x", "--export-xlsx", "", false, "Path to output Excel file.")
		group_extraOptions.NewBoolArgument(&testCredentials, "-tc", "--test-credentials", false, "Test credentials.")
	}

	ap.Parse()
	logger.SetQuiet(quiet)

	// Select the protocol-specific default unless the user explicitly supplied a port.
	ldapPort = defaultLDAPPort(ldapPort, useLdaps)

	// Validate required arguments
	if domainController == "" {
		if !quiet {
			fmt.Println("[!] Option -dc <fqdn> is required.")
			ap.Usage()
		}
		os.Exit(1)
	}
}

func TestCredentials(gpppfound gpp.GroupPolicyPreferencePasswordsFound, config config.Config, noColors bool) {
	testedUsernames := []string{}

	logger.Info("")
	logger.Info("Testing credentials:")

	for pathToFile := range gpppfound.Entries {
		for _, entry := range gpppfound.Entries[pathToFile] {
			username := ""
			domain := ""

			// Case of scheduled task
			if len(username) == 0 && len(entry.RunAs) != 0 && len(entry.UserName) == 0 {
				if strings.Contains(entry.RunAs, "\\") {
					parts := strings.SplitN(entry.RunAs, "\\", 2)
					domain = parts[0]
					username = parts[1]
				} else {
					username = entry.RunAs
				}
			}

			// Case of local account
			if len(username) == 0 && (len(entry.UserName) != 0 || len(entry.NewName) != 0) {
				if len(entry.NewName) != 0 {
					username = entry.NewName
				} else {
					username = entry.UserName
				}
			}

			if len(username) != 0 {
				if !slices.Contains(testedUsernames, username) {
					creds, err := credentials.NewCredentials(domain, username, entry.Password, "")
					var ldapSession *ldap.Session
					if err == nil {
						ldapSession, err = ldap.NewSession(
							domainController,
							ldapPort,
							creds,
							config.UseLdaps,
							false,
						)
					}
					if err == nil {
						_, err = ldapSession.Connect()
					}

					if err == nil {
						logger.Info(credentialTestMessage(true, domain, username, entry.Password, noColors))
					} else {
						logger.Info(credentialTestMessage(false, domain, username, entry.Password, noColors))
					}
					if ldapSession != nil {
						ldapSession.Close()
					}
					testedUsernames = append(testedUsernames, username)
				} else {
					message := fmt.Sprintf("   [*] Skipping test of %s : %s to avoid potential lockout.", username, entry.Password)
					if !noColors {
						message = "\x1b[93m" + message + "\x1b[0m"
					}
					logger.Info(message)
				}
			}
		}
	}

	logger.Info("Finished testing credentials.")
	logger.Info("")
}

func main() {
	parseArgs()

	startTime := time.Now()

	authDomain = strings.ToUpper(authDomain)

	config := config.Config{}
	config.Credentials.Username = authUsername
	config.Credentials.Domain = authDomain
	config.Credentials.Password = authPassword
	config.Credentials.Hashes = authHashes
	config.Credentials.DCIP = domainController
	if len(dnsNameServer) == 0 {
		config.DnsNameServer = domainController
	} else {
		config.DnsNameServer = dnsNameServer
	}
	if numberOfThreads != 0 {
		config.Threads = numberOfThreads
	} else {
		config.Threads = runtime.NumCPU()
	}
	config.UseLdaps = useLdaps
	config.Debug = debug

	outputDir, err := os.Getwd()
	if err != nil {
		logger.Warn(fmt.Sprintf("Error getting current working directory: %s", err))
		config.OutputDir = "./"
	} else {
		config.OutputDir = outputDir
	}

	if debug {
		if !useLdaps {
			logger.Debug(fmt.Sprintf("Connecting to remote ldap://%s:%d ...", domainController, ldapPort))
		} else {
			logger.Debug(fmt.Sprintf("Connecting to remote ldaps://%s:%d ...", domainController, ldapPort))
		}
	}
	creds, err := credentials.NewCredentials(
		config.Credentials.Domain,
		config.Credentials.Username,
		config.Credentials.Password,
		config.Credentials.Hashes,
	)
	var ldapSession *ldap.Session
	if err == nil {
		ldapSession, err = ldap.NewSession(
			domainController,
			ldapPort,
			creds,
			config.UseLdaps,
			false,
		)
	}
	if err == nil {
		_, err = ldapSession.Connect()
	}

	if err == nil {
		defer ldapSession.Close()
		logger.Info(fmt.Sprintf("Connected as '%s\\%s'", authDomain, authUsername))

		domainControllersQuery := "(&"
		// We look for computer accounts
		domainControllersQuery += "(objectClass=computer)"
		// That are domain controllers
		domainControllersQuery += fmt.Sprintf("(userAccountControl:1.2.840.113556.1.4.803:=%d)", ldap_attributes.UAF_SERVER_TRUST_ACCOUNT)
		// Account that are not disabled
		domainControllersQuery += fmt.Sprintf("(!(userAccountControl:1.2.840.113556.1.4.803:=%d))", ldap_attributes.UAF_ACCOUNT_DISABLED)
		// Closing the AND
		domainControllersQuery += ")"

		if config.Debug {
			logger.Debug(fmt.Sprintf("LDAP query used: %s", domainControllersQuery))
		}
		attributes := []string{"distinguishedName", "dnsHostname"}
		domainControllersResults, queryErr := ldapSession.QueryWholeSubtree("", domainControllersQuery, attributes)
		if queryErr != nil {
			logger.Warn(fmt.Sprintf("Error querying domain controllers: %s", queryErr))
		}

		gpppfound := gpp.GroupPolicyPreferencePasswordsFound{}
		gpppfound.Entries = make(map[string][]*gpp.CPasswordEntry)

		if len(domainControllersResults) != 0 {

			core.RunWorkers(config.Threads, domainControllersResults, config, &gpppfound)

			logger.Info("")
			if len(gpppfound.Entries) == 0 {
				logger.Info("No results.")
				logger.Info("")
			} else {
				logger.Info("Results:")
				logger.Info("")
			}

			for pathToFile := range gpppfound.Entries {
				if (runtime.GOOS == "linux" || runtime.GOOS == "darwin") && !nocolors {
					logger.Info(fmt.Sprintf("[+] File: \x1b[94m%s\x1b[0m", pathToFile))
				} else {
					logger.Info(fmt.Sprintf("[+] File: %s", pathToFile))
				}
				for k, entry := range gpppfound.Entries[pathToFile] {
					if len(entry.RunAs) != 0 {
						if (runtime.GOOS == "linux" || runtime.GOOS == "darwin") && !nocolors {
							logger.Info(fmt.Sprintf("  │ \x1b[94mRunAs\x1b[0m : \x1b[93m%s\x1b[0m", entry.RunAs))
						} else {
							logger.Info(fmt.Sprintf("  │ RunAs : %s", entry.RunAs))
						}
					}
					if len(entry.UserName) != 0 {
						if (runtime.GOOS == "linux" || runtime.GOOS == "darwin") && !nocolors {
							logger.Info(fmt.Sprintf("  │ \x1b[94mUserName\x1b[0m : \x1b[93m%s\x1b[0m", entry.UserName))
						} else {
							logger.Info(fmt.Sprintf("  │ UserName : %s", entry.UserName))
						}
					}
					if len(entry.NewName) != 0 {
						if (runtime.GOOS == "linux" || runtime.GOOS == "darwin") && !nocolors {
							logger.Info(fmt.Sprintf("  │ \x1b[94mNewName\x1b[0m : \x1b[93m%s\x1b[0m", entry.NewName))
						} else {
							logger.Info(fmt.Sprintf("  │ NewName : %s", entry.NewName))
						}
					}
					if len(entry.Password) != 0 {
						if (runtime.GOOS == "linux" || runtime.GOOS == "darwin") && !nocolors {
							logger.Info(fmt.Sprintf("  │ \x1b[94mPassword\x1b[0m : \x1b[93m%s\x1b[0m", entry.Password))
						} else {
							logger.Info(fmt.Sprintf("  │ Password : %s", entry.Password))
						}
					}

					if k == (len(gpppfound.Entries[pathToFile]) - 1) {
						logger.Info("  └──")
					} else {
						logger.Info("  ├──")
					}
				}
			}

			if len(gpppfound.Entries) == 0 {
				logger.Info("Found no files containing Group Policy Preferences Passwords")
			} else if len(gpppfound.Entries) == 1 {
				logger.Info(fmt.Sprintf("Found %d file containing Group Policy Preferences Passwords", len(gpppfound.Entries)))
			} else {
				logger.Info(fmt.Sprintf("Found %d files containing Group Policy Preferences Passwords", len(gpppfound.Entries)))
			}

			if len(outputExcel) != 0 {
				exporter.GenerateExcel(gpppfound, config, outputExcel)
			}

			if testCredentials {
				TestCredentials(gpppfound, config, nocolors)
			}
		} else {
			logger.Warn("No domain controllers were found; the scan could not be performed.")
			os.Exit(1)
		}
	} else {
		logger.Warn(fmt.Sprintf("Error: %s", err))
		os.Exit(1)
	}

	// Elapsed time
	elapsedTime := time.Since(startTime).Round(time.Millisecond)
	hours := int(elapsedTime.Hours())
	minutes := int(elapsedTime.Minutes()) % 60
	seconds := int(elapsedTime.Seconds()) % 60
	milliseconds := int(elapsedTime.Milliseconds()) % 1000
	logger.Info(fmt.Sprintf("Total time elapsed: %02dh%02dm%02d.%04ds", hours, minutes, seconds, milliseconds))
}
