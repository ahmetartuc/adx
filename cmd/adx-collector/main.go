// Command adx-collector gathers an Active Directory collection from a domain
// controller over LDAP and writes a zip the adX GUI can open. Run it from your
// attack host; nothing is dropped on the target.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"adx/internal/collect"
)

const version = "0.1.0"

func main() {
	var cfg collect.Config
	flag.StringVar(&cfg.Domain, "d", "", "domain FQDN, e.g. corp.local")
	flag.StringVar(&cfg.DC, "dc", "", "domain controller host or IP (required)")
	flag.StringVar(&cfg.User, "u", "", "username (sAMAccountName, UPN, or DOMAIN\\user)")
	flag.StringVar(&cfg.Password, "p", "", "password")
	flag.StringVar(&cfg.Hash, "H", "", "NT hash or LM:NT for pass-the-hash (NTLM)")
	flag.BoolVar(&cfg.NTLM, "ntlm", false, "use NTLM bind with the password instead of simple bind")
	flag.StringVar(&cfg.Ccache, "ccache", "", "Kerberos ccache for pass-the-ticket / local (defaults to $KRB5CCNAME)")
	flag.BoolVar(&cfg.Kerberos, "kerberos", false, "authenticate with Kerberos using the password")
	flag.StringVar(&cfg.Krb5Conf, "krb5conf", "", "path to krb5.conf (generated from -dc/-d if omitted)")
	flag.BoolVar(&cfg.LDAPS, "ldaps", false, "use LDAPS (TLS, port 636)")
	flag.BoolVar(&cfg.Insecure, "k", false, "skip TLS certificate verification (LDAPS)")
	flag.IntVar(&cfg.Port, "port", 0, "LDAP port (default 389, or 636 with -ldaps)")
	flag.StringVar(&cfg.OutDir, "o", ".", "output directory for the collection zip")
	showVer := flag.Bool("version", false, "print version and exit")
	flag.Usage = usage
	flag.Parse()

	if *showVer {
		fmt.Println("adx-collector", version)
		return
	}
	// Default the ccache to $KRB5CCNAME (local / pass-the-ticket).
	if cfg.Ccache == "" && !cfg.Kerberos {
		if cc := os.Getenv("KRB5CCNAME"); cc != "" {
			cfg.Ccache = strings.TrimPrefix(cc, "FILE:")
		}
	}
	hasAuth := cfg.Ccache != "" || cfg.Password != "" || cfg.Hash != ""
	needUser := cfg.Ccache == "" // a ticket carries its own principal
	if cfg.DC == "" || !hasAuth || (needUser && cfg.User == "") {
		usage()
		os.Exit(2)
	}

	fmt.Printf("adx-collector %s — collecting from %s\n", version, cfg.DC)
	path, err := collect.Run(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	fmt.Printf("\n  wrote %s\n  open it in adX (drag it into the window).\n", path)
}

func usage() {
	fmt.Fprintf(os.Stderr, `adx-collector %s — SharpHound-compatible AD collector for adX

Usage:
  adx-collector -dc <host> -u <user> -p <pass> [-d domain.fqdn] [-ldaps] [-o dir]

Examples:
  # remote, password:
  adx-collector -dc 10.10.10.10 -u jdoe -p 'Winter2026!' -d corp.local
  # remote, pass-the-hash:
  adx-collector -dc dc01.corp.local -u jdoe -H 31d6cfe0d16ae931b73c59d7e0c089c0 -d corp.local
  # local / pass-the-ticket (uses $KRB5CCNAME):
  export KRB5CCNAME=/tmp/jdoe.ccache
  adx-collector -dc dc01.corp.local -d corp.local

Flags:
`, version)
	flag.PrintDefaults()
}
