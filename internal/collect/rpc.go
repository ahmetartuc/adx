package collect

import (
	"context"
	"strings"
	"time"

	"github.com/oiweiwei/go-msrpc/dcerpc"
	"github.com/oiweiwei/go-msrpc/ssp"
	"github.com/oiweiwei/go-msrpc/ssp/credential"
	"github.com/oiweiwei/go-msrpc/ssp/gssapi"

	"github.com/oiweiwei/go-msrpc/msrpc/dtyp"
	"github.com/oiweiwei/go-msrpc/msrpc/samr/samr/v1"
	"github.com/oiweiwei/go-msrpc/msrpc/srvs/srvsvc/v3"

	_ "github.com/oiweiwei/go-msrpc/msrpc/erref/ntstatus"
)

const samrRead = dtyp.AccessMaskGenericRead | dtyp.AccessMaskGenericExecute

// Local alias RID -> the field it fills on the computer.
var aliasRIDs = []uint32{544, 555, 562, 580}

// rpcReady reports whether we have credentials go-msrpc can use (password or
// NT hash). Kerberos/ccache for SMB is not wired up yet.
func rpcReady(cfg Config) bool { return cfg.Password != "" || cfg.Hash != "" }

// collectRPC enumerates local group membership (AdminTo/CanRDP/ExecuteDCOM/
// CanPSRemote) and sessions (HasSession) from each computer over SMB. Hosts
// that are unreachable or deny access are skipped; this is best-effort.
func collectRPC(cfg Config, computers []*entry, samToSID map[string]string) (reached, denied, failed int) {
	setupGSSAPI(cfg)
	for _, c := range computers {
		host := c.first("dNSHostName")
		if host == "" {
			host = strings.ToLower(strings.TrimSuffix(c.first("sAMAccountName"), "$")) + "." + strings.ToLower(cfg.Domain)
		}
		// We already have a reachable address for the DC; member hosts need DNS.
		if isDC(c) {
			host = cfg.DC
		}
		base, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		ctx := gssapi.NewSecurityContext(base)
		ok, acc := enumLocalGroups(ctx, host, c)
		enumSessions(ctx, host, c, samToSID)
		cancel()
		switch {
		case ok:
			reached++
		case acc:
			denied++
		default:
			failed++
		}
	}
	return reached, denied, failed
}

func setupGSSAPI(cfg Config) {
	un := cfg.Domain + "\\" + ntlmUser(cfg)
	if cfg.Hash != "" {
		h := cfg.Hash
		if i := strings.LastIndexByte(h, ':'); i >= 0 {
			h = h[i+1:]
		}
		gssapi.AddCredential(credential.NewFromNTHash(un, h))
	} else {
		gssapi.AddCredential(credential.NewFromPassword(un, cfg.Password))
	}
	gssapi.AddMechanism(ssp.SPNEGO)
	gssapi.AddMechanism(ssp.NTLM)
}

// enumLocalGroups returns (reached, accessDenied).
func enumLocalGroups(ctx context.Context, host string, c *entry) (bool, bool) {
	cc, err := dcerpc.Dial(ctx, host, dcerpc.WithEndpoint("ncacn_np:[samr]"))
	if err != nil {
		return false, false
	}
	defer cc.Close(ctx)
	cli, err := samr.NewSamrClient(ctx, cc, dcerpc.WithInsecure())
	if err != nil {
		return false, isDenied(err)
	}
	conn, err := cli.Connect(ctx, &samr.ConnectRequest{DesiredAccess: samrRead})
	if err != nil {
		return false, isDenied(err)
	}
	dom, err := cli.LookupDomainInSAMServer(ctx, &samr.LookupDomainInSAMServerRequest{
		Server: conn.Server, Name: &dtyp.UnicodeString{Buffer: "Builtin"}})
	if err != nil {
		return false, isDenied(err)
	}
	dh, err := cli.OpenDomain(ctx, &samr.OpenDomainRequest{Server: conn.Server, DesiredAccess: samrRead, DomainID: dom.DomainID})
	if err != nil {
		return false, isDenied(err)
	}
	for _, rid := range aliasRIDs {
		ah, err := cli.OpenAlias(ctx, &samr.OpenAliasRequest{Domain: dh.Domain, DesiredAccess: samrRead, AliasID: rid})
		if err != nil {
			continue
		}
		mem, err := cli.GetMembersInAlias(ctx, &samr.GetMembersInAliasRequest{AliasHandle: ah.AliasHandle})
		if err != nil {
			continue
		}
		for _, s := range mem.Members.SIDs {
			if s == nil || s.SIDPointer == nil {
				continue
			}
			sid := strings.ToUpper(s.SIDPointer.String())
			if !strings.HasPrefix(sid, "S-1-5-21-") {
				continue // domain principals only
			}
			switch rid {
			case 544:
				c.admins = append(c.admins, sid)
			case 555:
				c.rdp = append(c.rdp, sid)
			case 562:
				c.dcom = append(c.dcom, sid)
			case 580:
				c.psremote = append(c.psremote, sid)
			}
		}
	}
	return true, false
}

func enumSessions(ctx context.Context, host string, c *entry, samToSID map[string]string) {
	cc, err := dcerpc.Dial(ctx, host, dcerpc.WithEndpoint("ncacn_np:[srvsvc]"))
	if err != nil {
		return
	}
	defer cc.Close(ctx)
	cli, err := srvsvc.NewSrvsvcClient(ctx, cc, dcerpc.WithInsecure())
	if err != nil {
		return
	}
	resp, err := cli.SessionEnum(ctx, &srvsvc.SessionEnumRequest{
		Info: &srvsvc.SessionEnum{Level: 10, SessionInfo: &srvsvc.SessionEnumUnion{
			Value: &srvsvc.SessionEnumUnion_Level10{Level10: &srvsvc.SessionInfo10Container{}}}},
		PreferredMaximumLength: 0xffffffff,
	})
	if err != nil { // commonly ACCESS_DENIED without admin; that is expected
		return
	}
	cont, _ := resp.Info.SessionInfo.GetValue().(*srvsvc.SessionInfo10Container)
	if cont == nil {
		return
	}
	for _, s := range cont.Buffer {
		name := strings.ToUpper(strings.TrimSpace(s.UserName))
		name = strings.TrimSuffix(name, "$")
		if name == "" {
			continue
		}
		if sid, ok := samToSID[name]; ok {
			c.sessions = append(c.sessions, sid)
		}
	}
}

func isDenied(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "access")
}

