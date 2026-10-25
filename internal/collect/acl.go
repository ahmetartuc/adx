package collect

import (
	"encoding/binary"
	"strings"
)

// Windows security descriptor / ACL parsing, enough to recover the
// control-relationship ACEs BloodHound represents as edges.

// Access mask bits (ADS_RIGHTS / standard rights).
const (
	rightGenericAll    = 0x10000000
	rightGenericWrite  = 0x40000000
	rightWriteDacl     = 0x00040000
	rightWriteOwner    = 0x00080000
	rightDSControl     = 0x00000100 // DS_CONTROL_ACCESS (extended right)
	rightDSWriteProp   = 0x00000020 // DS write property
	rightDSSelf        = 0x00000008 // validated write
	rightFullControl   = 0x000f01ff
)

// Extended-right and property GUIDs (lowercase).
const (
	guidForceChangePwd = "00299570-246d-11d0-a768-00aa006e0529"
	guidMember         = "bf9679c0-0de6-11d0-a285-00aa003049e2"
	guidGetChanges     = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
	guidGetChangesAll  = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
	guidGetChangesFilt = "89e95b76-444d-4c62-991a-0facbeda640c"
	guidAllowedToAct   = "3f78c3e5-f79a-46bd-a0b8-9d18116ddc79"
	guidKeyCredLink    = "5b47d60f-6090-40b2-9f37-2a4de88f3063"
)

type aceOut struct {
	PrincipalSID  string `json:"PrincipalSID"`
	PrincipalType string `json:"PrincipalType"`
	RightName     string `json:"RightName"`
	IsInherited   bool   `json:"IsInherited"`
}

// aces parses an object's security descriptor into the ACE list the GUI reads.
func (c *converter) aces(e *entry) []any {
	out := []any{}
	if len(e.sd) < 20 {
		return out
	}
	owner, daclOff := parseSDHeader(e.sd)
	// Owner → Owns, unless it is a default tier-zero principal (pure noise).
	if owner != "" && !noisePrincipal(owner) {
		out = append(out, aceOut{PrincipalSID: owner, PrincipalType: c.ptype(owner), RightName: "Owner"})
	}
	if daclOff == 0 || daclOff+8 > uint32(len(e.sd)) {
		return out
	}
	for _, a := range parseACL(e.sd[daclOff:]) {
		if noisePrincipal(a.sid) {
			continue
		}
		pt := c.ptype(a.sid)
		rights := rightsFor(a, e.kind)
		// LAPS / gMSA password reads use per-forest schema GUIDs resolved at runtime.
		if r, ok := c.readGUIDs[a.objectType]; ok && a.mask&(0x10|rightDSControl|rightGenericAll) != 0 {
			rights = append(rights, r)
		}
		for _, r := range rights {
			out = append(out, aceOut{PrincipalSID: a.sid, PrincipalType: pt, RightName: r, IsInherited: a.inherited})
		}
	}
	return out
}

func (c *converter) ptype(sid string) string {
	if t, ok := c.sidType[sid]; ok {
		return t
	}
	return "Base"
}

// parseSDHeader returns the owner SID and the DACL offset.
func parseSDHeader(b []byte) (owner string, daclOff uint32) {
	if len(b) < 20 {
		return "", 0
	}
	ownerOff := binary.LittleEndian.Uint32(b[4:8])
	daclOff = binary.LittleEndian.Uint32(b[16:20])
	if ownerOff != 0 && int(ownerOff) < len(b) {
		owner = decodeSID(b[ownerOff:])
	}
	return owner, daclOff
}

type rawACE struct {
	sid        string
	mask       uint32
	objectType string // lowercase GUID, "" if none
	inherited  bool
	allowed    bool
}

// parseACL walks an ACL structure (header then ACEs).
func parseACL(b []byte) []rawACE {
	var out []rawACE
	if len(b) < 8 {
		return out
	}
	count := int(binary.LittleEndian.Uint16(b[4:6]))
	off := 8
	for i := 0; i < count && off+4 <= len(b); i++ {
		aceType := b[off]
		aceFlags := b[off+1]
		size := int(binary.LittleEndian.Uint16(b[off+2 : off+4]))
		if size < 4 || off+size > len(b) {
			break
		}
		body := b[off+4 : off+size]
		a := rawACE{inherited: aceFlags&0x10 != 0}
		switch aceType {
		case 0x00: // ACCESS_ALLOWED_ACE
			a.allowed = true
			if len(body) >= 4 {
				a.mask = binary.LittleEndian.Uint32(body[0:4])
				a.sid = decodeSID(body[4:])
			}
		case 0x05: // ACCESS_ALLOWED_OBJECT_ACE
			a.allowed = true
			if len(body) >= 8 {
				a.mask = binary.LittleEndian.Uint32(body[0:4])
				flags := binary.LittleEndian.Uint32(body[4:8])
				p := 8
				if flags&0x1 != 0 && p+16 <= len(body) { // ObjectType present
					a.objectType = strings.ToLower(decodeGUID(body[p : p+16]))
					p += 16
				}
				if flags&0x2 != 0 && p+16 <= len(body) { // InheritedObjectType present
					p += 16
				}
				if p <= len(body) {
					a.sid = decodeSID(body[p:])
				}
			}
		}
		if a.allowed && a.sid != "" {
			out = append(out, a)
		}
		off += size
	}
	return out
}

// rightsFor maps one ACE to zero or more BloodHound edge names.
func rightsFor(a rawACE, targetKind string) []string {
	// Full control short-circuits the sub-rights.
	if a.mask&rightGenericAll != 0 || a.mask&rightFullControl == rightFullControl {
		return []string{"GenericAll"}
	}
	var r []string
	if a.mask&rightWriteDacl != 0 {
		r = append(r, "WriteDacl")
	}
	if a.mask&rightWriteOwner != 0 {
		r = append(r, "WriteOwner")
	}
	if a.objectType == "" {
		// Rights that apply to the whole object.
		if a.mask&rightGenericWrite != 0 {
			r = append(r, "GenericWrite")
		}
		if a.mask&rightDSControl != 0 {
			r = append(r, "AllExtendedRights")
		}
	} else {
		if a.mask&rightDSControl != 0 {
			switch a.objectType {
			case guidForceChangePwd:
				r = append(r, "ForceChangePassword")
			case guidGetChanges:
				r = append(r, "GetChanges")
			case guidGetChangesAll:
				r = append(r, "GetChangesAll")
			case guidGetChangesFilt:
				r = append(r, "GetChangesInFilteredSet")
			}
		}
		if a.mask&(rightDSWriteProp|rightDSSelf) != 0 {
			switch a.objectType {
			case guidMember:
				r = append(r, "AddMember")
			case guidAllowedToAct:
				r = append(r, "AddAllowedToAct")
			case guidKeyCredLink:
				r = append(r, "AddKeyCredentialLink")
			}
		}
	}
	return r
}

// noisePrincipal skips default tier-zero / built-in SIDs whose ACEs never form
// a new attack path, keeping the collection lean.
func noisePrincipal(sid string) bool {
	switch sid {
	case "S-1-5-18", "S-1-5-10", "S-1-3-0", "S-1-5-9", "S-1-5-32-544",
		"S-1-5-32-548", "S-1-5-32-549", "S-1-5-32-550", "S-1-5-32-551", "S-1-5-32-552":
		return true
	}
	if strings.HasPrefix(sid, "S-1-5-21-") {
		switch ridOf(sid) {
		case "512", "516", "518", "519", "520", "521", "498":
			return true
		}
	}
	return false
}

func ridOf(sid string) string {
	if i := strings.LastIndexByte(sid, '-'); i >= 0 {
		return sid[i+1:]
	}
	return sid
}
