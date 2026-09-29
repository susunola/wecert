package config

// uploadAliasPrefix is the marker every wecert upload carries in the Tencent Cloud SSL
// remark. Preflight and the certificate reaper select on it, so it must not change
// without a migration for certificates that are already uploaded.
const uploadAliasPrefix = "wecert/"

// UploadAlias is the SSL remark ("备注") a certificate uploaded under certName carries:
// "wecert/<certificate name>".
//
// The Tencent Cloud SSL console identifies a certificate by this remark rather than by
// anything wecert-side, and the read-only inventory shows the same string next to the
// deployed certificate ID so an operator can match the two consoles row for row.
// The uploader and the inventory call this one function: that is what keeps the displayed
// remark from drifting away from the remark that was actually written on upload.
func UploadAlias(certName string) string {
	if certName == "" {
		return ""
	}
	return uploadAliasPrefix + certName
}
