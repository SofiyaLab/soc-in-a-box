# SOC-in-a-Box Security Report

**High Risk:** 1
**Medium Risk:** 0
**Low Risk:** 4

## [LOW] Port 135/tcp (msrpc)
**Risk:** Unknown or less common service
**Fix:** Review service necessity

## [LOW] Port 445/tcp (microsoft-ds)
**Risk:** Unknown or less common service
**Fix:** Review service necessity

## [LOW] Port 902/tcp (vmware-auth)
**Risk:** Unknown or less common service
**Fix:** Review service necessity

## [LOW] Port 912/tcp (vmware-auth)
**Risk:** Unknown or less common service
**Fix:** Review service necessity

## [HIGH] Port 3306/tcp (mysql)
**Risk:** Database service exposed
**Fix:** Restrict access to internal network only


---

## OWASP ZAP Summary

Detected 0 potential web vulnerabilities.

See full details in zap_report.html
