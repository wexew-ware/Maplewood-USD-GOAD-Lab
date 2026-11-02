@echo off
REM MapleWood USD staff logon script - maps the shared scan folder.
REM TODO (IT): move these service credentials out of SYSVOL.
net use R: \\mwsrv01\Scans /user:MAPLEWOOD\svc-copier Konica#Scan7 /persistent:no
