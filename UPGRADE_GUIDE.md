# 🔄 MKPE UPGRADE GUIDE

## 📊 What You Currently Have vs. What's New

### **CURRENT VERSION (v1.0.0)**
**Location:** `C:\MKPE\MKPE_MODERN.exe` (7.1 MB)

**Current Features:**
- ✅ File protection and monitoring
- ✅ System tray icon (sometimes works)
- ✅ Protected folders (sometimes lose settings)
- ✅ Basic UI with 3 tabs
- ⚠️ No secrets vault
- ⚠️ No file creation tracking
- ⚠️ Icon paths hardcoded

### **NEW VERSION (v1.1.0)**
**Location:** `C:\MKPE\ui_desktop\target\release\mkpe_desktop.exe` (6.8 MB)

**New Features:**
- ✅ **Secrets Vault Tab** - Track .dcx, .pdf, .rs file creation
- ✅ **Trust Indicators** - Visual trust levels for all files
- ✅ **Cryptographic Hashing** - SHA-256 verification for integrity
- ✅ **File Details View** - Creator, machine, timestamp, hash
- ✅ **Fixed Icon Paths** - System tray icon works reliably
- ✅ **Fixed Persistence** - Protected folders save correctly
- ✅ **Better Error Handling** - Config creation and loading improved

---

## 🤔 SHOULD YOU UPGRADE?

### **YES, UPGRADE IF:**
- ✅ You want the secrets vault for file tracking
- ✅ You're having issues with system tray icon
- ✅ Your protected folders aren't saving correctly
- ✅ You need cryptographic proof of file creation
- ✅ You want to test on the 4 systems you mentioned

### **WAIT IF:**
- ⏸️ Your current version is working perfectly
- ⏸️ You're in the middle of important work
- ⏸️ You want to wait for full testing across all systems

---

## 🚀 THREE UPGRADE OPTIONS

### **OPTION 1: SIDE-BY-SIDE (SAFEST)**
**Recommended for testing on your 4 systems**

```powershell
cd C:\MKPE
.\upgrade_mkpe.ps1 -SideBySide -Backup
```

**Result:**
- Old version: `C:\MKPE\MKPE_MODERN.exe` (keeps running)
- New version: `C:\MKPE\MKPE_v1.1.0.exe` (test this)
- Can compare both versions
- Easy rollback if needed

### **OPTION 2: IN-PLACE UPGRADE (CLEANEST)**
**Recommended after testing confirms everything works**

```powershell
cd C:\MKPE
.\upgrade_mkpe.ps1 -Backup
```

**Result:**
- Replaces `C:\MKPE\MKPE_MODERN.exe` with new version
- Backup saved to `C:\MKPE\backups\`
- Clean single installation
- All settings preserved

### **OPTION 3: MANUAL INSTALL (FULL CONTROL)**
**If you want to do it yourself**

```powershell
# Stop any running MKPE
Get-Process | Where-Object { $_.Name -like "*mkpe*" } | Stop-Process -Force

# Copy new version
Copy-Item "C:\MKPE\ui_desktop\target\release\mkpe_desktop.exe" "C:\MKPE\MKPE_v1.1.0.exe"

# Create secrets directory
New-Item -ItemType Directory -Path "C:\MKPE\secrets" -Force

# Launch new version
Start-Process "C:\MKPE\MKPE_v1.1.0.exe"
```

---

## 🔍 WHAT GETS PRESERVED

### **Your Data (Safe):**
- ✅ Protected folders list
- ✅ Configuration files
- ✅ Log files
- ✅ Activity history
- ✅ Threat logs

### **New Data (Added):**
- 🆕 Secrets vault database (`C:\MKPE\secrets\vault.json`)
- 🆕 File creation records
- 🆕 Trust level tracking
- 🆕 Cryptographic hashes

---

## 🎯 RECOMMENDED APPROACH FOR YOUR 4 SYSTEMS

Since you mentioned you have MKPE running on **4 separate systems with different configurations**, here's the smart approach:

### **SYSTEM 1 (Test System):**
```powershell
# Install side-by-side and test thoroughly
cd C:\MKPE
.\upgrade_mkpe.ps1 -SideBySide -Backup
```
Test for 24-48 hours, verify:
- ✅ System tray icon appears
- ✅ Protected folders persist after restart
- ✅ Secrets vault works
- ✅ No crashes or errors

### **SYSTEMS 2-4 (After System 1 Success):**
```powershell
# Do clean in-place upgrade
cd C:\MKPE
.\upgrade_mkpe.ps1 -Backup
```

---

## 🆘 ROLLBACK PLAN (If Something Goes Wrong)

### **If Side-by-Side:**
Just use the old version: `C:\MKPE\MKPE_MODERN.exe`

### **If In-Place Upgraded:**
```powershell
# Restore from backup
$backup = Get-ChildItem "C:\MKPE\backups\MKPE_MODERN_*.exe" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
Copy-Item $backup.FullName "C:\MKPE\MKPE_MODERN.exe" -Force
```

---

## 📋 UPGRADE CHECKLIST

Before upgrading:
- [ ] Backup important config files
- [ ] Note your protected folders
- [ ] Close any running MKPE instances
- [ ] Have 10 minutes for testing

After upgrading:
- [ ] Launch new version
- [ ] Verify protected folders loaded
- [ ] Check system tray icon
- [ ] Test secrets vault (new 🔐 tab)
- [ ] Add a test file to vault
- [ ] Verify trust indicators work

---

## 💡 RECOMMENDATION

**For your situation (4 systems, need to test):**

1. **TODAY:** Side-by-side install on one test system
2. **Test 24-48 hours:** Make sure everything works
3. **THEN:** In-place upgrade on other 3 systems
4. **FINALLY:** Once all 4 systems confirmed working, we can package a full installer

**This way you don't lose anything and can roll back instantly if needed.**

---

## 🚀 Ready to Upgrade?

Run this command to start:
```powershell
cd C:\MKPE
.\upgrade_mkpe.ps1 -SideBySide -Backup
```

Choose option 1 to launch immediately and see the new Secrets Vault! 🔐
