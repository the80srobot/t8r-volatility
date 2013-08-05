import volatility.plugins.common as common
import volatility.utils as utils
import volatility.plugins.registry.hivelist as hl
import volatility.plugins.registry.printkey as pk
import volatility.win32.hive as hivemod
import volatility.win32.rawreg as rawreg

reg_keys = {
  "HKCU": [
    "Software\\Policies\\Microsoft\\Windows\\System\\Scripts\\Logoff",
    "Software\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\Scripts\\Startup",
    "Software\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\Scripts\\Shutdown",
    "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Shell",
    "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell",
    "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\Load",
    "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\Run",
    "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
    "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Terminal Server\\Install\\Software\\Microsoft\\Windows\\CurrentVersion\\Runonce",
    "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Terminal Server\\Install\\Software\\Microsoft\\Windows\\CurrentVersion\\RunonceEx",
    "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Terminal Server\\Install\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "SOFTWARE\\Classes\\Protocols\\Filter",
    "SOFTWARE\\Classes\\Protocols\\Handler",
    "SOFTWARE\\Microsoft\\Internet Explorer\\Desktop\\Components",
    "SOFTWARE\\Microsoft\\Active Setup\\Installed Components",
    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ShellServiceObjectDelayLoad",
    "Software\\Classes\\*\\ShellEx\\ContextMenuHandlers",
    "Software\\Classes\\AllFileSystemObjects\\ShellEx\\ContextMenuHandlers",
    "Software\\Classes\\Directory\\ShellEx\\ContextMenuHandlers",
    "Software\\Classes\\Directory\\Shellex\\DragDropHandlers",
    "Software\\Classes\\Directory\\Shellex\\PropertySheetHandlers",
    "Software\\Classes\\Directory\\Shellex\\CopyHookHandlers",
    "Software\\Classes\\Folder\\Shellex\\ColumnHandlers",
    "Software\\Classes\\Folder\\ShellEx\\ContextMenuHandlers",
    "Software\\Classes\\Directory\\Background\\ShellEx\\ContextMenuHandlers",
    "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellIconOverlayIdentifiers",
    "Software\\Microsoft\\Ctf\\LangBarAddin",
    "Software\\Microsoft\\Windows\\CurrentVersion\\Shell Extensions\\Approved",
    "Software\\Microsoft\\Internet Explorer\\UrlSearchHooks",
    "Software\\Microsoft\\Internet Explorer\\Explorer Bars",
    "Software\\Microsoft\\Internet Explorer\\Extensions",
    "Software\\Microsoft\\Windows NT\\CurrentVersion\\Drivers32",
    "Software\\Classes\\Filter",
    "Software\\Microsoft\\Command Processor\\Autorun",
    "SOFTWARE\\Classes\\Exefile\\Shell\\Open\\Command\\(Default)",
    "Software\\Classes\\.exe",
    "Software\\Classes\\.cmd",
    "SOFTWARE\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop\\Scrnsave.exe",
    "Control Panel\\Desktop\\Scrnsave.exe"
  ],

  "HKLM\\Software": [
    "Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\AppSetup",
    "Policies\\Microsoft\\Windows\\System\\Scripts\\Startup",
    "Policies\\Microsoft\\Windows\\System\\Scripts\\Logon",
    "Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit",
    "Policies\\Microsoft\\Windows\\System\\Scripts\\Shutdown",
    "Policies\\Microsoft\\Windows\\System\\Scripts\\Logoff",
    "Microsoft\\Windows\\CurrentVersion\\Group Policy\\Scripts\\Startup",
    "Microsoft\\Windows\\CurrentVersion\\Group Policy\\Scripts\\Shutdown",
    "Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Shell",
    "Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell",
    "Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Taskman",
    "Microsoft\\Windows NT\\CurrentVersion\\Terminal Server\\Install\\Software\\Microsoft\\Windows\\CurrentVersion\\Runonce",
    "Microsoft\\Windows NT\\CurrentVersion\\Terminal Server\\Install\\Software\\Microsoft\\Windows\\CurrentVersion\\RunonceEx",
    "Microsoft\\Windows NT\\CurrentVersion\\Terminal Server\\Install\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "Microsoft\\Windows\\CurrentVersion\\Run",
    "Microsoft\\Windows\\CurrentVersion\\RunOnceEx",
    "Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
    "Classes\\Protocols\\Filter",
    "Classes\\Protocols\\Handler",
    "Microsoft\\Active Setup\\Installed Components",
    "Microsoft\\Windows\\CurrentVersion\\Explorer\\SharedTaskScheduler",
    "Microsoft\\Windows\\CurrentVersion\\ShellServiceObjectDelayLoad",
    "Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellExecuteHooks",
    "Classes\\*\\ShellEx\\ContextMenuHandlers",
    "Classes\\AllFileSystemObjects\\ShellEx\\ContextMenuHandlers",
    "Classes\\Directory\\ShellEx\\ContextMenuHandlers",
    "Classes\\Directory\\Shellex\\DragDropHandlers",
    "Classes\\Directory\\Shellex\\PropertySheetHandlers",
    "Classes\\Directory\\Shellex\\CopyHookHandlers",
    "Classes\\Folder\\Shellex\\ColumnHandlers",
    "Classes\\Folder\\ShellEx\\ContextMenuHandlers",
    "Classes\\Directory\\Background\\ShellEx\\ContextMenuHandlers",
    "Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellIconOverlayIdentifiers",
    "Microsoft\\Ctf\\LangBarAddin",
    "Microsoft\\Windows\\CurrentVersion\\Shell Extensions\\Approved",
    "Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects",
    "Microsoft\\Internet Explorer\\Toolbar",
    "Microsoft\\Internet Explorer\\Explorer Bars",
    "Microsoft\\Internet Explorer\\Extensions",
    "Microsoft\\Windows NT\\CurrentVersion\\Drivers32",
    "Classes\\Filter",
    "Classes\\CLSID\\{083863F1-70DE-11d0-BD40-00A0C911CE86}\\Instance",
    "Classes\\CLSID\\{AC757296-3522-4E11-9862-C17BE5A1767E}\\Instance",
    "Classes\\CLSID\\{7ED96837-96F0-4812-B211-F13C24117ED3}\\Instance",
    "Classes\\CLSID\\{ABE3B9A4-257D-4B97-BD1A-294AF496222E}\\Instance",
    "Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
    "Microsoft\\Command Processor\\Autorun",
    "Classes\\Exefile\\Shell\\Open\\Command\\(Default)",
    "Classes\\.exe",
    "Classes\\.cmd",
    "Microsoft\\Windows NT\\CurrentVersion\\Windows\\Appinit_Dlls",
    "Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\ServiceControllerStart",
    "Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\LsaStart",
    "Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\System",
    "Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\UIHost",
    "Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify",
    "Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\GinaDLL",
    "Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Taskman",
    "Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SaveDumpStart"
  ],

  "HKLM\\System": [
    "CurrentControlSet\\Services",
    "CurrentControlSet\\Control\\Terminal Server\\Wds\\rdpwd\\StartupPrograms",
    "CurrentControlSet\\Control\\Session Manager\\KnownDlls",
    "CurrentControlSet\\Control\\Session Manager\\BootExecute",
    "CurrentControlSet\\Control\\Session Manager\\SetupExecute",
    "CurrentControlSet\\Control\\Session Manager\\Execute",
    "CurrentControlSet\\Control\\Session Manager\\S0InitialCommand",
    "CurrentControlSet\\Control\\BootVerificationProgram\\ImagePath",
    "CurrentControlSet\\Services\\WinSock2\\Parameters\\Protocol_Catalog9\\Catalog_Entries",
    "CurrentControlSet\\Services\\WinSock2\\Parameters\\NameSpace_Catalog5\\Catalog_Entries",
    "CurrentControlSet\\Control\\Print\\Monitors",
    "CurrentControlSet\\Control\\SecurityProviders\\SecurityProviders",
    "CurrentControlSet\\Control\\Lsa\\Authentication Packages",
    "CurrentControlSet\\Control\\Lsa\\Notification Packages",
    "CurrentControlSet\\Control\\Lsa\\Security Packages",
    "CurrentControlSet\\Control\\NetworkProvider\\Order"
  ]
}

hive_map = {
  "ntuser.dat": "HKCU",
  "config\\software": "HKLM\\Software",
  "config\\system": "HKLM\\System"
}

class Persistence(pk.PrintKey):
  """Prints keys in Windows registry known for enabling executable persistence (SLOW)"""
  
  def calc_offsets(self):
    hives = hl.HiveList.calculate(self)
    prefix_offsets = dict.fromkeys(hive_map.values(), [])

    for hive in hives:
      if hive.Hive.Signature == 0xbee0bee0:
        try:
          name = str(hive.FileFullPath or '') or str(hive.FileUserName or '') or str(hive.HiveRootPath or '') or "[no name]"
        except AttributeError:
          continue

      off = hive.obj_offset
      name = name.lower()

      for key, prefix in hive_map.iteritems():
        if name.find(key) > 0:
          bucket = prefix_offsets[prefix]
          if off not in bucket:
            bucket.append(off)
          break

    return prefix_offsets

  def calc_keys(self, offsets, reg_keys):
    addr_space = utils.load_as(self._config)

    for prefix, keys in reg_keys.iteritems():
      for off in offsets[prefix]:
        hive = hivemod.HiveAddressSpace(addr_space, self._config, off)
        root = rawreg.get_root(hive)
        for key in keys:
          val = rawreg.open_key(root, key.split("\\"))
          if val:
            idx = prefix + "\\" + key
            yield idx, val

  def calculate(self):
    offsets = self.calc_offsets()
    results = self.calc_keys(offsets, reg_keys)

    return results
