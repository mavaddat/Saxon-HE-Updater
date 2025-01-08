# Saxon-HE Updater

This program updates Saxon-HE from Maven into the `%LOCALAPPDATA%\Programs\Saxonica` folder using `gpg` (GnuPG) to validate the signatures. It requires that GnuPG be installed at `%ProgramFiles(x86)%\gnupg\bin\gpg.exe`, which is the default location for GNU Privacy Guard via Gpg4Win:

```pwsh
winget install --id GnuPG.GnuPG
```