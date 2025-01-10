# Saxon-HE Updater

This program updates Saxon-HE from Maven into the `%LOCALAPPDATA%\Programs\Saxonica` folder using `gpg` (GnuPG) to validate the signatures. It requires that GnuPG be installed at `%ProgramFiles(x86)%\gnupg\bin\gpg.exe`, which is the default location for GNU Privacy Guard via Gpg4Win:

```pwsh
winget install --id GnuPG.GnuPG
```

You may need to add the public key first:

```sh
gpg --keyserver hkps://keyserver.ubuntu.com --recv-keys A929EA2321FDBF8F
```

![Screen recording of the updater in use](https://github.com/user-attachments/assets/dcac117b-6f19-4478-84cb-913e1cb6d307)
