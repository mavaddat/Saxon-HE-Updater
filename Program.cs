﻿using System.ComponentModel;
using System.Diagnostics;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Xml;
using AngleSharp.Html.Parser;

namespace Saxon_HE_Updater
{
    internal static class Program
    {
        private static void Main()
        {
            Console.WriteLine("Starting program...");
            Uri saxonicaMavenUrl = new("https://repo1.maven.org/maven2/net/sf/saxon/Saxon-HE");
            Uri xmlResolverMavenUrl = new ("https://repo1.maven.org/maven2/org/xmlresolver/xmlresolver");
            foreach (var mavenRepositoryUrl in new[] { saxonicaMavenUrl, xmlResolverMavenUrl })
            {
                var mavenMetadataUrl = $"{mavenRepositoryUrl}/maven-metadata.xml";

                // Download and verify maven-metadata.xml
                Console.WriteLine($"Downloading and verifying {mavenMetadataUrl}...");
                var mavenMetadataPath = DownloadAndVerifyFile(mavenMetadataUrl, Path.GetTempPath(), withSignature: false);
                if (string.IsNullOrEmpty(mavenMetadataPath)) return;
                Console.WriteLine($"Successfully downloaded and verified {mavenMetadataUrl}");

                // Parse maven-metadata.xml to get the latest version
                Console.WriteLine("Parsing maven-metadata.xml to get the latest version...");
                var xmlDoc = new XmlDocument();
                xmlDoc.Load(mavenMetadataPath);
                var latestVersion = xmlDoc.SelectSingleNode("/metadata/versioning/latest")?.InnerText;
                Console.WriteLine($"Latest version is {latestVersion}");

                // Download and verify JAR files
                var versionUrl = $"{mavenRepositoryUrl}/{latestVersion}/";
                Console.WriteLine($"Downloading and verifying JAR files from {versionUrl}...");
                var client = GetHttpClient();
                var response = client.GetAsync(versionUrl).Result;
                response.EnsureSuccessStatusCode();
                var htmlContent = response.Content.ReadAsStringAsync().Result;

                // Parse HTML content to get file links
                Console.WriteLine("Parsing HTML content to get file links...");
                var parser = new HtmlParser();
                var htmlDoc = parser.ParseDocument(htmlContent);
                var fileLinks = htmlDoc.QuerySelectorAll("#contents > a").Select(e => e.InnerHtml).Where(link => link.EndsWith(".jar")).ToArray();
                var hasFailures = false;
                foreach (var link in fileLinks)
                {
                    Console.WriteLine($"Processing file {link}...");
                    var fileUrl = $"{versionUrl}{link}";

                    // Download and verify file
                    Console.WriteLine($"Downloading and verifying '{fileUrl}'...");
                    var filePath = DownloadAndVerifyFile(fileUrl, Path.GetTempPath());
                    if (string.IsNullOrEmpty(filePath))
                    {
                        Console.WriteLine($"Failed to download and verify '{fileUrl}'");
                        hasFailures = true;
                        continue;
                    }
                    Console.WriteLine($"Successfully downloaded and verified '{fileUrl}'");

                    // Move the file to the destination folder
                    Console.WriteLine("Moving the file to the destination folder...");
                    var destinationFolder = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs", mavenRepositoryUrl.Segments[^1]);
                    Directory.CreateDirectory(destinationFolder);
                    File.Move(filePath, Path.Combine(destinationFolder, link), true);
                    Console.WriteLine($"Successfully moved the file to '{destinationFolder}'");
                }

                Console.WriteLine(hasFailures ? "Failed to download and verify some files" : "Successfully downloaded and verified all files");
            }
        }

        internal static string DownloadAndVerifyFile(string fileUrl, string downloadFolder, bool withSignature = true)
        {
            Console.WriteLine($"Downloading '{fileUrl}'...");
            var client = GetHttpClient();
            var fileName = Path.GetFileName(fileUrl);
            var filePath = Path.Combine(downloadFolder, fileName);

            // Download the file
            var fileBytes = client.GetByteArrayAsync(fileUrl).Result;
            File.WriteAllBytes(filePath, fileBytes);
            Console.WriteLine($"Successfully downloaded '{fileUrl}'");

            // Verify file hashes
            Console.WriteLine($"Verifying file hashes for '{fileUrl}'...");
            var sigVerified = !withSignature || DownloadGpgSigAndVerify(fileUrl, filePath);
            var result = VerifyFileHashes(fileUrl, filePath) && sigVerified ? filePath : string.Empty;
            if (sigVerified && withSignature) Console.WriteLine($"Successfully verified signature for '{fileUrl}'");
            Console.WriteLine(result != string.Empty ? $"Successfully verified file hashes for '{fileUrl}'" : $"Failed to verify file hashes for '{fileUrl}'");
            return result;
        }

        private static HttpClient GetHttpClient()
        {
            Console.WriteLine("Creating HttpClient with custom headers...");
            var client = new HttpClient();

            // Add Accept header
            client.DefaultRequestHeaders.Accept.Clear();
            client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("text/html"));
            client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/xhtml+xml"));
            client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/xml"));

            // Add User-Agent header
            client.DefaultRequestHeaders.UserAgent.Clear();
            client.DefaultRequestHeaders.UserAgent.ParseAdd("Mozilla/5.0");
            client.DefaultRequestHeaders.UserAgent.ParseAdd("(Windows NT 10.0; Microsoft Windows 10.0.19045; en-CA)");
            client.DefaultRequestHeaders.UserAgent.ParseAdd("PowerShell/7.4.2");

            // Add Accept-Encoding header
            client.DefaultRequestHeaders.AcceptEncoding.Clear();
            client.DefaultRequestHeaders.AcceptEncoding.Add(new StringWithQualityHeaderValue("gzip"));
            client.DefaultRequestHeaders.AcceptEncoding.Add(new StringWithQualityHeaderValue("deflate"));
            client.DefaultRequestHeaders.AcceptEncoding.Add(new StringWithQualityHeaderValue("br"));

            Console.WriteLine("Successfully created HttpClient with custom headers");
            return client;
        }

        internal static bool VerifyFileHashes(string fileUrl, string filePath)
        {
            Console.WriteLine($"Verifying file hashes for '{fileUrl}'...");
            string[] hashAlgorithms = ["md5", "sha1", "sha256", "sha512"];
            var hashesMatch = true;

            foreach (var hashAlgorithm in hashAlgorithms)
            {
                Console.WriteLine($"Checking {hashAlgorithm} hash for '{fileUrl}'...");
                var hashUrl = $"{fileUrl}.{hashAlgorithm}";
                var client = GetHttpClient();
                var remoteHash = client.GetStringAsync(hashUrl).Result;
                var fileBytes = File.ReadAllBytes(filePath);
                var localHash = hashAlgorithm switch
                {
                    "md5" => Convert.ToHexStringLower(MD5.HashData(fileBytes)),
                    "sha1" => Convert.ToHexStringLower(SHA1.HashData(fileBytes)),
                    "sha256" => Convert.ToHexStringLower(SHA256.HashData(fileBytes)),
                    "sha512" => Convert.ToHexStringLower(SHA512.HashData(fileBytes)),
                    _ => throw new InvalidOperationException($"Unsupported hash algorithm: {hashAlgorithm}")
                };
                hashesMatch = hashesMatch && remoteHash == localHash;
                Console.WriteLine(hashesMatch ? $"Successfully checked {hashAlgorithm} hash for '{fileUrl}'" : $"Failed to check {hashAlgorithm} hash for '{fileUrl}'.\n\tRemote hash: '{remoteHash}'\n\tLocal hash: '{localHash}'.\nSee '{hashUrl}'.");
                if (!hashesMatch) break;
            }

            return hashesMatch;
        }

        private static bool VerifyGpg(string signatureFile, string downloadedFile)
        {
            Console.WriteLine($"Verifying GPG signature for {downloadedFile}...");
            var result = false;
            var keyServers = new[] { "hkps://keys.openpgp.org", "hkps://keyserver.ubuntu.com", "hkps://pgp.mit.edu", "hkps://pgp.surf.nl" };
            foreach (var keyServer in keyServers)
            {
                var startInfo = new ProcessStartInfo()
                {
                    FileName = GpgPath,
                    Arguments = $"--auto-key-locate keyserver --keyserver {keyServer} --keyserver-options auto-key-retrieve --verify \"{signatureFile}\" \"{downloadedFile}\"",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                };

                using var process = new Process();
                process.StartInfo = startInfo;
                try
                {
                    process.Start();
                }catch (Exception ex) when (ex is FileNotFoundException or Win32Exception or InvalidOperationException)
                {
                    Console.Error.WriteLine($"Error: GnuPG executable not found at path '{GpgPath}'. Please ensure that GnuPG is installed and the path is correct.");
                    Console.Error.WriteLine("""
                                            You can install GnuPG using the following command:
                                            
                                                winget install --id GnuPG.GnuPG
                                            
                                            You may need to add the public key first:
                                            
                                                gpg --keyserver hkps://keyserver.ubuntu.com --recv-keys A929EA2321FDBF8F
                                            
                                            """);
                    return result;
                }

                var output = process.StandardOutput.ReadToEnd();
                var errors = process.StandardError.ReadToEnd();
                process.WaitForExit();

                result |= process.ExitCode == 0;
                Console.WriteLine(result ? $"Successfully verified GPG signature for '{downloadedFile}'\n{output}" : $"Failed to verify GPG signature for '{downloadedFile}' using key server '{keyServer}'.\n{errors}");
                if (result) break;
            }
            return result;
        }

        public static bool DownloadGpgSigAndVerify(string fileUrl, string filePath)
        {
            Console.WriteLine($"Downloading GPG signature for '{fileUrl}'...");
            var sigUrl = $"{fileUrl}.asc";
            var sigPath = Path.GetTempFileName();
            var client = GetHttpClient();
            var asciiSig = client.GetStringAsync(sigUrl).Result;
            File.WriteAllText(sigPath, asciiSig);
            Console.WriteLine($"Successfully downloaded GPG signature for '{fileUrl}'");

            Console.WriteLine($"Verifying GPG signature for '{fileUrl}'...");
            var result = VerifyGpg(sigPath, filePath);
            Console.WriteLine(result ? $"Successfully verified GPG signature for '{fileUrl}'" : $"Failed to verify GPG signature for '{fileUrl}'. See '{sigUrl}'");
            return result;
        }

        private static readonly string GpgPath = FindGpgPath();
        private static string FindGpgPath()
        {
            var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "where",
                    Arguments = "gpg.exe",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                }
            };
            process.Start();
            var output = process.StandardOutput.ReadToEnd();
            process.WaitForExit();
            return output.Trim();
        }
    }
}
