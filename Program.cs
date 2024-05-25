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
            const string mavenRepositoryUrl = "https://repo1.maven.org/maven2/net/sf/saxon/Saxon-HE";
            const string mavenMetadataUrl = $"{mavenRepositoryUrl}/maven-metadata.xml";

            // Download and verify maven-metadata.xml
            var mavenMetadataPath = DownloadAndVerifyFile(mavenMetadataUrl, Path.GetTempPath(), withSignature: false);
            if (string.IsNullOrEmpty(mavenMetadataPath)) return;
            // Parse maven-metadata.xml to get the latest version
            var xmlDoc = new XmlDocument();
            xmlDoc.Load(mavenMetadataPath);
            var latestVersion = xmlDoc.SelectSingleNode("/metadata/versioning/latest")?.InnerText;

            // Download and verify JAR files
            var versionUrl = $"{mavenRepositoryUrl}/{latestVersion}/";
            var client = GetHttpClient();
            var response = client.GetAsync(versionUrl).Result;
            response.EnsureSuccessStatusCode();
            var htmlContent = response.Content.ReadAsStringAsync().Result;

            // Parse HTML content to get file links
            var parser = new HtmlParser();
            var htmlDoc = parser.ParseDocument(htmlContent);
            var fileLinks = htmlDoc.QuerySelectorAll("#contents > a").Select(e=>e.InnerHtml).Where(link=>link.EndsWith(".jar")).ToArray();

            foreach (var link in fileLinks)
            {
                var fileUrl = $"{versionUrl}{link}";

                // Download and verify file
                var filePath = DownloadAndVerifyFile(fileUrl, Path.GetTempPath());
                if (string.IsNullOrEmpty(filePath)) continue;
                // Move the file to the destination folder
                var destinationFolder = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs", "Saxonica");
                Directory.CreateDirectory(destinationFolder);
                File.Move(filePath, Path.Combine(destinationFolder, link));
            }
        }

        internal static string DownloadAndVerifyFile(string fileUrl, string downloadFolder, bool withSignature = true)
        {
            var client = GetHttpClient();
            var fileName = Path.GetFileName(fileUrl);
            var filePath = Path.Combine(downloadFolder, fileName);

            // Download the file
            var fileBytes = client.GetByteArrayAsync(fileUrl).Result;
            File.WriteAllBytes(filePath, fileBytes);

            // Verify file hashes
            return VerifyFileHashes(fileUrl, filePath) && (!withSignature || DownloadGpgSigAndVerify(fileUrl, filePath)) ? filePath : string.Empty;
        }

        private static HttpClient GetHttpClient()
        {
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
            return client;
        }

        internal static bool VerifyFileHashes(string fileUrl, string filePath)
        {
            string[] hashAlgorithms = ["md5", "sha1", "sha256", "sha512"];
            var hashesMatch = true;

            foreach (var hashAlgorithm in hashAlgorithms)
            {
                var hashUrl = $"{fileUrl}.{hashAlgorithm}";
                var client = GetHttpClient();
                var remoteHash = client.GetStringAsync(hashUrl).Result;

#pragma warning disable SYSLIB0045
                using var hashAlg = HashAlgorithm.Create(hashAlgorithm);
                var fileBytes = File.ReadAllBytes(filePath);
#pragma warning restore SYSLIB0045
                var localHash = BitConverter.ToString(hashAlg?.ComputeHash(fileBytes) ?? []).Replace("-", string.Empty).ToLowerInvariant();
                hashesMatch = hashesMatch && remoteHash == localHash;
                if (!hashesMatch) break;
            }

            return hashesMatch;
        }
        static bool VerifyGpg(string signatureFile, string downloadedFile)
        {
            var startInfo = new ProcessStartInfo()
            {
                FileName = GpgPath,
                Arguments = $"--auto-key-locate keyserver --keyserver hkps://keys.openpgp.org --keyserver-options auto-key-retrieve --verify \"{signatureFile}\" \"{downloadedFile}\"",
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };

            using var process = new Process();
            process.StartInfo = startInfo;
            process.Start();

            var output = process.StandardOutput.ReadToEnd();
            process.WaitForExit();

            return process.ExitCode == 0;
        }

        static bool DownloadGpgSigAndVerify(string fileUrl, string filePath)
        {
            var sigUrl = $"{fileUrl}.asc";
            var sigPath = Path.GetTempFileName();
            var client = GetHttpClient();
            var asciiSig = client.GetStringAsync(sigUrl).Result;
            File.WriteAllText(sigPath,asciiSig);
            return VerifyGpg(sigPath, filePath);
        }

        private static readonly string GpgPath = Path.Join(Environment.GetEnvironmentVariable("ProgramFiles(x86)"), "gnupg", "bin", "gpg.exe");
    }
}