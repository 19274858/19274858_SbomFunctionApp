using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using NuGet.Protocol;
using NuGet.Protocol.Core.Types;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;

namespace SbomFunctionApp
{
    internal class SBomJsonParser
    {
        private const string NuGetUrl = "https://api.nuget.org/v3/index.json";

        internal string GetVulnerabilityInfo(string sbomJsonString)
        {
            var currentLocation = Assembly.GetEntryAssembly()?.Location;
            var currentFolder = Path.GetDirectoryName(currentLocation);

            if (string.IsNullOrEmpty(currentFolder))
            {
                throw new Exception("Unable to get current directory");
            }

            var reader = new SbomJsonReader();
            var sboms = reader.ReadSbomJson(sbomJsonString, NuGetUrl);

            return JsonSerializer.Serialize(sboms);
        }
    }
   
    public class SbomJsonReader
    {
        public IEnumerable<SBom> ReadSbomJson(string sbomJsonString, string nuGetUrl)
        {
            var sbomObj = JObject.Parse(sbomJsonString);
            var sBomComponents = sbomObj.GetValue("components");
            var sBomComponentsArray = sBomComponents as JArray;
            var sboms = new SBom[sBomComponentsArray?.Count ?? 0];

            for (var i = 0; i < sboms.Length; i++)
            {
                Console.WriteLine(i);

                var sBomComponent = sBomComponentsArray?[i];
                if (sBomComponent is not JObject jObj) continue;

                var soup = jObj.GetValue("name")?.ToString();
                var version = jObj.GetValue("version")?.ToString();
                var lastVersion = GetLastStableVersion(soup, nuGetUrl);
                var vulnerabilityInfo = GetPackageVulnerabilityInfo(soup, version, nuGetUrl);
                
                sboms[i] = new SBom()
                {
                    Soup = soup,
                    Author = jObj.GetValue("author")?.ToString(),
                    LicenseType = GetLicenseInfo(soup, jObj),
                    LastStableVersion = lastVersion,
                    UsedVersion = jObj.GetValue("version")?.ToString(),
                    VulnerabilityInfo = vulnerabilityInfo,
                    ExternalReferences = GetExternalReferences(jObj),
                    Description = jObj.GetValue("description")?.ToString()
                };
            }

            return sboms;
        }


        /// <summary>
        /// Connecting to NuGet to extract last available package version
        /// </summary>
        /// <param name="packageName"></param>
        /// <param name="nuGetUrl"></param>
        /// <returns></returns>
        private string GetLastStableVersion(string packageName, string nuGetUrl)
        {

            // Create a NuGet source repository
            var sourceRepository = Repository.Factory.GetCoreV3(nuGetUrl);

            // Get the package metadata
            var metadataResource = sourceRepository.GetResource<PackageMetadataResource>();
            var metadata = metadataResource.GetMetadataAsync(packageName, 
                true, true, new SourceCacheContext(), NuGet.Common.NullLogger.Instance, CancellationToken.None).Result;

            // Find the latest stable version
            var latestStableVersion = metadata.Max(m => m.Identity.Version);

            return latestStableVersion?.Version.ToString();
        }
        private static IEnumerable<string> GetPackageVulnerabilityInfo(string packageName, string packageVersion, string nuGetUrl)
        {
            var nugetRepository = Repository.Factory.GetCoreV3(nuGetUrl);
            var packageMetadataResource = nugetRepository.GetResource<PackageMetadataResource>();
            var metadata = packageMetadataResource
                .GetMetadataAsync(packageName, true, true, new SourceCacheContext(), NuGet.Common.NullLogger.Instance, CancellationToken.None).Result;
            var package = metadata.FirstOrDefault(p => p.Identity.Version.ToString() == packageVersion);

            return package?.Vulnerabilities?.Select(x=>x.AdvisoryUrl.ToString());
        }

        private string GetExternalReferences(JObject sBomComponent)
        {
            if (sBomComponent.GetValue("externalReferences") is not JArray externalReferences || !externalReferences.Any())
            {
                return "Unable to parse a ExternalReferences";
            }
            var urls = externalReferences.Select(x => (x as JObject)?.GetValue("url")?.ToString()).ToArray();
            return string.Join(", ", urls);
        }
        private string GetLicenseInfo(string name, JObject sBomComponent)
        {
            var licenses = sBomComponent.GetValue("licenses") as JArray;
            if (licenses != null && (!licenses.Any() || licenses.Count != 1))
                throw new Exception($"Unable to parse a license for {name} component");

            if ((licenses?.FirstOrDefault() as JObject)?.GetValue("license") is not JObject license)
            {
                return "No license information found";
            }
            else if (license.TryGetValue("id", out var licenseId))
            {
                return licenseId.ToString();
            }
            else
            {
                var options = new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true,
                    PropertyNamingPolicy = JsonNamingPolicy.CamelCase
                };
                var yourObject = JsonSerializer.Deserialize<License>(license?.ToString() ?? string.Empty, options);

                return $"{yourObject.Name}, {yourObject.Url}";
            }

        }
    }
   
    public class License
    {
        public string Name { get; set; }
        public string Url { get; set; }
    }
    public class SBom
    {
        public string Soup { get; set; }
        public string Author { get; set; }
        public string LicenseType { get; set; }
        public string LastStableVersion { get; set; }
        public string UsedVersion { get; set; }
        public IEnumerable<string> VulnerabilityInfo { get; set; }
        public string Description { get; set; }
        public string ExternalReferences { get; set; }
    }

    //public class PackageVulnerability
    //{
    //    public PackageVulnerability(PackageVulnerabilityMetadata packageVulnerabilityMetadata)
    //    {
    //        AdvisoryUrl = packageVulnerabilityMetadata.AdvisoryUrl;
    //        Severity = packageVulnerabilityMetadata.Severity;
    //    }

    //    public PackageVulnerability()
    //    {

    //    }
    //    public Uri AdvisoryUrl { get; set; }

    //    /// <summary>
    //    /// 1. Low: Generally, these are less severe issues, and mitigations might be available without much effort.
    //    /// 2. Medium: These issues have a moderate impact and might require some attention.It's essential to address them but may not be as urgent as higher-severity issues.
    //    /// 3. High: High-severity issues are more critical and can have a significant impact on the security of the package.Prompt attention and remediation are usually necessary.
    //    /// 4. Critical: These are the most severe vulnerabilities.They pose a serious risk to the security of the package, and immediate action is required to address them.
    //    /// </summary>
    //    public int Severity { get; set; }
    //}
}
