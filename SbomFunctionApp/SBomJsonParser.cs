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
using Microsoft.Extensions.Logging;

namespace SbomFunctionApp
{
    internal class SBomJsonParser
    {
        private const string NuGetUrl = "https://api.nuget.org/v3/index.json";

        internal string GetVulnerabilityInfo(string sbomJsonString, ILogger log)
        {
            log.LogTrace("Started GetVulnerabilityInfo");
            var currentLocation = Assembly.GetEntryAssembly()?.Location;
            var currentFolder = Path.GetDirectoryName(currentLocation);
            
            if (string.IsNullOrEmpty(currentFolder))
            {
                throw new Exception("Unable to get current directory");
            }
            log.LogTrace($"currentLocation: {currentLocation}, currentFolder: {currentFolder}");

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
                var usedVersion = jObj.GetValue("version")?.ToString();
                var usedVersionVulnerabilityInfo = GetPackageVulnerabilityInfo(soup, usedVersion, nuGetUrl);
                var lastVersion = GetLastStableVersion(soup, nuGetUrl);
                var lastStableVersionVulnerabilityInfo = GetPackageVulnerabilityInfo(soup, lastVersion, nuGetUrl);

                sboms[i] = new SBom()
                {
                    Soup = soup,
                    Author = jObj.GetValue("author")?.ToString(),
                    LicenseType = GetLicenseInfo(soup, jObj),
                    LastStableVersion = lastVersion,
                    UsedVersion = jObj.GetValue("version")?.ToString(),
                    UsedVersionVulnerabilityInfo = usedVersionVulnerabilityInfo,
                    LastStableVersionVulnerabilityInfo = lastStableVersionVulnerabilityInfo,
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

            if (license.TryGetValue("id", out var licenseId))
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

        public string UsedVersion { get; set; }
        public IEnumerable<string> UsedVersionVulnerabilityInfo { get; set; }

        public string LastStableVersion { get; set; }
        public IEnumerable<string> LastStableVersionVulnerabilityInfo { get; set; }

        public string Description { get; set; }
        public string ExternalReferences { get; set; }
    }
}
