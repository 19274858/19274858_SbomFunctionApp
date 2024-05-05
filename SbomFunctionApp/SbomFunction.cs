using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using SbomFunctionApp;

namespace SbomServices
{
    public static class SbomFunction
    {
        [FunctionName("GenerateSbom")]
        public static async Task<IActionResult> GenerateSbom(
            [HttpTrigger(AuthorizationLevel.Function, "get", "post", Route = null)] HttpRequest req,
            ILogger log)
        {
            log.LogInformation("C# HTTP trigger function processed a request.");

            var requestBody = await new StreamReader(req.Body).ReadToEndAsync();
            log.LogInformation("Request body {requestBody}", requestBody);

            var sbomJsonParser = new SBomJsonParser();
            var sbom = sbomJsonParser.GetVulnerabilityInfo(requestBody);

            return new OkObjectResult(sbom);
        }
    }
}
