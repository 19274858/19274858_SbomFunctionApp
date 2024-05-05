using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using System.Text.Json;

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

            string name = req.Query["name"];

            string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
            log.LogInformation("Request body {requestBody}", requestBody);
            string responseMessage = string.IsNullOrEmpty(name)
                ? "This HTTP triggered function executed successfully. Pass a name in the query string or in the request body for a personalized response."
                : $"Hello, {name}. This HTTP triggered function executed successfully.";

            //string jsonString = JsonSerializer.Serialize(responseMessage);
            //log.LogInformation("GenerateSbom request completed: {jsonString}", jsonString);
            return new OkObjectResult(requestBody);
        }
    }
}
