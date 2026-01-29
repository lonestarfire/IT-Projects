using System;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;
using Azure.Data.Tables;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Extensions.Logging;
using System.Net;
using System.Net.Http;

public class ReceiveWebhook
{
    private readonly ILogger _logger;
    private static readonly HttpClient httpClient = new HttpClient();

    public ReceiveWebhook(ILoggerFactory loggerFactory)
    {
        _logger = loggerFactory.CreateLogger<ReceiveWebhook>();
    }

    [Function("SweepUnprocessedWebhooks")]
    public async Task SweepUnprocessedWebhooks(
        [TimerTrigger("0 */4 * * * *")] TimerInfo timerInfo)
    {
        _logger.LogInformation($"Sweep function triggered at {DateTime.UtcNow:u}");

        string storageUri = Environment.GetEnvironmentVariable("STORAGE_ACCOUNT_URI");
        string storageKey = Environment.GetEnvironmentVariable("STORAGE_ACCOUNT_KEY");

        if (string.IsNullOrWhiteSpace(storageUri) || string.IsNullOrWhiteSpace(storageKey))
        {
            _logger.LogWarning("Storage configuration missing. Ensure STORAGE_ACCOUNT_URI and STORAGE_ACCOUNT_KEY are set.");
            return;
        }

        var accountName = storageUri.Split('.')[0].Replace("https://", "");
        var serviceClient = new TableServiceClient(new Uri(storageUri), new TableSharedKeyCredential(accountName, storageKey));

        var incomingTableName = Environment.GetEnvironmentVariable("INCOMING_WEBHOOK_TABLE") ?? "__STORAGE_TABLE_INCOMING__";
        var tableClient = serviceClient.GetTableClient(incomingTableName);

        bool hasUnprocessedWorkflowA = false;
        bool hasUnprocessedWorkflowB = false;

        try
        {
            var statusChangeQuery = tableClient.QueryAsync<TableEntity>(
                filter: $"ProcessedFlag eq false and Resource_Field eq 'Employee Status'",
                maxPerPage: 1);

            await foreach (var _ in statusChangeQuery)
            {
                hasUnprocessedWorkflowA = true;
                hasUnprocessedWorkflowB = true;
                break;
            }

            if (!hasUnprocessedWorkflowB)
            {
                var allUnprocessedQuery = tableClient.QueryAsync<TableEntity>(
                    filter: $"ProcessedFlag eq false",
                    maxPerPage: 1);

                await foreach (var _ in allUnprocessedQuery)
                {
                    hasUnprocessedWorkflowB = true;
                    break;
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError($"Error querying incoming webhook table: {ex.Message}");
            return;
        }

        if (hasUnprocessedWorkflowA)
        {
            _logger.LogInformation("Sweep found unprocessed status-change webhooks - triggering WorkflowA");
            await TriggerWorkflowDirect("WorkflowA", incomingTableName, "Sweep: Unprocessed status-change webhooks found");
        }

        if (hasUnprocessedWorkflowB)
        {
            _logger.LogInformation("Sweep found unprocessed webhooks - triggering WorkflowB");
            await TriggerWorkflowDirect("WorkflowB", incomingTableName, "Sweep: Unprocessed webhooks found");
        }

        if (!hasUnprocessedWorkflowA && !hasUnprocessedWorkflowB)
        {
            _logger.LogInformation("Sweep complete - no unprocessed webhooks found");
        }
    }

    private async Task TriggerWorkflowDirect(string workflowType, string tableName, string message)
    {
        try
        {
            string workflowUrl = workflowType == "WorkflowA"
                ? Environment.GetEnvironmentVariable("WORKFLOW_A_URL")
                : Environment.GetEnvironmentVariable("WORKFLOW_B_URL");

            if (string.IsNullOrWhiteSpace(workflowUrl))
            {
                _logger.LogWarning($"Workflow URL not configured for {workflowType} - skipping trigger");
                return;
            }

            var triggerPayload = new
            {
                triggerTime = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ"),
                source = "SweepUnprocessedWebhooks",
                message = message,
                tableName = tableName
            };

            var jsonPayload = JsonSerializer.Serialize(triggerPayload);
            using var content = new StringContent(jsonPayload, System.Text.Encoding.UTF8, "application/json");

            using var request = new HttpRequestMessage(HttpMethod.Post, workflowUrl) { Content = content };

            var authHeaderValue = Environment.GetEnvironmentVariable("WORKFLOW_SHARED_AUTH") ?? "__WORKFLOW_SHARED_AUTH__";
            request.Headers.Add("X-Webhook-Auth", authHeaderValue);

            var response = await httpClient.SendAsync(request);
            _logger.LogInformation($"Sweep triggered {workflowType} - Status: {response.StatusCode}");
        }
        catch (Exception ex)
        {
            _logger.LogError($"Sweep failed to trigger {workflowType}: {ex.Message}");
        }
    }

    [Function("ReceiveWebhook")]
    public async Task<HttpResponseData> Run(
        [HttpTrigger(AuthorizationLevel.Function, "post")] HttpRequestData req)
    {
        _logger.LogInformation("Webhook received.");

        string requestBody = await new StreamReader(req.Body).ReadToEndAsync();

        JsonDocument json;
        try
        {
            json = JsonDocument.Parse(requestBody);
        }
        catch (JsonException)
        {
            var badResponse = req.CreateResponse(HttpStatusCode.BadRequest);
            await badResponse.WriteStringAsync("Invalid JSON payload.");
            return badResponse;
        }

        string storageUri = Environment.GetEnvironmentVariable("STORAGE_ACCOUNT_URI");
        string storageKey = Environment.GetEnvironmentVariable("STORAGE_ACCOUNT_KEY");

        if (string.IsNullOrWhiteSpace(storageUri) || string.IsNullOrWhiteSpace(storageKey))
        {
            var badResponse = req.CreateResponse(HttpStatusCode.InternalServerError);
            await badResponse.WriteStringAsync("Server storage configuration is missing.");
            return badResponse;
        }

        var accountName = storageUri.Split('.')[0].Replace("https://", "");
        var serviceClient = new TableServiceClient(new Uri(storageUri), new TableSharedKeyCredential(accountName, storageKey));

        string eventId = null;
        string employeeNumber = null;
        string eventName = null;
        DateTimeOffset? eventDateTime = null;

        string resourceField = null;
        string resourceIdentifier = null;
        string obj = null;
        string endpoint = null;
        string endpointUrl = null;

        try
        {
            var root = json.RootElement;

            if (root.TryGetProperty("Event_Id", out var eventIdEl))
                eventId = eventIdEl.GetString();

            if (root.TryGetProperty("Object_Identifier", out var empEl))
            {
                if (empEl.ValueKind == JsonValueKind.String)
                    employeeNumber = empEl.GetString();
                else if (empEl.ValueKind == JsonValueKind.Number)
                    employeeNumber = empEl.GetInt32().ToString();
            }

            if (root.TryGetProperty("Event_Name", out var eventNameEl))
                eventName = eventNameEl.GetString();

            if (root.TryGetProperty("Event_DateTime", out var tsEl) && tsEl.TryGetInt64(out var unix))
                eventDateTime = DateTimeOffset.FromUnixTimeSeconds(unix);

            if (root.TryGetProperty("Resource_Field", out var resFieldEl))
                resourceField = resFieldEl.GetString();

            if (root.TryGetProperty("Resource_Identifier", out var resIdEl))
                resourceIdentifier = resIdEl.ValueKind == JsonValueKind.Null ? null : resIdEl.GetString();

            if (root.TryGetProperty("Object", out var objEl))
                obj = objEl.ValueKind == JsonValueKind.Null ? null : objEl.GetString();

            if (root.TryGetProperty("Endpoint", out var endpointEl))
                endpoint = endpointEl.GetString();

            if (root.TryGetProperty("EndpointUrl", out var endpointUrlEl))
                endpointUrl = endpointUrlEl.GetString();
        }
        catch (Exception ex)
        {
            _logger.LogWarning($"Failed to parse webhook payload: {ex.Message}");
        }

        bool isStatusChange = !string.IsNullOrWhiteSpace(resourceField) &&
                             resourceField.Equals("Employee Status", StringComparison.OrdinalIgnoreCase);

        var rowKey = !string.IsNullOrWhiteSpace(eventId) ? eventId : Guid.NewGuid().ToString();

        var entity = new TableEntity("Webhook", rowKey)
        {
            { "ReceivedAt", DateTimeOffset.UtcNow },
            { "EventId", eventId ?? string.Empty },
            { "EmployeeNumber", employeeNumber ?? string.Empty },
            { "EventName", eventName ?? string.Empty },
            { "EventDateTime", eventDateTime.HasValue ? (object)eventDateTime.Value : string.Empty },

            { "Resource_Field", resourceField ?? string.Empty },
            { "Resource_Identifier", resourceIdentifier ?? string.Empty },
            { "Object", obj ?? string.Empty },
            { "Endpoint", endpoint ?? string.Empty },
            { "EndpointUrl", endpointUrl ?? string.Empty },

            { "RawJson", requestBody },
            { "ProcessedFlag", false }
        };

        var incomingTableName = Environment.GetEnvironmentVariable("INCOMING_WEBHOOK_TABLE") ?? "__STORAGE_TABLE_INCOMING__";
        var tableClient = serviceClient.GetTableClient(incomingTableName);
        await tableClient.CreateIfNotExistsAsync();
        await tableClient.UpsertEntityAsync(entity);

        _logger.LogInformation($"Webhook queued - EventId: {eventId}, Employee: {employeeNumber}, Resource_Field: {resourceField}");

        if (isStatusChange)
        {
            var shouldTriggerA = await CheckAndUpdateTriggerThrottle(serviceClient, "WorkflowA");
            if (shouldTriggerA)
            {
                _ = TriggerWorkflow("WorkflowA", incomingTableName, "New status-change webhooks available");
            }

            var shouldTriggerB = await CheckAndUpdateTriggerThrottle(serviceClient, "WorkflowB");
            if (shouldTriggerB)
            {
                _ = TriggerWorkflow("WorkflowB", incomingTableName, "New status-change webhooks available");
            }
        }
        else
        {
            var shouldTriggerB = await CheckAndUpdateTriggerThrottle(serviceClient, "WorkflowB");
            if (shouldTriggerB)
            {
                _ = TriggerWorkflow("WorkflowB", incomingTableName, "New webhooks available");
            }
        }

        var response = req.CreateResponse(HttpStatusCode.Accepted);
        await response.WriteStringAsync("Webhook received and queued for processing.");
        return response;
    }

    private Task TriggerWorkflow(string workflowType, string tableName, string message)
    {
        return Task.Run(async () =>
        {
            try
            {
                string workflowUrl = workflowType == "WorkflowA"
                    ? Environment.GetEnvironmentVariable("WORKFLOW_A_URL")
                    : Environment.GetEnvironmentVariable("WORKFLOW_B_URL");

                if (string.IsNullOrWhiteSpace(workflowUrl))
                {
                    _logger.LogWarning($"Workflow URL not configured for {workflowType} - skipping trigger");
                    return;
                }

                var triggerPayload = new
                {
                    triggerTime = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ"),
                    source = "WebhookIngestFunction",
                    message = message,
                    tableName = tableName
                };

                var jsonPayload = JsonSerializer.Serialize(triggerPayload);
                using var content = new StringContent(jsonPayload, System.Text.Encoding.UTF8, "application/json");

                using var request = new HttpRequestMessage(HttpMethod.Post, workflowUrl) { Content = content };

                var authHeaderValue = Environment.GetEnvironmentVariable("WORKFLOW_SHARED_AUTH") ?? "__WORKFLOW_SHARED_AUTH__";
                request.Headers.Add("X-Webhook-Auth", authHeaderValue);

                await httpClient.SendAsync(request);
                _logger.LogInformation($"{workflowType} triggered successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Failed to trigger {workflowType}: {ex.Message}");
            }
        });
    }

    private async Task<bool> CheckAndUpdateTriggerThrottle(TableServiceClient serviceClient, string workflowType)
    {
        try
        {
            var throttleTableName = Environment.GetEnvironmentVariable("TRIGGER_THROTTLE_TABLE") ?? "__STORAGE_TABLE_THROTTLE__";
            var throttleTable = serviceClient.GetTableClient(throttleTableName);
            await throttleTable.CreateIfNotExistsAsync();

            var now = DateTime.UtcNow;
            var throttleKey = $"lastTrigger_{workflowType}";

            var throttleResponse = await throttleTable.GetEntityIfExistsAsync<TableEntity>("throttle", throttleKey);

            var shouldTrigger = false;

            if (!throttleResponse.HasValue)
            {
                shouldTrigger = true;
            }
            else
            {
                var lastTriggerTime = throttleResponse.Value.GetDateTime("LastTriggerTime");
                if (lastTriggerTime.HasValue)
                {
                    var timeSinceLastTrigger = now - lastTriggerTime.Value;
                    shouldTrigger = timeSinceLastTrigger.TotalMinutes >= 1.0;
                }
                else
                {
                    shouldTrigger = true;
                }
            }

            if (shouldTrigger)
            {
                var throttleEntity = new TableEntity("throttle", throttleKey)
                {
                    { "LastTriggerTime", now }
                };

                await throttleTable.UpsertEntityAsync(throttleEntity);
                _logger.LogInformation($"{workflowType} trigger throttle updated");
            }

            return shouldTrigger;
        }
        catch (Exception ex)
        {
            _logger.LogError($"Error checking trigger throttle for {workflowType}: {ex.Message}");
            return false;
        }
    }
}
