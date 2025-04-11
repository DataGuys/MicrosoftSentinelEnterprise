<#
.SYNOPSIS
Analyzes Azure Sentinel query execution patterns and provides cost optimization recommendations.

.DESCRIPTION
This script connects to Azure Monitor logs and analyzes query patterns to identify:
- High-cost scheduled queries
- Redundant data ingestion
- Optimization opportunities for cross-workspace queries
It then provides recommendations to reduce query costs and overall Azure Sentinel spend.

.PARAMETER ResourceGroup
Resource group containing the Sentinel workspaces

.PARAMETER Prefix
Prefix used for resource naming

.PARAMETER DaysToAnalyze
Number of days of query history to analyze (default: 30)

.PARAMETER OutputPath
Path where the analysis report will be saved (default: current directory)

.EXAMPLE
.\batch-query-optimizer.ps1 -ResourceGroup "rg-sentinel-enterprise" -Prefix "sec" -DaysToAnalyze 14

.NOTES
This script requires:
- PowerShell 7.0 or higher
- Az PowerShell module
- Azure CLI
- Contributor access to the Azure Sentinel workspaces
#>

param (
    [Parameter(Mandatory = $true)]
    [string]$ResourceGroup,
    
    [Parameter(Mandatory = $true)]
    [string]$Prefix,
    
    [Parameter(Mandatory = $false)]
    [int]$DaysToAnalyze = 30,
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = (Get-Location).Path
)

# Check for required modules and tools
function CheckPrerequisites {
    # Check PowerShell version
    if ($PSVersionTable.PSVersion.Major -lt 7) {
        Write-Error "PowerShell 7.0 or higher is required. Current version: $($PSVersionTable.PSVersion)"
        exit 1
    }
    
    # Check for Az module
    if (-not (Get-Module -ListAvailable -Name Az.OperationalInsights)) {
        Write-Warning "Az.OperationalInsights module not found. Installing..."
        Install-Module -Name Az.OperationalInsights -Force -AllowClobber
    }
    
    # Check for Azure CLI
    try {
        $azVersion = (az version | ConvertFrom-Json).'azure-cli'
        Write-Host "Azure CLI version: $azVersion"
    }
    catch {
        Write-Error "Azure CLI not found or not working properly. Please install it and try again."
        exit 1
    }
    
    # Check if logged into Azure
    try {
        $account = az account show | ConvertFrom-Json
        Write-Host "Logged in as: $($account.user.name) (Subscription: $($account.name))"
    }
    catch {
        Write-Error "Not logged into Azure. Please run 'az login' first."
        exit 1
    }
}

# Set workspace names based on prefix
$sentinelWorkspace = "$Prefix-sentinel-ws"
$verboseWorkspace = "$Prefix-verbose-ws"
$stagingWorkspace = "$Prefix-staging-ws"

# Verify workspaces exist
function ValidateWorkspaces {
    Write-Host "Validating workspaces..." -ForegroundColor Cyan
    
    # Check Sentinel workspace
    try {
        $sentinel = az monitor log-analytics workspace show --workspace-name $sentinelWorkspace --resource-group $ResourceGroup | ConvertFrom-Json
        Write-Host "✓ Sentinel workspace: $sentinelWorkspace" -ForegroundColor Green
        $global:sentinelWorkspaceId = $sentinel.id
    }
    catch {
        Write-Error "Sentinel workspace '$sentinelWorkspace' not found in resource group '$ResourceGroup'."
        exit 1
    }
    
    # Check Verbose workspace
    try {
        $verbose = az monitor log-analytics workspace show --workspace-name $verboseWorkspace --resource-group $ResourceGroup | ConvertFrom-Json
        Write-Host "✓ Verbose workspace: $verboseWorkspace" -ForegroundColor Green
        $global:verboseWorkspaceExists = $true
        $global:verboseWorkspaceId = $verbose.id
    }
    catch {
        Write-Warning "Verbose workspace '$verboseWorkspace' not found. Analysis will focus on Sentinel workspace only."
        $global:verboseWorkspaceExists = $false
    }
    
    # Check Staging workspace
    try {
        $staging = az monitor log-analytics workspace show --workspace-name $stagingWorkspace --resource-group $ResourceGroup | ConvertFrom-Json
        Write-Host "✓ Staging workspace: $stagingWorkspace" -ForegroundColor Green
        $global:stagingWorkspaceExists = $true
        $global:stagingWorkspaceId = $staging.id
    }
    catch {
        Write-Warning "Staging workspace '$stagingWorkspace' not found."
        $global:stagingWorkspaceExists = $false
    }
}

# Execute KQL query on a workspace
function Invoke-KqlQuery {
    param (
        [string]$WorkspaceId,
        [string]$Query
    )
    
    try {
        $result = az monitor log-analytics query `
            --workspace $WorkspaceId `
            --analytics-query $Query `
            --output json
        
        return $result | ConvertFrom-Json
    }
    catch {
        Write-Error "Error executing query on workspace $WorkspaceId: $_"
        return $null
    }
}

# Analyze scheduled queries and their cost
function Analyze-ScheduledQueries {
    Write-Host "Analyzing scheduled queries..." -ForegroundColor Cyan
    
    $query = @"
    _LogOperation
    | where TimeGenerated > ago($DaysToAnalyze d)
    | where Operation == "RunScheduledSearch"
    | extend SearchId = tostring(split(Detail, ":", 1)[0])
    | join kind=inner (
        _LogOperation
        | where TimeGenerated > ago($DaysToAnalyze d)
        | where Operation == "SearchLog"
        | extend SearchId = tostring(split(Detail, ":", 1)[0])
        | extend ResponseTime = Duration
        | extend ScanBytes = toreal(split(Detail, ":", 3)[0])
        | project TimeGenerated, SearchId, ResponseTime, ScanBytes
    ) on SearchId
    | project TimeGenerated, SearchId, ResponseTime, ScanBytes
    | summarize 
        ExecutionCount = count(),
        AvgResponseTime = avg(ResponseTime),
        AvgScanBytes = avg(ScanBytes),
        TotalScanBytes = sum(ScanBytes),
        TotalScanGB = sum(ScanBytes) / (1024 * 1024 * 1024)
    by SearchId
    | extend DailyScanGB = TotalScanGB / $DaysToAnalyze
    | extend QueryCost = TotalScanGB * 0.006 // Assume $0.006 per GB for query processing
    | sort by TotalScanGB desc
"@
    
    $results = Invoke-KqlQuery -WorkspaceId $global:sentinelWorkspaceId -Query $query
    
    if ($null -eq $results -or $results.Count -eq 0) {
        Write-Warning "No scheduled query data found or no queries executed in the analysis period."
        return @()
    }
    
    # Identify high-cost queries
    $highCostQueries = $results | Where-Object { $_.QueryCost -gt 5 } # $5 threshold
    
    # Create report
    Write-Host "Found $($results.Count) scheduled queries, with $($highCostQueries.Count) high-cost queries." -ForegroundColor Yellow
    
    if ($highCostQueries.Count -gt 0) {
        Write-Host "Top 5 highest cost queries:" -ForegroundColor Yellow
        $highCostQueries | Select-Object -First 5 | Format-Table SearchId, ExecutionCount, @{Name="AvgScanGB";Expression={[math]::Round($_.AvgScanBytes / (1024 * 1024 * 1024), 2)}}, @{Name="QueryCost";Expression={[math]::Round($_.QueryCost, 2)}}
    }
    
    # Generate optimization recommendations
    $recommendations = @()
    
    foreach ($query in $highCostQueries) {
        if ($query.ExecutionCount -gt 100 && $query.TotalScanGB -gt 50) {
            $recommendations += @{
                QueryId = $query.SearchId
                Type = "High frequency, high volume"
                Recommendation = "Consider reducing query frequency or limiting time range"
                PotentialSavings = [math]::Round($query.QueryCost * 0.5, 2) # Assume 50% optimization potential
            }
        }
        elseif ($query.AvgScanBytes / (1024 * 1024 * 1024) -gt 10) {
            $recommendations += @{
                QueryId = $query.SearchId
                Type = "Large data scan"
                Recommendation = "Add more filters or reduce time range"
                PotentialSavings = [math]::Round($query.QueryCost * 0.7, 2) # Assume 70% optimization potential
            }
        }
    }
    
    return $recommendations
}

# Analyze cross-workspace query patterns
function Analyze-CrossWorkspaceQueries {
    Write-Host "Analyzing cross-workspace query patterns..." -ForegroundColor Cyan
    
    if (-not $global:verboseWorkspaceExists) {
        Write-Warning "Verbose workspace not found. Skipping cross-workspace query analysis."
        return @()
    }
    
    $query = @"
    _LogOperation
    | where TimeGenerated > ago($DaysToAnalyze d)
    | where Operation == "SearchLog"
    | where Detail has "workspace("
    | extend CrossWorkspace = true
    | project TimeGenerated, Detail, CrossWorkspace, ResponseTime = Duration, ScanBytes
    | summarize 
        QueryCount = count(),
        AvgResponseTime = avg(ResponseTime),
        TotalScanBytes = sum(ScanBytes),
        TotalScanGB = sum(ScanBytes) / (1024 * 1024 * 1024)
    | extend DailyScanGB = TotalScanGB / $DaysToAnalyze
    | extend QueryCost = TotalScanGB * 0.006 // Assume $0.006 per GB for query processing
"@
    
    $results = Invoke-KqlQuery -WorkspaceId $global:sentinelWorkspaceId -Query $query
    
    if ($null -eq $results -or $results.Count -eq 0) {
        Write-Warning "No cross-workspace queries found in the analysis period."
        return @()
    }
    
    Write-Host "Cross-workspace query statistics:" -ForegroundColor Yellow
    Write-Host "Total queries: $($results[0].QueryCount)" -ForegroundColor Yellow
    Write-Host "Total data scanned: $([math]::Round($results[0].TotalScanGB, 2)) GB" -ForegroundColor Yellow
    Write-Host "Average response time: $([math]::Round($results[0].AvgResponseTime, 2)) ms" -ForegroundColor Yellow
    Write-Host "Estimated cost: `$$([math]::Round($results[0].QueryCost, 2))" -ForegroundColor Yellow
    
    # Generate optimization recommendations
    $recommendations = @()
    
    if ($results[0].QueryCount -gt 100 && $results[0].TotalScanGB -gt 50) {
        $recommendations += @{
            Type = "High volume cross-workspace querying"
            Recommendation = "Consider materializing frequently accessed cross-workspace data with scheduled analytics rules"
            PotentialSavings = [math]::Round($results[0].QueryCost * 0.6, 2) # Assume 60% optimization potential
        }
    }
    
    if ($results[0].AvgResponseTime -gt 5000) { # 5 seconds
        $recommendations += @{
            Type = "Slow cross-workspace queries"
            Recommendation = "Optimize query patterns with time filtering and materialized views"
            PotentialSavings = "Improved performance and user experience"
        }
    }
    
    return $recommendations
}

# Analyze workspace data distribution
function Analyze-DataDistribution {
    Write-Host "Analyzing data distribution between workspaces..." -ForegroundColor Cyan
    
    if (-not $global:verboseWorkspaceExists) {
        Write-Warning "Verbose workspace not found. Skipping data distribution analysis."
        return @()
    }
    
    # Query for Sentinel workspace
    $sentinelQuery = @"
    Usage
    | where TimeGenerated > ago($DaysToAnalyze d)
    | summarize TotalGB = sum(Quantity) / 1000 by DataType
    | project DataType, SentinelGB = TotalGB, DailyGB = TotalGB / $DaysToAnalyze
    | sort by SentinelGB desc
"@
    
    # Query for Verbose workspace
    $verboseQuery = @"
    Usage
    | where TimeGenerated > ago($DaysToAnalyze d)
    | summarize TotalGB = sum(Quantity) / 1000 by DataType
    | project DataType, VerboseGB = TotalGB, DailyGB = TotalGB / $DaysToAnalyze
    | sort by VerboseGB desc
"@
    
    $sentinelResults = Invoke-KqlQuery -WorkspaceId $global:sentinelWorkspaceId -Query $sentinelQuery
    $verboseResults = Invoke-KqlQuery -WorkspaceId $global:verboseWorkspaceId -Query $verboseQuery
    
    if ($null -eq $sentinelResults -or $sentinelResults.Count -eq 0) {
        Write-Warning "No data found in Sentinel workspace for the analysis period."
        return @()
    }
    
    if ($null -eq $verboseResults -or $verboseResults.Count -eq 0) {
        Write-Warning "No data found in Verbose workspace for the analysis period."
        return @()
    }
    
    # Calculate total ingestion
    $sentinelTotalGB = ($sentinelResults | Measure-Object -Property SentinelGB -Sum).Sum
    $verboseTotalGB = ($verboseResults | Measure-Object -Property VerboseGB -Sum).Sum
    
    Write-Host "Data distribution summary:" -ForegroundColor Yellow
    Write-Host "Sentinel workspace total: $([math]::Round($sentinelTotalGB, 2)) GB" -ForegroundColor Yellow
    Write-Host "Verbose workspace total: $([math]::Round($verboseTotalGB, 2)) GB" -ForegroundColor Yellow
    Write-Host "Total data ingestion: $([math]::Round($sentinelTotalGB + $verboseTotalGB, 2)) GB" -ForegroundColor Yellow
    
    # Find common tables between workspaces
    $commonTables = @()
    
    foreach ($sentinelTable in $sentinelResults) {
        $verboseTable = $verboseResults | Where-Object { $_.DataType -eq $sentinelTable.DataType }
        
        if ($null -ne $verboseTable) {
            $ratio = if ($verboseTable.VerboseGB -gt 0) { $sentinelTable.SentinelGB / $verboseTable.VerboseGB } else { 0 }
            
            $commonTables += [PSCustomObject]@{
                DataType = $sentinelTable.DataType
                SentinelGB = $sentinelTable.SentinelGB
                VerboseGB = $verboseTable.VerboseGB
                Ratio = $ratio
                TotalGB = $sentinelTable.SentinelGB + $verboseTable.VerboseGB
            }
        }
    }
    
    $commonTables = $commonTables | Sort-Object -Property TotalGB -Descending
    
    if ($commonTables.Count -gt 0) {
        Write-Host "Found $($commonTables.Count) tables in both workspaces." -ForegroundColor Yellow
        Write-Host "Top 5 largest common tables:" -ForegroundColor Yellow
        $commonTables | Select-Object -First 5 | Format-Table DataType, @{Name="SentinelGB";Expression={[math]::Round($_.SentinelGB, 2)}}, @{Name="VerboseGB";Expression={[math]::Round($_.VerboseGB, 2)}}, @{Name="Ratio";Expression={[math]::Round($_.Ratio, 2)}}
    }
    
    # Generate optimization recommendations
    $recommendations = @()
    
    # Check for high duplication (similar volumes in both workspaces)
    $highDuplicationTables = $commonTables | Where-Object { $_.Ratio -gt 0.7 -and $_.Ratio -lt 1.3 -and $_.TotalGB -gt 10 }
    
    if ($highDuplicationTables.Count -gt 0) {
        $duplicatedGB = ($highDuplicationTables | Measure-Object -Property SentinelGB -Sum).Sum
        $potentialSavings = $duplicatedGB * 2.76 # Analytics tier price per GB
        
        $recommendations += @{
            Type = "Data duplication"
            Description = "$($highDuplicationTables.Count) tables with significant duplication between workspaces"
            AffectedTables = $highDuplicationTables.DataType -join ", "
            Recommendation = "Review DCR transformations to prevent duplication"
            PotentialSavings = [math]::Round($potentialSavings, 2)
        }
    }
    
    # Check for tables that should be in the verbose workspace
    $highVolumeTables = $sentinelResults | Where-Object { $_.SentinelGB -gt 50 }
    
    if ($highVolumeTables.Count -gt 0) {
        $movableGB = ($highVolumeTables | Measure-Object -Property SentinelGB -Sum).Sum
        $potentialSavings = $movableGB * (2.76 - 0.74) # Price difference between Analytics and Basic tier
        
        $recommendations += @{
            Type = "Tier optimization"
            Description = "$($highVolumeTables.Count) high-volume tables in Analytics tier"
            AffectedTables = ($highVolumeTables | Select-Object -First 3 -ExpandProperty DataType) -join ", " + $(if ($highVolumeTables.Count -gt 3) { "..." } else { "" })
            Recommendation = "Move non-critical high-volume tables to Basic tier"
            PotentialSavings = [math]::Round($potentialSavings * 0.7, 2) # Assume 70% can be moved
        }
    }
    
    return $recommendations
}

# Generate optimization report
function Generate-Report {
    param (
        [array]$QueryRecommendations,
        [array]$CrossWorkspaceRecommendations,
        [array]$DataDistributionRecommendations
    )
    
    $totalPotentialSavings = 0
    
    # Calculate total potential savings
    foreach ($rec in $QueryRecommendations) {
        if ($rec.PotentialSavings -is [double]) {
            $totalPotentialSavings += $rec.PotentialSavings
        }
    }
    
    foreach ($rec in $CrossWorkspaceRecommendations) {
        if ($rec.PotentialSavings -is [double]) {
            $totalPotentialSavings += $rec.PotentialSavings
        }
    }
    
    foreach ($rec in $DataDistributionRecommendations) {
        if ($rec.Potential
