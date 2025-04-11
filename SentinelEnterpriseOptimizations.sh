Security Recommendations Checklist

 Implement Zero Trust architecture for all Sentinel components
 Use Azure Private DNS Zones for all private endpoints
 Configure service endpoints for Azure services (when Private Link is not available)
 Implement forced tunneling for all outbound internet traffic
 Use Azure DDoS Protection Standard for public endpoints
 Implement TLS inspection for all egress traffic
 Enable diagnostic settings for all network components
 Set up Azure Network Watcher for network monitoring
 Implement Traffic Analytics for network traffic analysis
 Configure Azure Firewall threat intelligence in Deny mode


# Cost Management Tools for Azure Sentinel Enterprise Repository

## Interactive Cost Calculator (HTML)

Save this as `tools/cost-calculator/sentinel-cost-calculator.html`:

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Enterprise Sentinel Cost Calculator</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            color: #333;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
        }
        h1, h2 {
            color: #0078d4;
        }
        .section {
            margin-bottom: 30px;
            padding: 20px;
            border: 1px solid #ddd;
            border-radius: 4px;
            background-color: #f9f9f9;
        }
        .input-group {
            margin-bottom: 15px;
        }
        label {
            display: block;
            margin-bottom: 5px;
            font-weight: 600;
        }
        input[type="number"], select {
            width: 100%;
            padding: 8px;
            border: 1px solid #ddd;
            border-radius: 4px;
            box-sizing: border-box;
        }
        .checkbox-group {
            margin-top: 10px;
        }
        button {
            background-color: #0078d4;
            color: white;
            border: none;
            padding: 10px 15px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
        }
        button:hover {
            background-color: #106ebe;
        }
        .results {
            margin-top: 20px;
            padding: 20px;
            border: 1px solid #ddd;
            border-radius: 4px;
            background-color: #f0f8ff;
        }
        .cost-breakdown {
            margin-top: 15px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #0078d4;
            color: white;
        }
        tr:nth-child(even) {
            background-color: #f2f2f2;
        }
        .info-icon {
            display: inline-block;
            width: 16px;
            height: 16px;
            background-color: #0078d4;
            color: white;
            border-radius: 50%;
            text-align: center;
            line-height: 16px;
            font-size: 12px;
            margin-left: 5px;
            cursor: help;
        }
        .tooltip {
            position: relative;
            display: inline-block;
        }
        .tooltip .tooltiptext {
            visibility: hidden;
            width: 250px;
            background-color: #333;
            color: #fff;
            text-align: center;
            border-radius: 6px;
            padding: 5px;
            position: absolute;
            z-index: 1;
            bottom: 125%;
            left: 50%;
            margin-left: -125px;
            opacity: 0;
            transition: opacity 0.3s;
        }
        .tooltip:hover .tooltiptext {
            visibility: visible;
            opacity: 1;
        }
        .comparison-chart {
            width: 100%;
            height: 400px;
            margin-top: 20px;
        }
        .savings {
            font-weight: bold;
            color: #107c10;
            font-size: 18px;
            margin-top: 10px;
        }
        .tabs {
            overflow: hidden;
            border: 1px solid #ccc;
            background-color: #f1f1f1;
            border-radius: 4px 4px 0 0;
        }
        .tabs button {
            background-color: inherit;
            float: left;
            border: none;
            outline: none;
            cursor: pointer;
            padding: 14px 16px;
            transition: 0.3s;
            font-size: 16px;
            color: #333;
        }
        .tabs button:hover {
            background-color: #ddd;
        }
        .tabs button.active {
            background-color: #0078d4;
            color: white;
        }
        .tabcontent {
            display: none;
            padding: 20px;
            border: 1px solid #ccc;
            border-top: none;
            border-radius: 0 0 4px 4px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Enterprise Azure Sentinel Cost Calculator</h1>
        <p>Use this calculator to estimate costs for different Azure Sentinel deployment architectures and optimize your security monitoring spend.</p>
        
        <div class="tabs">
            <button class="tablinks active" onclick="openTab(event, 'BasicCalculator')">Basic Calculator</button>
            <button class="tablinks" onclick="openTab(event, 'AdvancedCalculator')">Advanced Calculator</button>
            <button class="tablinks" onclick="openTab(event, 'ComparisonTab')">Architecture Comparison</button>
            <button class="tablinks" onclick="openTab(event, 'OptimizationTips')">Optimization Tips</button>
        </div>
        
        <!-- Basic Calculator Tab -->
        <div id="BasicCalculator" class="tabcontent" style="display:block;">
            <div class="section">
                <h2>Environment Configuration</h2>
                
                <div class="input-group">
                    <label for="numEndpoints">Number of Endpoints</label>
                    <input type="number" id="numEndpoints" min="0" value="1000">
                </div>
                
                <div class="input-group">
                    <label for="numUsers">Number of User Accounts</label>
                    <input type="number" id="numUsers" min="0" value="500">
                </div>
                
                <div class="input-group">
                    <label for="totalDailyGB">
                        Estimated Daily Data Volume (GB)
                        <div class="tooltip">
                            <span class="info-icon">i</span>
                            <span class="tooltiptext">Total amount of log data generated daily before any filtering</span>
                        </div>
                    </label>
                    <input type="number" id="totalDailyGB" min="0" step="0.1" value="50">
                </div>
                
                <div class="input-group">
                    <label for="architectureType">Architecture Type</label>
                    <select id="architectureType">
                        <option value="single">Single Workspace</option>
                        <option value="multi" selected>Multi-Workspace (Tiered)</option>
                        <option value="cluster">Log Analytics Cluster</option>
                    </select>
                </div>
                
                <div class="input-group">
                    <label for="defenderIntegration">Defender XDR Integration</label>
                    <select id="defenderIntegration">
                        <option value="alerts" selected>Alerts Only</option>
                        <option value="full">Full Raw Data</option>
                    </select>
                </div>
                
                <div class="input-group">
                    <label for="retentionDays">
                        Data Retention Period (Days)
                        <div class="tooltip">
                            <span class="info-icon">i</span>
                            <span class="tooltiptext">SOX compliance requires 2557 days (7 years)</span>
                        </div>
                    </label>
                    <input type="number" id="retentionDays" min="30" max="2557" value="90">
                </div>
                
                <button onclick="calculateCost()">Calculate Cost</button>
            </div>
            
            <div id="results" class="results" style="display:none;">
                <h2>Cost Estimate Results</h2>
                <div id="costSummary"></div>
                
                <div class="cost-breakdown">
                    <h3>Monthly Cost Breakdown</h3>
                    <table id="costBreakdownTable">
                        <thead>
                            <tr>
                                <th>Component</th>
                                <th>Data Volume (GB)</th>
                                <th>Unit Price ($)</th>
                                <th>Monthly Cost ($)</th>
                            </tr>
                        </thead>
                        <tbody id="costBreakdownBody">
                        </tbody>
                    </table>
                </div>
                
                <div class="savings" id="savings"></div>
            </div>
        </div>
        
        <!-- Advanced Calculator Tab -->
        <div id="AdvancedCalculator" class="tabcontent">
            <div class="section">
                <h2>Advanced Configuration</h2>
                
                <div class="input-group">
                    <label for="advNumEndpoints">Number of Endpoints</label>
                    <input type="number" id="advNumEndpoints" min="0" value="5000">
                </div>
                
                <div class="input-group">
                    <label for="advNumUsers">Number of User Accounts</label>
                    <input type="number" id="advNumUsers" min="0" value="15000">
                </div>
                
                <!-- Data volumes by source -->
                <h3>Daily Data Volume by Source (GB)</h3>
                
                <div class="input-group">
                    <label for="securityEventsGB">Windows Security Events</label>
                    <input type="number" id="securityEventsGB" min="0" step="0.1" value="200">
                </div>
                
                <div class="input-group">
                    <label for="syslogGB">Linux Syslog</label>
                    <input type="number" id="syslogGB" min="0" step="0.1" value="50">
                </div>
                
                <div class="input-group">
                    <label for="defenderGB">Defender for Endpoint</label>
                    <input type="number" id="defenderGB" min="0" step="0.1" value="500">
                </div>
                
                <div class="input-group">
                    <label for="azureLogsGB">Azure Activity & Resource Logs</label>
                    <input type="number" id="azureLogsGB" min="0" step="0.1" value="20">
                </div>
                
                <div class="input-group">
                    <label for="networkLogsGB">Network Logs (Firewall, NSG, etc.)</label>
                    <input type="number" id="networkLogsGB" min="0" step="0.1" value="100">
                </div>
                
                <div class="input-group">
                    <label for="otherLogsGB">Other Logs</label>
                    <input type="number" id="otherLogsGB" min="0" step="0.1" value="50">
                </div>
                
                <!-- Architecture configuration -->
                <h3>Architecture Configuration</h3>
                
                <div class="input-group">
                    <label for="advArchitectureType">Base Architecture</label>
                    <select id="advArchitectureType">
                        <option value="single">Single Workspace</option>
                        <option value="multi" selected>Multi-Workspace (Tiered)</option>
                        <option value="cluster">Log Analytics Cluster</option>
                    </select>
                </div>
                
                <div class="input-group">
                    <label for="filteringEfficiency">
                        Filtering Efficiency (%)
                        <div class="tooltip">
                            <span class="info-icon">i</span>
                            <span class="tooltiptext">Percentage of data filtered out before ingestion to Sentinel workspace</span>
                        </div>
                    </label>
                    <input type="number" id="filteringEfficiency" min="0" max="99" value="80">
                </div>
                
                <div class="input-group">
                    <label for="clusterReservationGB">
                        LA Cluster Capacity Reservation (GB/day)
                        <div class="tooltip">
                            <span class="info-icon">i</span>
                            <span class="tooltiptext">Only applicable for LA Cluster architecture</span>
                        </div>
                    </label>
                    <input type="number" id="clusterReservationGB" min="1000" step="100" value="1500">
                </div>
                
                <div class="input-group">
                    <label for="clusterDiscount">
                        Cluster Discount (%)
                        <div class="tooltip">
                            <span class="info-icon">i</span>
                            <span class="tooltiptext">Typically 15-25% discount on ingestion with LA Cluster</span>
                        </div>
                    </label>
                    <input type="number" id="clusterDiscount" min="0" max="30" value="25">
                </div>
                
                <!-- Compliance settings -->
                <h3>Compliance Configuration</h3>
                
                <div class="input-group">
                    <label for="complianceType">Compliance Requirements</label>
                    <select id="complianceType">
                        <option value="none">None</option>
                        <option value="sox" selected>SOX (7-year retention)</option>
                        <option value="gdpr">GDPR</option>
                        <option value="pci">PCI-DSS</option>
                    </select>
                </div>
                
                <div class="input-group">
                    <label for="longTermStorageCost">
                        Long-term Storage Cost ($/GB/Month)
                        <div class="tooltip">
                            <span class="info-icon">i</span>
                            <span class="tooltiptext">Cost for archived data in Azure Storage</span>
                        </div>
                    </label>
                    <input type="number" id="longTermStorageCost" min="0" step="0.001" value="0.01">
                </div>
                
                <button onclick="calculateAdvancedCost()">Calculate Detailed Cost</button>
            </div>
            
            <div id="advResults" class="results" style="display:none;">
                <h2>Detailed Cost Estimate</h2>
                <div id="advCostSummary"></div>
                
                <div class="cost-breakdown">
                    <h3>Monthly Cost Breakdown</h3>
                    <table id="advCostBreakdownTable">
                        <thead>
                            <tr>
                                <th>Component</th>
                                <th>Data Volume (GB/Month)</th>
                                <th>Unit Price ($)</th>
                                <th>Monthly Cost ($)</th>
                            </tr>
                        </thead>
                        <tbody id="advCostBreakdownBody">
                        </tbody>
                    </table>
                </div>
                
                <div class="cost-breakdown">
                    <h3>Annual Cost Projection</h3>
                    <table id="annualCostTable">
                        <thead>
                            <tr>
                                <th>Year</th>
                                <th>Estimated Annual Cost ($)</th>
                                <th>Cumulative Storage (TB)</th>
                                <th>Notes</th>
                            </tr>
                        </thead>
                        <tbody id="annualCostBody">
                        </tbody>
                    </table>
                </div>
                
                <div class="savings" id="advSavings"></div>
            </div>
        </div>
        
        <!-- Comparison Tab -->
        <div id="ComparisonTab" class="tabcontent">
            <div class="section">
                <h2>Architecture Cost Comparison</h2>
                <p>Compare the costs of different Azure Sentinel architectures based on your data volume and requirements.</p>
                
                <div class="input-group">
                    <label for="compNumEndpoints">Number of Endpoints</label>
                    <input type="number" id="compNumEndpoints" min="0" value="5000">
                </div>
                
                <div class="input-group">
                    <label for="compDailyDataGB">Daily Data Volume (GB)</label>
                    <input type="number" id="compDailyDataGB" min="0" step="1" value="1000">
                </div>
                
                <div class="input-group">
                    <label for="compRetentionDays">Retention Period (Days)</label>
                    <input type="number" id="compRetentionDays" min="30" max="2557" value="2557">
                </div>
                
                <div class="checkbox-group">
                    <label><input type="checkbox" id="includeRawDefender" checked> Include Raw Defender Data</label>
                </div>
                
                <button onclick="compareArchitectures()">Compare Architectures</button>
            </div>
            
            <div id="comparisonResults" class="results" style="display:none;">
                <h2>Architecture Comparison Results</h2>
                
                <table id="architectureComparisonTable">
                    <thead>
                        <tr>
                            <th>Architecture</th>
                            <th>Monthly Cost ($)</th>
                            <th>Annual Cost ($)</th>
                            <th>Key Benefits</th>
                            <th>Limitations</th>
                        </tr>
                    </thead>
                    <tbody id="architectureComparisonBody">
                    </tbody>
                </table>
                
                <div class="comparison-chart" id="comparisonChart"></div>
                
                <div id="architectureRecommendation" class="section">
                    <h3>Recommendation</h3>
                    <p id="recommendationText"></p>
                </div>
            </div>
        </div>
        
        <!-- Optimization Tips Tab -->
        <div id="OptimizationTips" class="tabcontent">
            <div class="section">
                <h2>Cost Optimization Strategies</h2>
                
                <h3>Data Tiering Strategies</h3>
                <ul>
                    <li><strong>Use the multi-workspace architecture</strong> - Keep critical security alerts in the Analytics tier and verbose logs in the Basic tier.</li>
                    <li><strong>Implement DCR transformations</strong> - Filter data before ingestion to reduce volume.</li>
                    <li><strong>Use Alert-Only integration for Defender XDR</strong> - Avoid duplicating data from Microsoft Defender.</li>
                    <li><strong>Export compliance data to cheaper storage</strong> - Use Azure Storage Archive tier for long-term retention.</li>
                </ul>
                
                <h3>Capacity Reservation Guidance</h3>
                <p>Log Analytics Cluster with capacity reservation becomes cost-effective at different thresholds:</p>
                <table>
                    <thead>
                        <tr>
                            <th>Daily Data Volume</th>
                            <th>Recommendation</th>
                            <th>Estimated Savings</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td>&lt; 100 GB/day</td>
                            <td>Pay-as-you-go with multi-workspace architecture</td>
                            <td>N/A</td>
                        </tr>
                        <tr>
                            <td>100-500 GB/day</td>
                            <td>Capacity Reservation in regular workspace</td>
                            <td>~10%</td>
                        </tr>
                        <tr>
                            <td>500-1000 GB/day</td>
                            <td>Consider Log Analytics Cluster</td>
                            <td>~15%</td>
                        </tr>
                        <tr>
                            <td>&gt; 1000 GB/day</td>
                            <td>Log Analytics Cluster highly recommended</td>
                            <td>20-25%</td>
                        </tr>
                    </tbody>
                </table>
                
                <h3>High-Impact Optimization Techniques</h3>
                <ol>
                    <li><strong>Defender XDR Alert-Only Integration</strong> - Up to 90% cost reduction vs. full data ingestion</li>
                    <li><strong>Security Event Filtering</strong> - Target 70-80% volume reduction through smart filtering</li>
                    <li><strong>Table-Level Retention</strong> - Apply different retention periods based on data importance</li>
                    <li><strong>Basic/Auxiliary Tier Usage</strong> - Save 73% on ingestion costs for compliance and reference data</li>
                    <li><strong>Log Analytics Cluster</strong> - Save up to 25% with volume discount</li>
                </ol>
                
                <h3>Query Optimization for Cost Reduction</h3>
                <p>Optimize queries to reduce compute costs:</p>
                <ul>
                    <li>Limit time ranges as much as possible</li>
                    <li>Filter early in queries</li>
                    <li>Use summarize and project operators to reduce data processed</li>
                    <li>Create materialized views for frequently queried data</li>
                </ul>
                
                <h3>Regular Review Process</h3>
                <p>Implement a monthly review cycle to identify optimization opportunities:</p>
                <ol>
                    <li>Review ingestion volume by table</li>
                    <li>Identify tables with high volume but low query frequency</li>
                    <li>Adjust DCR transformations to optimize filtering</li>
                    <li>Review and adjust capacity reservations</li>
                    <li>Validate compliance with retention requirements</li>
                </ol>
            </div>
        </div>
    </div>

    <script>
        // Tab navigation function
        function openTab(evt, tabName) {
            var i, tabcontent, tablinks;
            tabcontent = document.getElementsByClassName("tabcontent");
            for (i = 0; i < tabcontent.length; i++) {
                tabcontent[i].style.display = "none";
            }
            tablinks = document.getElementsByClassName("tablinks");
            for (i = 0; i < tablinks.length; i++) {
                tablinks[i].className = tablinks[i].className.replace(" active", "");
            }
            document.getElementById(tabName).style.display = "block";
            evt.currentTarget.className += " active";
        }
        
        // Basic Calculator Functions
        function calculateCost() {
            // Get input values
            const numEndpoints = parseInt(document.getElementById('numEndpoints').value) || 0;
            const numUsers = parseInt(document.getElementById('numUsers').value) || 0;
            const totalDailyGB = parseFloat(document.getElementById('totalDailyGB').value) || 0;
            const architectureType = document.getElementById('architectureType').value;
            const defenderIntegration = document.getElementById('defenderIntegration').value;
            const retentionDays = parseInt(document.getElementById('retentionDays').value) || 90;
            
            // Constants
            const analyticsPrice = 2.76; // $ per GB
            const basicPrice = 0.74; // $ per GB
            const sentinelCapabilityPrice = 0.25; // $ per GB
            
            // Calculated values
            let monthlyCost = 0;
            let costBreakdown = [];
            let defenderRawGB = 0;
            let criticalEventsGB = 0;
            let verboseEventsGB = 0;
            
            // Estimated data volumes based on endpoints and users
            if (defenderIntegration === 'full') {
                defenderRawGB = numEndpoints * 0.5; // 0.5 GB per endpoint per month for raw Defender data
            }
            
            criticalEventsGB = totalDailyGB * 0.2 * 30; // 20% of events are critical, monthly
            verboseEventsGB = totalDailyGB * 0.8 * 30; // 80% of events are verbose, monthly
            
            // Calculate costs based on architecture
            if (architectureType === 'single') {
                // Single workspace architecture
                const totalMonthlyGB = criticalEventsGB + verboseEventsGB + defenderRawGB;
                const dataIngestionCost = totalMonthlyGB * analyticsPrice;
                const sentinelCapabilityCost = totalMonthlyGB * sentinelCapabilityPrice;
                
                monthlyCost = dataIngestionCost + sentinelCapabilityCost;
                
                costBreakdown = [
                    {
                        component: "Log Analytics Ingestion (Analytics Tier)",
                        dataVolume: totalMonthlyGB.toFixed(2),
                        unitPrice: analyticsPrice.toFixed(2),
                        monthlyCost: dataIngestionCost.toFixed(2)
                    },
                    {
                        component: "Sentinel Capability",
                        dataVolume: totalMonthlyGB.toFixed(2),
                        unitPrice: sentinelCapabilityPrice.toFixed(2),
                        monthlyCost: sentinelCapabilityCost.toFixed(2)
                    }
                ];
            } else if (architectureType === 'multi') {
                // Multi-workspace tiered architecture
                const sentinelWorkspaceGB = criticalEventsGB + defenderRawGB;
                const verboseWorkspaceGB = verboseEventsGB;
                
                const sentinelIngestionCost = sentinelWorkspaceGB * analyticsPrice;
                const verboseIngestionCost = verboseWorkspaceGB * basicPrice;
                const sentinelCapabilityCost = sentinelWorkspaceGB * sentinelCapabilityPrice;
                
                monthlyCost = sentinelIngestionCost + verboseIngestionCost + sentinelCapabilityCost;
                
                costBreakdown = [
                    {
                        component: "Sentinel Workspace Ingestion (Analytics Tier)",
                        dataVolume: sentinelWorkspaceGB.toFixed(2),
                        unitPrice: analyticsPrice.toFixed(2),
                        monthlyCost: sentinelIngestionCost.toFixed(2)
                    },
                    {
                        component: "Verbose Workspace Ingestion (Basic Tier)",
                        dataVolume: verboseWorkspaceGB.toFixed(2),
                        unitPrice: basicPrice.toFixed(2),
                        monthlyCost: verboseIngestionCost.toFixed(2)
                    },
                    {
                        component: "Sentinel Capability",
                        dataVolume: sentinelWorkspaceGB.toFixed(2),
                        unitPrice: sentinelCapabilityPrice.toFixed(2),
                        monthlyCost: sentinelCapabilityCost.toFixed(2)
                    }
                ];
            } else if (architectureType === 'cluster') {
                // Log Analytics Cluster
                const clusterDiscount = 0.25; // 25% discount
                const discountedAnalyticsPrice = analyticsPrice * (1 - clusterDiscount);
                const discountedBasicPrice = basicPrice * (1 - clusterDiscount);
                
                const sentinelWorkspaceGB = criticalEventsGB + defenderRawGB;
                const verboseWorkspaceGB = verboseEventsGB;
                
                const sentinelIngestionCost = sentinelWorkspaceGB * discountedAnalyticsPrice;
                const verboseIngestionCost = verboseWorkspaceGB * discountedBasicPrice;
                const sentinelCapabilityCost = sentinelWorkspaceGB * sentinelCapabilityPrice;
                
                monthlyCost = sentinelIngestionCost + verboseIngestionCost + sentinelCapabilityCost;
                
                costBreakdown = [
                    {
                        component: "Sentinel Workspace Ingestion (with Cluster)",
                        dataVolume: sentinelWorkspaceGB.toFixed(2),
                        unitPrice: discountedAnalyticsPrice.toFixed(2),
                        monthlyCost: sentinelIngestionCost.toFixed(2)
                    },
                    {
                        component: "Verbose Workspace Ingestion (with Cluster)",
                        dataVolume: verboseWorkspaceGB.toFixed(2),
                        unitPrice: discountedBasicPrice.toFixed(2),
                        monthlyCost: verboseIngestionCost.toFixed(2)
                    },
                    {
                        component: "Sentinel Capability",
                        dataVolume: sentinelWorkspaceGB.toFixed(2),
                        unitPrice: sentinelCapabilityPrice.toFixed(2),
                        monthlyCost: sentinelCapabilityCost.toFixed(2)
                    }
                ];
            }
            
            // Display results
            document.getElementById('results').style.display = 'block';
            document.getElementById('costSummary').innerHTML = `
                <p>Estimated monthly cost: <strong>$${monthlyCost.toFixed(2)}</strong></p>
                <p>Estimated annual cost: <strong>$${(monthlyCost * 12).toFixed(2)}</strong></p>
            `;
            
            // Generate cost breakdown table
            const costBreakdownBody = document.getElementById('costBreakdownBody');
            costBreakdownBody.innerHTML = '';
            
            let totalMonthlyCost = 0;
            
            costBreakdown.forEach(item => {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${item.component}</td>
                    <td>${item.dataVolume}</td>
                    <td>$${item.unitPrice}</td>
                    <td>$${item.monthlyCost}</td>
                `;
                costBreakdownBody.appendChild(row);
                totalMonthlyCost += parseFloat(item.monthlyCost);
            });
            
            // Add total row
            const totalRow = document.createElement('tr');
            totalRow.style.fontWeight = 'bold';
            totalRow.innerHTML = `
                <td>Total</td>
                <td></td>
                <td></td>
                <td>$${totalMonthlyCost.toFixed(2)}</td>
            `;
            costBreakdownBody.appendChild(totalRow);
            
            // Calculate savings compared to single workspace
            if (architectureType !== 'single') {
                // Calculate single workspace cost for comparison
                const totalMonthlyGB = criticalEventsGB + verboseEventsGB + defenderRawGB;
                const singleWorkspaceCost = (totalMonthlyGB * analyticsPrice) + (totalMonthlyGB * sentinelCapabilityPrice);
                
                const savings = singleWorkspaceCost - monthlyCost;
                const savingsPercentage = (savings / singleWorkspaceCost) * 100;
                
                document.getElementById('savings').innerHTML = `
                    <p>Savings compared to single workspace: <strong>$${savings.toFixed(2)}</strong> per month (${savingsPercentage.toFixed(2)}%)</p>
                `;
            } else {
                document.getElementById('savings').innerHTML = '';
            }
        }
        
        // Additional functions for Advanced Calculator, Comparison, etc. would go here
        // For brevity, they are not included in this example
        
        // Initialize the calculator with default values
        document.addEventListener('DOMContentLoaded', function() {
            // Set default active tab
            document.getElementById('BasicCalculator').style.display = 'block';
            
            // Calculate initial values
            calculateCost();
        });
    </script>
</body>
</html>
Cost Optimization Analysis Script
Save this as src/scripts/maintenance/cost-optimization-analyzer.sh:
bash#!/bin/bash
# Azure Sentinel Cost Optimization Analysis Script
# This script analyzes Sentinel workspace usage and provides optimization recommendations

# Set color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Set defaults
DAYS_TO_ANALYZE=30
THRESHOLD_HIGH_VOLUME_TABLE=10 # GB per day
THRESHOLD_LOW_QUERY_TABLE=5 # queries per day
ANALYTICS_TIER_PRICE=2.76
BASIC_TIER_PRICE=0.74

# Parse command line arguments
while [[ $# -gt 0 ]]; do
  key="$1"
  case $key in
    -g|--resource-group)
      RESOURCE_GROUP="$2"
      shift
      shift
      ;;
    -p|--prefix)
      PREFIX="$2"
      shift
      shift
      ;;
    -d|--days)
      DAYS_TO_ANALYZE="$2"
      shift
      shift
      ;;
    -h|--help)
      echo "Usage: cost-optimization-analyzer.sh -g <resource-group> -p <prefix> [-d <days-to-analyze>]"
      echo ""
      echo "Options:"
      echo "  -g, --resource-group   Resource group containing the Sentinel workspaces"
      echo "  -p, --prefix           Prefix used for resource naming"
      echo "  -d, --days             Number of days to analyze (default: 30)"
      echo "  -h, --help             Show this help message"
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
done

# Verify required parameters
if [ -z "$RESOURCE_GROUP" ] || [ -z "$PREFIX" ]; then
  echo -e "${RED}Error: resource group and prefix are required.${NC}"
  echo "Usage: cost-optimization-analyzer.sh -g <resource-group> -p <prefix> [-d <days-to-analyze>]"
  exit 1
fi

# Define workspace names
SENTINEL_WS="${PREFIX}-sentinel-ws"
VERBOSE_WS="${PREFIX}-verbose-ws"
STAGING_WS="${PREFIX}-staging-ws"

# Check if Azure CLI is installed and logged in
if ! command -v az &> /dev/null; then
  echo -e "${RED}Error: Azure CLI is not installed. Please install it and try again.${NC}"
  exit 1
fi

# Check if jq is installed
if ! command -v jq &> /dev/null; then
  echo -e "${RED}Error: jq is not installed. Please install it and try again.${NC}"
  exit 1
fi

# Check if az account show returns successfully (logged in)
if ! az account show &> /dev/null; then
  echo -e "${RED}Error: Not logged in to Azure. Please run 'az login' first.${NC}"
  exit 1
fi

echo -e "${BLUE}========== Azure Sentinel Cost Optimization Analysis ==========${NC}"
echo -e "${BLUE}Resource Group:${NC} $RESOURCE_GROUP"
echo -e "${BLUE}Analyzing:${NC} $DAYS_TO_ANALYZE days of data"
echo -e "${BLUE}=================================================${NC}"

# Validate workspaces exist
echo -e "${CYAN}Validating workspaces...${NC}"

SENTINEL_WS_EXISTS=$(az monitor log-analytics workspace show --workspace-name $SENTINEL_WS --resource-group $RESOURCE_GROUP &> /dev/null && echo "true" || echo "false")
VERBOSE_WS_EXISTS=$(az monitor log-analytics workspace show --workspace-name $VERBOSE_WS --resource-group $RESOURCE_GROUP &> /dev/null && echo "true" || echo "false")
STAGING_WS_EXISTS=$(az monitor log-analytics workspace show --workspace-name $STAGING_WS --resource-group $RESOURCE_GROUP &> /dev/null && echo "true" || echo "false")

if [ "$SENTINEL_WS_EXISTS" == "false" ]; then
  echo -e "${RED}Error: Sentinel workspace '$SENTINEL_WS' not found in resource group '$RESOURCE_GROUP'.${NC}"
  exit 1
fi

echo -e "${GREEN}✓ Sentinel workspace:${NC} $SENTINEL_WS"

if [ "$VERBOSE_WS_EXISTS" == "true" ]; then
  echo -e "${GREEN}✓ Verbose workspace:${NC} $VERBOSE_WS"
else
  echo -e "${YELLOW}⚠ Warning: Verbose workspace '$VERBOSE_WS' not found. Analysis will focus on Sentinel workspace only.${NC}"
fi

if [ "$STAGING_WS_EXISTS" == "true" ]; then
  echo -e "${GREEN}✓ Staging workspace:${NC} $STAGING_WS"
else
  echo -e "${YELLOW}⚠ Warning: Staging workspace '$STAGING_WS' not found.${NC}"
fi

echo -e "${BLUE}------------------------------------------------${NC}"
echo -e "${CYAN}Analyzing data volume by table...${NC}"

# Helper function to query log analytics and handle errors
run_query() {
  local workspace=$1
  local query=$2
  local result

  result=$(az monitor log-analytics query \
    --workspace "$workspace" \
    --analytics-query "$query" \
    --resource-group "$RESOURCE_GROUP" \
    --output json 2>/dev/null)
  
  # Check for errors
  if [ $? -ne 0 ]; then
    echo -e "${RED}Error executing query on workspace $workspace.${NC}"
    return 1
  fi
  
  echo "$result"
}

# Query to analyze data volume by table in Sentinel workspace
SENTINEL_VOLUME_QUERY="
Usage
| where TimeGenerated > ago(${DAYS_TO_ANALYZE}d)
| summarize TotalGB=sum(Quantity)/1000 by DataType
| project DataType, TotalGB, DailyGB=TotalGB/${DAYS_TO_ANALYZE}
| sort by TotalGB desc
"

# Run the query
SENTINEL_VOLUME_RESULT=$(run_query "$SENTINEL_WS" "$SENTINEL_VOLUME_QUERY")
if [ $? -ne 0 ]; then
  exit 1
fi

# Process results for Sentinel workspace
SENTINEL_TOTAL_GB=$(echo "$SENTINEL_VOLUME_RESULT" | jq -r 'map(.TotalGB) | add')
SENTINEL_DAILY_GB=$(echo "$SENTINEL_VOLUME_RESULT" | jq -r 'map(.DailyGB) | add')

echo -e "${GREEN}Sentinel workspace total ingestion:${NC} ${SENTINEL_TOTAL_GB:.2f} GB over $DAYS_TO_ANALYZE days"
echo -e "${GREEN}Sentinel workspace daily average:${NC} ${SENTINEL_DAILY_GB:.2f} GB/day"

# Identify high-volume tables
HIGH_VOLUME_TABLES=$(echo "$SENTINEL_VOLUME_RESULT" | jq -r --arg threshold "$THRESHOLD_HIGH_VOLUME_TABLE" '[.[] | select(.DailyGB >= ($threshold | tonumber))]')
HIGH_VOLUME_COUNT=$(echo "$HIGH_VOLUME_TABLES" | jq -r 'length')

echo -e "${BLUE}------------------------------------------------${NC}"
echo -e "${CYAN}High volume tables (>${THRESHOLD_HIGH_VOLUME_TABLE} GB/day):${NC}"

if [ "$HIGH_VOLUME_COUNT" -gt 0 ]; then
  # Format high volume tables as a table
  echo -e "Table Name\tDaily GB\tTotal GB\tPotential Monthly Savings"
  echo -e "---------\t--------\t--------\t----------------------"
  
  # Calculate potential savings for each high volume table
  echo "$HIGH_VOLUME_TABLES" | jq -r --arg analytics "$ANALYTICS_TIER_PRICE" --arg basic "$BASIC_TIER_PRICE" '.[] | "\(.DataType)\t\(.DailyGB | tonumber | floor * 100 / 100)\t\(.TotalGB | tonumber | floor * 100 / 100)\t$\((.DailyGB | tonumber) * 30 * (($analytics | tonumber) - ($basic | tonumber)) | floor * 100 / 100)"' | sort -k2 -nr
else
  echo -e "${GREEN}No high volume tables found.${NC}"
fi

# Query to analyze query frequency by table
QUERY_FREQUENCY_QUERY="
_LogOperation
| where TimeGenerated > ago(${DAYS_TO_ANALYZE}d)
| where Operation == \"SearchLog\"
| extend Table = tostring(split(Detail, \"|\")[0])
| where isnotempty(Table)
| summarize QueryCount=count() by Table
| project Table, QueryCount, DailyQueries=QueryCount/${DAYS_TO_ANALYZE}
| sort by QueryCount desc
"

# Run the query
QUERY_FREQUENCY_RESULT=$(run_query "$SENTINEL_WS" "$QUERY_FREQUENCY_QUERY")
if [ $? -ne 0 ]; then
  echo -e "${YELLOW}⚠ Warning: Could not analyze query frequency. Continuing with partial analysis.${NC}"
else
  # Find tables with high volume but low query frequency
  echo -e "${BLUE}------------------------------------------------${NC}"
  echo -e "${CYAN}Tables with high volume but low query frequency:${NC}"
  
  # Join the two result sets
  HIGH_VOL_LOW_QUERY=$(echo "$SENTINEL_VOLUME_RESULT" "$QUERY_FREQUENCY_RESULT" | jq -rs --arg high_threshold "$THRESHOLD_HIGH_VOLUME_TABLE" --arg low_threshold "$THRESHOLD_LOW_QUERY_TABLE" '
    .[0] as $volume | .[1] as $queries |
    $volume | map(
      . as $v | 
      $queries[] | select(.Table == $v.DataType) as $q |
      if $q then
        $v + {
          QueryCount: ($q.QueryCount // 0),
          DailyQueries: ($q.DailyQueries // 0)
        }
      else
        $v + {
          QueryCount: 0,
          DailyQueries: 0
        }
      end
    ) |
    map(select(
      .DailyGB >= ($high_threshold | tonumber) and
      .DailyQueries <= ($low_threshold | tonumber)
    )) |
    sort_by(-.DailyGB)
  ')
  
  HIGH_VOL_LOW_QUERY_COUNT=$(echo "$HIGH_VOL_LOW_QUERY" | jq -r 'length')
  
  if [ "$HIGH_VOL_LOW_QUERY_COUNT" -gt 0 ]; then
    echo -e "Table Name\tDaily GB\tDaily Queries\tRecommendation"
    echo -e "---------\t--------\t-------------\t-------------"
    
    echo "$HIGH_VOL_LOW_QUERY" | jq -r '.[] | "\(.DataType)\t\(.DailyGB | tonumber | floor * 100 / 100)\t\(.DailyQueries | tonumber | floor * 100 / 100)\tMove to Basic tier workspace"'
  else
    echo -e "${GREEN}No tables found with high volume and low query frequency.${NC}"
  fi
fi

# If verbose workspace exists, analyze cross-workspace data for duplication
if [ "$VERBOSE_WS_EXISTS" == "true" ]; then
  echo -e "${BLUE}------------------------------------------------${NC}"
  echo -e "${CYAN}Analyzing data distribution between workspaces...${NC}"
  
  # Query to get verbose workspace volume
  VERBOSE_VOLUME_QUERY="
  Usage
  | where TimeGenerated > ago(${DAYS_TO_ANALYZE}d)
  | summarize TotalGB=sum(Quantity)/1000 by DataType
  | project DataType, TotalGB, DailyGB=TotalGB/${DAYS_TO_ANALYZE}
  | sort by TotalGB desc
  "
  
  # Run the query
  VERBOSE_VOLUME_RESULT=$(run_query "$VERBOSE_WS" "$VERBOSE_VOLUME_QUERY")
  if [ $? -ne 0 ]; then
    echo -e "${YELLOW}⚠ Warning: Could not analyze verbose workspace data. Skipping cross-workspace analysis.${NC}"
  else
    # Process results for Verbose workspace
    VERBOSE_TOTAL_GB=$(echo "$VERBOSE_VOLUME_RESULT" | jq -r 'map(.TotalGB) | add')
    VERBOSE_DAILY_GB=$(echo "$VERBOSE_VOLUME_RESULT" | jq -r 'map(.DailyGB) | add')
    
    echo -e "${GREEN}Verbose workspace total ingestion:${NC} ${VERBOSE_TOTAL_GB:.2f} GB over $DAYS_TO_ANALYZE days"
    echo -e "${GREEN}Verbose workspace daily average:${NC} ${VERBOSE_DAILY_GB:.2f} GB/day"
    
    # Find tables that exist in both workspaces and compare volumes
    echo -e "${BLUE}------------------------------------------------${NC}"
    echo -e "${CYAN}Tables in both workspaces (potential duplication):${NC}"
    
    COMMON_TABLES=$(echo "$SENTINEL_VOLUME_RESULT" "$VERBOSE_VOLUME_RESULT" | jq -rs '
      .[0] as $sentinel | .[1] as $verbose |
      $sentinel | map(
        . as $s | 
        $verbose[] | select(.DataType == $s.DataType) as $v |
        if $v then
          {
            DataType: $s.DataType,
            SentinelGB: $s.TotalGB,
            VerboseGB: $v.TotalGB,
            Ratio: ($s.TotalGB / $v.TotalGB)
          }
        else
          null
        end
      ) |
      map(select(. != null)) |
      sort_by(-.Ratio)
    ')
    
    COMMON_TABLES_COUNT=$(echo "$COMMON_TABLES" | jq -r 'length')
    
    if [ "$COMMON_TABLES_COUNT" -gt 0 ]; then
      echo -e "Table Name\tSentinel GB\tVerbose GB\tSentinel/Verbose Ratio\tRecommendation"
      echo -e "---------\t-----------\t----------\t---------------------\t-------------"
      
      echo "$COMMON_TABLES" | jq -r '.[] | 
        "\(.DataType)\t\(.SentinelGB | tonumber | floor * 100 / 100)\t\(.VerboseGB | tonumber | floor * 100 / 100)\t\(.Ratio | tonumber | floor * 100 / 100)\t\(
          if .Ratio >= 0.8 then 
            "Potential full duplication - optimize DCR"
          elif .Ratio >= 0.3 then
            "Partial duplication - review filtering"
          else
            "Good tiering ratio"
          end
        )"
      ' | sort -k4 -nr
    else
      echo -e "${GREEN}No tables found in both workspaces.${NC}"
    fi
  fi
fi

# Calculate cost estimates and potential savings
echo -e "${BLUE}=================================================${NC}"
echo -e "${CYAN}Cost Analysis and Optimization Recommendations${NC}"

# Calculate current costs
SENTINEL_MONTHLY_COST=$(echo "$SENTINEL_DAILY_GB * $ANALYTICS_TIER_PRICE * 30" | bc)
VERBOSE_MONTHLY_COST=0
if [ "$VERBOSE_WS_EXISTS" == "true" ]; then
  VERBOSE_MONTHLY_COST=$(echo "$VERBOSE_DAILY_GB * $BASIC_TIER_PRICE * 30" | bc)
fi

TOTAL_MONTHLY_COST=$(echo "$SENTINEL_MONTHLY_COST + $VERBOSE_MONTHLY_COST" | bc)

# Calculate potential optimized cost based on identified opportunities
OPTIMIZED_SENTINEL_GB=$SENTINEL_DAILY_GB
OPTIMIZED_VERBOSE_GB=$VERBOSE_DAILY_GB

if [ "$HIGH_VOL_LOW_QUERY_COUNT" -gt 0 ]; then
  # Calculate total GB that could be moved from Sentinel to Verbose
  MOVABLE_GB=$(echo "$HIGH_VOL_LOW_QUERY" | jq -r 'map(.DailyGB) | add')
  
  # Update optimized volumes
  OPTIMIZED_SENTINEL_GB=$(echo "$OPTIMIZED_SENTINEL_GB - $MOVABLE_GB" | bc)
  OPTIMIZED_VERBOSE_GB=$(echo "$OPTIMIZED_VERBOSE_GB + $MOVABLE_GB" | bc)
fi

# Calculate optimized costs
OPTIMIZED_SENTINEL_COST=$(echo "$OPTIMIZED_SENTINEL_GB * $ANALYTICS_TIER_PRICE * 30" | bc)
OPTIMIZED_VERBOSE_COST=$(echo "$OPTIMIZED_VERBOSE_GB * $BASIC_TIER_PRICE * 30" | bc)
OPTIMIZED_TOTAL_COST=$(echo "$OPTIMIZED_SENTINEL_COST + $OPTIMIZED_VERBOSE_COST" | bc)

# Calculate savings
MONTHLY_SAVINGS=$(echo "$TOTAL_MONTHLY_COST - $OPTIMIZED_TOTAL_COST" | bc)
ANNUAL_SAVINGS=$(echo "$MONTHLY_SAVINGS * 12" | bc)
SAVINGS_PERCENTAGE=$(echo "scale=2; $MONTHLY_SAVINGS * 100 / $TOTAL_MONTHLY_COST" | bc)

echo -e "${BLUE}Current Monthly Cost:${NC} \$$TOTAL_MONTHLY_COST"
echo -e "  - Sentinel Workspace: \$$SENTINEL_MONTHLY_COST"
if [ "$VERBOSE_WS_EXISTS" == "true" ]; then
  echo -e "  - Verbose Workspace:  \$$VERBOSE_MONTHLY_COST"
fi

if [ $(echo "$MONTHLY_SAVINGS > 0" | bc) -eq 1 ]; then
  echo -e "${BLUE}Potential Optimized Monthly Cost:${NC} \$$OPTIMIZED_TOTAL_COST"
  echo -e "${GREEN}Potential Monthly Savings:${NC} \$$MONTHLY_SAVINGS (${SAVINGS_PERCENTAGE}%)"
  echo -e "${GREEN}Potential Annual Savings:${NC} \$$ANNUAL_SAVINGS"
else
  echo -e "${GREEN}Your current configuration appears to be well optimized.${NC}"
fi

echo -e "${BLUE}=================================================${NC}"
echo -e "${CYAN}Key Recommendations:${NC}"

# Generate list of recommendations
RECOMMENDATIONS=()

if [ "$HIGH_VOL_LOW_QUERY_COUNT" -gt 0 ]; then
  RECOMMENDATIONS+=("Move ${HIGH_VOL_LOW_QUERY_COUNT} high-volume, low-query tables to the Basic tier workspace.")
fi

if [ $(echo "$COMMON_TABLES_COUNT > 0" | bc) -eq 1 ]; then
  HIGH_DUPLICATION_COUNT=$(echo "$COMMON_TABLES" | jq -r '[.[] | select(.Ratio >= 0.8)] | length')
  if [ "$HIGH_DUPLICATION_COUNT" -gt 0 ]; then
    RECOMMENDATIONS+=("Review DCR filtering for ${HIGH_DUPLICATION_COUNT} tables with potential full duplication.")
  fi
fi

if [ $(echo "$SENTINEL_DAILY_GB > 1000" | bc) -eq 1 ]; then
  RECOMMENDATIONS+=("Consider implementing a Log Analytics Cluster for volume discounts (potential 25% savings).")
fi

if [ $(echo "$VERBOSE_DAILY_GB > 0" | bc) -ne 1 ]; then
  RECOMMENDATIONS+=("Implement a multi-workspace architecture to reduce costs by up to 73% for verbose logs.")
fi

if [ $(echo "$SENTINEL_DAILY_GB > 100" | bc) -eq 1 ]; then
  RECOMMENDATIONS+=("Review Sentinel capabilities pricing for potential volume discounts.")
fi

# Additional Defender XDR recommendation
DEFENDER_TABLE_COUNT=$(echo "$SENTINEL_VOLUME_RESULT" | jq -r '[.[] | select(.DataType | contains("Defender") or contains("Security"))] | length')
if [ "$DEFENDER_TABLE_COUNT" -gt 0 ]; then
  RECOMMENDATIONS+=("Review Defender XDR integration strategy - consider alert-only integration instead of raw data ingestion.")
fi

# Print recommendations
if [ ${#RECOMMENDATIONS[@]} -eq 0 ]; then
  echo -e "${GREEN}Your Sentinel environment appears to be well optimized. Continue monitoring usage patterns.${NC}"
else
  for i in "${!RECOMMENDATIONS[@]}"; do
    echo -e "${GREEN}$(($i+1)).${NC} ${RECOMMENDATIONS[$i]}"
  done
fi

echo -e "${BLUE}=================================================${NC}"
echo -e "${CYAN}Next Steps:${NC}"
echo -e "1. Run KQL queries to identify specific optimization opportunities"
echo -e "2. Implement recommended DCR transformations to optimize data routing"
echo -e "3. Schedule this analysis to run monthly to track optimization progress"
echo -e "${BLUE}=================================================${NC}"
