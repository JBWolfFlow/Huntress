# Phase 5 Monitoring and Alerting Guide

Comprehensive guide for monitoring the continuous learning system, configuring alerts, and interpreting metrics.

## Table of Contents

1. [Overview](#overview)
2. [Monitoring Architecture](#monitoring-architecture)
3. [Key Metrics](#key-metrics)
4. [Dashboard Usage](#dashboard-usage)
5. [Alert Configuration](#alert-configuration)
6. [Health Checks](#health-checks)
7. [Performance Baselines](#performance-baselines)
8. [Trend Analysis](#trend-analysis)
9. [Reporting](#reporting)
10. [Best Practices](#best-practices)

---

## Overview

The Phase 5 monitoring system provides real-time visibility into:
- Model performance and accuracy
- Training pipeline health
- System resource utilization
- Deployment status
- Data quality metrics
- Error rates and anomalies

### Monitoring Components

1. **Performance Monitor** - Tracks model success rates, FP rates, execution times
2. **Health Check System** - Monitors component health and system resources
3. **Training Dashboard** - Visual interface for real-time monitoring
4. **Alert System** - Automated notifications for critical issues
5. **Audit Logger** - Comprehensive event logging

---

## Monitoring Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Monitoring System                         │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ Performance  │  │    Health    │  │   Training   │      │
│  │   Monitor    │  │   Checker    │  │   Manager    │      │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘      │
│         │                  │                  │              │
│         └──────────────────┼──────────────────┘              │
│                            │                                 │
│                    ┌───────▼────────┐                        │
│                    │  Metrics Store │                        │
│                    │   (Qdrant)     │                        │
│                    └───────┬────────┘                        │
│                            │                                 │
│         ┌──────────────────┼──────────────────┐             │
│         │                  │                  │             │
│  ┌──────▼───────┐  ┌──────▼───────┐  ┌──────▼───────┐     │
│  │  Dashboard   │  │    Alerts    │  │   Reports    │     │
│  │   (React)    │  │   (Events)   │  │   (Files)    │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

---

## Key Metrics

### Performance Metrics

#### Success Rate
- **Description**: Percentage of successful vulnerability discoveries
- **Target**: ≥ 70%
- **Warning**: < 70%
- **Critical**: < 60%
- **Collection**: Per hunt execution
- **Retention**: 90 days

```typescript
// Access in code
const metrics = performanceMonitor.getCurrentMetrics();
console.log(`Success Rate: ${metrics.successRate * 100}%`);
```

#### False Positive Rate
- **Description**: Percentage of invalid findings
- **Target**: ≤ 10%
- **Warning**: > 10%
- **Critical**: > 20%
- **Collection**: Per hunt execution
- **Retention**: 90 days

#### Average Execution Time
- **Description**: Mean time to complete a hunt
- **Target**: ≤ 60 minutes
- **Warning**: > 90 minutes
- **Critical**: > 120 minutes
- **Collection**: Per hunt execution
- **Retention**: 90 days

#### Tool Efficiency
- **Description**: Average number of tools used per hunt
- **Target**: 4-6 tools
- **Warning**: > 8 tools
- **Collection**: Per hunt execution
- **Retention**: 30 days

### System Health Metrics

#### Component Health
- **Qdrant**: Database connectivity and response time
- **HTB API**: API availability and rate limits
- **GPU**: Availability, memory, temperature
- **Disk**: Available space and I/O performance
- **Memory**: Available RAM and swap usage
- **Model Manager**: Production model status
- **Learning Loop**: Training cycle status

#### Resource Utilization
- **CPU Usage**: Target < 80%
- **Memory Usage**: Target < 85%
- **GPU Memory**: Target < 90%
- **Disk Usage**: Target < 80%
- **Network I/O**: Monitor for bottlenecks

### Training Metrics

#### Data Quality
- **Quality Score**: Average quality of training examples
- **Target**: ≥ 0.7
- **Collection**: Per training cycle

#### Training Progress
- **Cycle Count**: Total training cycles completed
- **Success Rate**: Percentage of successful training cycles
- **Duration**: Average training cycle duration

#### Model Versions
- **Active Versions**: Count of models in each status
- **Deployment Frequency**: Deployments per week
- **Rollback Rate**: Percentage of deployments rolled back

---

## Dashboard Usage

### Accessing the Dashboard

```bash
# Start the application
npm run dev

# Navigate to dashboard
# http://localhost:5173/dashboard
```

### Dashboard Sections

#### 1. Current Metrics Cards
- Real-time performance indicators
- Color-coded status (green/yellow/red)
- Trend indicators (↑/↓/→)

**Interpretation:**
- **Green**: Metrics within target range
- **Yellow**: Approaching warning threshold
- **Red**: Critical threshold exceeded

#### 2. Training Status Panel
- Current learning loop status
- Training progress bar
- Manual control buttons

**Actions:**
- **Pause**: Temporarily halt training
- **Resume**: Continue paused training
- **Force Retrain**: Start immediate training cycle

#### 3. Performance Trends Chart
- 48-hour historical view
- Success rate, FP rate, tool usage
- Hover for detailed values

**Analysis:**
- Look for declining trends
- Identify anomalies or spikes
- Compare to baseline

#### 4. Resource Usage Chart
- 24-hour resource utilization
- Stacked area chart (CPU, Memory, GPU)
- Identify resource bottlenecks

#### 5. Model Versions Table
- All model versions and status
- Performance comparison
- Promotion controls

#### 6. Active Alerts
- Real-time alert notifications
- Severity-based color coding
- Acknowledgment controls

### Auto-Refresh Configuration

```typescript
// Configure refresh interval
setRefreshInterval(5000);  // 5 seconds
setRefreshInterval(30000); // 30 seconds
setRefreshInterval(60000); // 60 seconds

// Disable auto-refresh
setAutoRefresh(false);
```

---

## Alert Configuration

### Alert Levels

| Severity | Description | Response Time | Notification |
|----------|-------------|---------------|--------------|
| **Info** | Informational events | None | Log only |
| **Warning** | Potential issues | 1 hour | Dashboard |
| **Error** | Service degradation | 15 minutes | Dashboard + Log |
| **Critical** | System failure | Immediate | All channels |

### Alert Rules

Configure in [`config/monitoring.json`](../config/monitoring.json):

```json
{
  "alerting": {
    "rules": {
      "performanceDegradation": {
        "enabled": true,
        "severity": "high",
        "condition": "successRate < baseline * 0.85",
        "cooldown": 3600
      },
      "falsePositiveSpike": {
        "enabled": true,
        "severity": "medium",
        "condition": "falsePositiveRate > baseline + 5",
        "cooldown": 3600
      },
      "resourceExhaustion": {
        "enabled": true,
        "severity": "critical",
        "conditions": [
          "diskSpace < 10GB",
          "memory < 4GB",
          "gpuMemory > 95%"
        ],
        "cooldown": 1800
      }
    }
  }
}
```

### Alert Channels

#### Console Alerts
```json
{
  "channels": {
    "console": {
      "enabled": true,
      "minSeverity": "warning"
    }
  }
}
```

#### Log File Alerts
```json
{
  "channels": {
    "log": {
      "enabled": true,
      "minSeverity": "info",
      "path": "logs/alerts.log"
    }
  }
}
```

#### Email Alerts (Optional)
```json
{
  "channels": {
    "email": {
      "enabled": false,
      "minSeverity": "critical",
      "recipients": ["admin@example.com"],
      "smtpConfig": {
        "host": "smtp.example.com",
        "port": 587,
        "secure": false,
        "auth": {
          "user": "alerts@example.com",
          "pass": "password"
        }
      }
    }
  }
}
```

#### Webhook Alerts (Optional)
```json
{
  "channels": {
    "webhook": {
      "enabled": false,
      "minSeverity": "high",
      "url": "https://hooks.slack.com/services/YOUR/WEBHOOK/URL",
      "headers": {
        "Content-Type": "application/json"
      }
    }
  }
}
```

### Alert Escalation

```json
{
  "escalation": {
    "enabled": true,
    "levels": [
      {
        "severity": "critical",
        "delay": 0,
        "channels": ["console", "log", "email"]
      },
      {
        "severity": "high",
        "delay": 300,
        "channels": ["console", "log"]
      },
      {
        "severity": "medium",
        "delay": 900,
        "channels": ["log"]
      }
    ]
  }
}
```

---

## Health Checks

### Health Check Configuration

Configure in code or [`config/monitoring.json`](../config/monitoring.json):

```typescript
const healthConfig: HealthCheckConfig = {
  interval: 300, // 5 minutes
  timeout: 10000, // 10 seconds
  retries: 3,
  thresholds: {
    performanceDegradation: 10, // 10% drop
    errorRate: 5, // 5% error rate
    responseTime: 5000, // 5 seconds
    diskSpaceGB: 20,
    memoryGB: 8,
    gpuMemoryPercent: 90,
  },
  selfHealing: {
    enabled: true,
    maxAttempts: 3,
    cooldownSeconds: 300,
  },
  components: {
    htbAPI: true,
    qdrant: true,
    gpu: true,
    diskSpace: true,
    memory: true,
    trainingManager: true,
    modelManager: true,
    learningLoop: true,
    deploymentManager: true,
    performanceMonitor: true,
  },
};
```

### Running Health Checks

#### Manual Health Check
```typescript
import { HealthCheckSystem } from './src/core/training/health_checker';

const checker = new HealthCheckSystem(qdrant, healthConfig);
await checker.initialize();
const report = await checker.performHealthCheck();

console.log(`Overall Status: ${report.overallStatus}`);
console.log(`Healthy Components: ${report.metrics.healthyComponents}/${report.metrics.totalComponents}`);
```

#### Continuous Monitoring
```typescript
// Start continuous health monitoring
await checker.start();

// Listen for events
checker.on('check:completed', ({ report }) => {
  console.log('Health check completed:', report.overallStatus);
});

checker.on('alert:created', ({ alert }) => {
  console.log('Alert:', alert.severity, alert.message);
});

// Stop monitoring
checker.stop();
```

### Health Check Results

```typescript
interface SystemHealthReport {
  timestamp: Date;
  overallStatus: 'healthy' | 'degraded' | 'unhealthy' | 'unknown';
  components: ComponentHealth[];
  alerts: HealthAlert[];
  metrics: {
    totalComponents: number;
    healthyComponents: number;
    degradedComponents: number;
    unhealthyComponents: number;
    avgResponseTime: number;
  };
  recommendations: string[];
}
```

### Self-Healing Actions

The health checker can automatically attempt to fix issues:

1. **Qdrant Connection**: Reset connection
2. **Disk Space**: Clean old logs and temporary files
3. **Memory**: Trigger garbage collection
4. **GPU**: Clear GPU cache

Configure self-healing:
```typescript
selfHealing: {
  enabled: true,
  maxAttempts: 3,
  cooldownSeconds: 300, // 5 minutes between attempts
}
```

---

## Performance Baselines

### Establishing Baselines

Baselines are calculated from historical data (last 20 samples):

```typescript
const baseline = {
  successRate: 0.75,
  falsePositiveRate: 0.08,
  avgTimeToSuccess: 3600,
  avgToolsUsed: 5.2,
};
```

### Updating Baselines

Baselines automatically update as new data is collected. Manual adjustment:

```typescript
// Update baseline thresholds
const newBaseline = performanceMonitor.calculateBaseline();
console.log('New baseline:', newBaseline);
```

### Baseline Comparison

```typescript
const current = performanceMonitor.getCurrentMetrics();
const baseline = performanceMonitor.calculateBaseline();

const degradation = ((baseline.successRate - current.successRate) / baseline.successRate) * 100;

if (degradation > 10) {
  console.warn(`Performance degraded ${degradation.toFixed(1)}%`);
}
```

---

## Trend Analysis

### Analyzing Trends

```typescript
const trends = performanceMonitor.analyzeTrends(30); // Last 30 days

for (const trend of trends) {
  console.log(`${trend.metric}: ${trend.direction}`);
  console.log(`  Slope: ${trend.slope.toFixed(4)}`);
  console.log(`  Confidence: ${(trend.confidence * 100).toFixed(1)}%`);
  console.log(`  Prediction: ${trend.prediction.toFixed(2)}`);
}
```

### Trend Interpretation

| Direction | Meaning | Action |
|-----------|---------|--------|
| **Improving** | Metric trending positively | Monitor, document changes |
| **Declining** | Metric trending negatively | Investigate, take corrective action |
| **Stable** | No significant trend | Continue monitoring |

### Statistical Significance

Trends with confidence > 0.7 (70%) are considered statistically significant.

---

## Reporting

### Automated Reports

Configure in [`config/monitoring.json`](../config/monitoring.json):

```json
{
  "reporting": {
    "enabled": true,
    "schedule": {
      "daily": {
        "enabled": true,
        "time": "08:00",
        "timezone": "America/Chicago"
      },
      "weekly": {
        "enabled": true,
        "day": "monday",
        "time": "09:00"
      },
      "monthly": {
        "enabled": true,
        "day": 1,
        "time": "10:00"
      }
    },
    "formats": ["json", "markdown", "pdf"],
    "includeCharts": true,
    "destination": "reports/monitoring"
  }
}
```

### Manual Report Generation

#### Export Dashboard Data
```typescript
// From dashboard
handleExportData('csv');  // Export as CSV
handleExportData('json'); // Export as JSON
handleExportData('pdf');  // Export as PDF report
```

#### Generate Performance Report
```typescript
const dashboardData = await performanceMonitor.exportDashboardData();

// Save to file
await fs.writeFile(
  'reports/performance_report.json',
  JSON.stringify(dashboardData, null, 2)
);
```

#### Generate Health Report
```typescript
const healthReport = await healthChecker.getCurrentHealth();

// Export as markdown
const markdown = formatHealthReportAsMarkdown(healthReport);
await fs.writeFile('reports/health_report.md', markdown);
```

### Report Contents

**Daily Report:**
- Current performance metrics
- Active alerts
- Resource utilization summary
- Training status

**Weekly Report:**
- Performance trends (7 days)
- Model version changes
- Deployment history
- Alert summary

**Monthly Report:**
- Long-term performance trends
- Model performance comparison
- System reliability metrics
- Recommendations for improvement

---

## Best Practices

### Monitoring Strategy

1. **Set Realistic Thresholds**
   - Base on historical data
   - Account for normal variation
   - Adjust as system matures

2. **Monitor Trends, Not Just Values**
   - Look for gradual degradation
   - Identify patterns
   - Predict future issues

3. **Prioritize Alerts**
   - Critical: Immediate action required
   - High: Action within 15 minutes
   - Medium: Action within 1 hour
   - Low: Review during business hours

4. **Regular Review**
   - Daily: Check dashboard
   - Weekly: Review trends
   - Monthly: Analyze long-term patterns
   - Quarterly: Update baselines

### Alert Management

1. **Avoid Alert Fatigue**
   - Set appropriate thresholds
   - Use cooldown periods
   - Acknowledge non-critical alerts

2. **Alert Escalation**
   - Define escalation paths
   - Set response time SLAs
   - Document procedures

3. **Alert Documentation**
   - Document each alert type
   - Include resolution steps
   - Track alert history

### Performance Optimization

1. **Identify Bottlenecks**
   - Monitor resource usage
   - Profile slow operations
   - Optimize critical paths

2. **Capacity Planning**
   - Track growth trends
   - Plan for scale
   - Test under load

3. **Continuous Improvement**
   - Review metrics regularly
   - Implement optimizations
   - Measure impact

### Data Retention

| Data Type | Retention | Storage |
|-----------|-----------|---------|
| Real-time metrics | 48 hours | Memory |
| Hourly aggregates | 30 days | Disk |
| Daily aggregates | 90 days | Disk |
| Monthly aggregates | 1 year | Disk |
| Alerts | 90 days | Disk |
| Health checks | 30 days | Disk |
| Training logs | 90 days | Disk |
| Deployment logs | 1 year | Disk |

### Security Considerations

1. **Access Control**
   - Restrict dashboard access
   - Audit monitoring actions
   - Secure API endpoints

2. **Data Privacy**
   - Sanitize sensitive data
   - Encrypt at rest
   - Secure transmission

3. **Audit Trail**
   - Log all monitoring actions
   - Track configuration changes
   - Maintain deployment history

---

## Monitoring Checklist

### Daily Tasks
- [ ] Check dashboard for alerts
- [ ] Review current performance metrics
- [ ] Verify all components healthy
- [ ] Check resource utilization
- [ ] Review training status

### Weekly Tasks
- [ ] Analyze performance trends
- [ ] Review alert history
- [ ] Check model version status
- [ ] Verify backup integrity
- [ ] Review deployment history

### Monthly Tasks
- [ ] Generate performance report
- [ ] Update performance baselines
- [ ] Review and adjust thresholds
- [ ] Analyze long-term trends
- [ ] Plan capacity upgrades

### Quarterly Tasks
- [ ] Comprehensive system review
- [ ] Update monitoring strategy
- [ ] Review and update documentation
- [ ] Test disaster recovery
- [ ] Audit security controls

---

## Integration Examples

### Prometheus Integration

```typescript
// Export metrics for Prometheus
app.get('/metrics', (req, res) => {
  const metrics = performanceMonitor.getCurrentMetrics();
  
  res.set('Content-Type', 'text/plain');
  res.send(`
# HELP huntress_success_rate Model success rate
# TYPE huntress_success_rate gauge
huntress_success_rate ${metrics.successRate}

# HELP huntress_false_positive_rate False positive rate
# TYPE huntress_false_positive_rate gauge
huntress_false_positive_rate ${metrics.falsePositiveRate}

# HELP huntress_avg_execution_time Average execution time in seconds
# TYPE huntress_avg_execution_time gauge
huntress_avg_execution_time ${metrics.avgTimeToSuccess}
  `);
});
```

### Grafana Dashboard

```json
{
  "dashboard": {
    "title": "Huntress Monitoring",
    "panels": [
      {
        "title": "Success Rate",
        "targets": [
          {
            "expr": "huntress_success_rate",
            "legendFormat": "Success Rate"
          }
        ]
      }
    ]
  }
}
```

### Custom Webhook

```typescript
// Send alerts to custom webhook
healthChecker.on('alert:created', async ({ alert }) => {
  if (alert.severity === 'critical') {
    await fetch('https://your-webhook.com/alerts', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        severity: alert.severity,
        component: alert.component,
        message: alert.message,
        timestamp: alert.timestamp,
      }),
    });
  }
});
```

---

## Appendix: Metric Definitions

### Success Rate
```
Success Rate = (Successful Hunts / Total Hunts) × 100%
```

### False Positive Rate
```
FP Rate = (False Positives / Total Findings) × 100%
```

### Average Execution Time
```
Avg Time = Σ(Execution Times) / Count(Successful Hunts)
```

### Performance Degradation
```
Degradation = ((Baseline - Current) / Baseline) × 100%
```

### Resource Utilization
```
Utilization = (Used / Total) × 100%
```

---

**Last Updated:** 2025-01-23  
**Version:** 1.0.0  
**Maintainer:** Huntress Development Team