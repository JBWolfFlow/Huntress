# Training Dashboard

Production monitoring dashboard for Phase 5 continuous learning system.

## Installation

The dashboard requires the `recharts` library for data visualization:

```bash
npm install recharts
```

## Features

- Real-time performance metrics display
- Training status and progress visualization
- Model version history with comparison
- A/B test results visualization
- Resource usage graphs (GPU, CPU, memory, disk)
- Alert notifications with severity indicators
- Manual intervention controls
- Export functionality (CSV, JSON, PDF)
- Responsive design with Tailwind CSS
- Auto-refresh with configurable intervals

## Usage

```tsx
import { TrainingDashboard } from './components/TrainingDashboard';

function App() {
  return <TrainingDashboard />;
}
```

## Manual Controls

- **Pause/Resume Training**: Control the learning loop
- **Trigger Rollback**: Emergency rollback to previous version
- **Promote Model**: Promote a model version to production
- **Force Retraining**: Start a new training cycle immediately
- **Export Data**: Export metrics and reports in various formats

## Integration

The dashboard integrates with:
- Health Check System
- Performance Monitor
- Model Manager
- Deployment Manager
- Learning Loop Orchestrator

In production, replace the mock data with actual API calls to these systems.