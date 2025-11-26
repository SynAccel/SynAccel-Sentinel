import json
from collections import Counter
from datetime import datetime, timedelta

import boto3

class CloudTrailAnomalyDetector:
    """CloudTrailAnomalyDetector
    ---
    -Pulls recent CloudTrail events
    - Applies simple rule based anomaly detection
    - Returns a list of anomaly dictionaries that Sentinel can consume
    """
    
    def __init__(self, region_name="us-east-1", rules_path=None):
        """
        :param region_name: AWS region for CloudTrail
        :param rules_path: path to anomaly_rules.json
        """
        self.client = boto3.client("cloudtrail", region_name=region_name)
        
        # Load detection rules from json
        if rules_path is None:
            rules_path = "src/cloudtrail_anomaly_detector/anomaly_rules.json"
            
        with open(rules_path, "r") as f:
            self.rules = json.load(f)
        self.frequency_threshold = self.rules.get("frequency_threshold", 50)
        self.high_risk_prefixes = self.rules.get("high_risk_prefixes", [])
        self.lookback_hours = self.rules.get("lookback_hours", 24)
        
        def _fetch_events(self):
            """fetch cloudtrail events for configured time window
            uses lookup_events 
            """
            
            end_time = datetime.utcnow
            start_time = end_time - timedelta(hours=self.lookback_hours)
            
            response = self.client.lookup_events(
                StartTime=start_time
                EndTime=end_time
                MaxResults=1000 
            )
            
            return response.get("Events", [])
        
        def _identify_frequency_anomalies(self, events):
            """_summary_

            Args:
                events (_type_): _description_
            """
            event_names = [e["EventName"] for e in events]
            counts = Counter(event_names)
            
            anomalies = []
            
            for event_name, count in counts.items():
                if count >= self.frequency_threshold:
                    anomalies.append({
                        "type": "API_FREQUENCY_ANOMALY",
                    "event_name": event_name,
                    "count": count,
                    "threshold": self.frequency_threshold
                        
                    })
                    
                    return anomalies
                
                def _identify_high_risk_actions(self,events):
                    """Flag events where API name starts with high-risk prefixes
                    ex. Delete*, Put*, Attach*, etc.
                    """
                    anomalies = []
                    
                    for e in events: 
                        event_name = e["EventName"]
                        username = e.get("Username", "Unknown")
                        event_time = e.get("EventTime")
                        
                        if any(event_name.startswith(prefix)for prefix in self.high_risk_prefixes):
                            anomalies.append({
                                "type": "HIGH_RISK_ACTION",
                                "event_name": event_name,
                                "user": username,
                                "time": event_time.isoformat() if hasattr(event_time, "isoformat") else str(event_time)
                            })
                        
                        return anomalies
                    
                    def run(self):
                        """Main entry point.
                        1. Fetch events
                        2. Run detection logic
                        3. Return combined list of anomalies
                        """
                        
                        events = self._fetch_events()
                        if not events:
                            return []
                        
                        anomalies = []
                        anomalies.extend(self._identify_frequency_anomalies(events))
                        anomalies.extend(self._identify_high_risk_actions(events))

                        return anomalies
                        
                            
                        
                        
                        
        