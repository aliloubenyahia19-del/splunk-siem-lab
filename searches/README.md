# SPL Search Library

These 25 searches were developed for the five dashboards in this project. Index names reflect the original lab environment.

## Android logs - `index=ezz`

### Message length

```spl
index=ezz | eval msg_length=length(_raw) | table _time, msg_length, _raw
```

### Event-tag frequency

```spl
index=ezz | rex field=_raw ":\s+(?<final_tag>[^:]+):" | stats count by final_tag
```

### Process-ID extraction

```spl
index=ezz | rex field=_raw "\s+(?<pid>\d+)\s+" | table _time, pid, _raw
```

### Top event tags

```spl
index=ezz | rex field=_raw ":\s+(?<final_tag>[^:]+):" | top 10 final_tag | chart sum(count) by final_tag
```

### Event volume over time

```spl
index=ezz | timechart count
```

## Windows logs - `index=win`

### Component activity

```spl
index=win | stats dc(EventId) as "Unique Event IDs", count as Total_Logs by Component
```

### Warnings and failures over time

```spl
index=win Content="*Warning*" OR Content="*Failed*" | timechart span=30m count
```

### Most frequent warning or failure event IDs

```spl
index=win Content="*Warning*" OR Content="*Failed*" | top EventId limit=10
```

### Keyword-based event classification

```spl
index=win
| eval Keyword_Type=case(
    like(Content, "%Failed%"), "Failure",
    like(Content, "%Warning%"), "Warning",
    like(Content, "%HRESULT%"), "System Error",
    true(), "Normal")
| stats count by Keyword_Type
```

### Event-template frequency

```spl
index=win | stats count as Event_Count by EventTemplate | sort -Event_Count
```

## Fraud detection - `index=inn`

### Fraud by transaction type

```spl
index=inn | where Fraudulent=1 | stats count as Fraud_Count by Transaction_Type | sort -Fraud_Count
```

### Fraud by device

```spl
index=inn | where Fraudulent=1 | stats count as Fraud_Count by Device_Used | sort -Fraud_Count
```

### Fraud by location

```spl
index=inn | where Fraudulent=1 AND isnotnull(Location) | stats count as Fraud_Count by Location | sort -Fraud_Count
```

### Fraud by transaction time

```spl
index=inn | where Fraudulent=1 AND isnotnull(Time_of_Transaction) | stats count as Fraud_Count by Time_of_Transaction | sort Time_of_Transaction
```

### Behavioural risk score

```spl
index=inn
| eval Risk_Score=(Previous_Fraudulent_Transactions * 2) + Number_of_Transactions_Last_24H + (Transaction_Amount / 100)
| stats avg(Risk_Score) as Avg_Score, sum(Fraudulent) as Fraud_Cases by User_ID
| where Fraud_Cases > 0
| sort -Avg_Score
```

## Apache logs - `index=okk`

### Forbidden directory requests by country

```spl
index=okk "Directory index forbidden"
| rex field=_raw "client (?<client_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
| iplocation client_ip
| geostats count by Country
```

### Child-process activity by scoreboard slot

```spl
index=okk "jk2_init() Found child"
| rex "Found child (?<child_id>\d+) in scoreboard slot (?<slot_number>\d+)"
| timechart count by slot_number
```

### Worker error states over time

```spl
index=okk "mod_jk child workerEnv in error state"
| rex "mod_jk child workerEnv in error state (?<error_state>\d+)"
| chart count over _time by error_state
```

### Worker errors by client IP

```spl
index=okk "mod_jk child workerEnv in error state"
| rex field=_raw "client (?<client_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
| stats count by client_ip
| sort -count
```

### Worker-error distribution

```spl
index=okk "mod_jk child workerEnv in error state"
| rex "mod_jk child workerEnv in error state (?<error_state>\d+)"
| stats count by error_state
```

## Linux SSH logs - `index=linuxx`

### Most frequently targeted usernames

```spl
index=linuxx sshd authentication failure | rex field=_raw "user=(?<failed_user>\S+)" | top 10 failed_user
```

### Most frequent remote hosts

```spl
index=linuxx sshd authentication failure | rex field=_raw "rhost=(?<remote_host>\S+)" | top 10 remote_host
```

### Brute-force candidates

```spl
index=linuxx sshd authentication failure
| rex field=_raw "rhost=(?<remote_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
| stats count by remote_ip
| where count >= 5
```

### Authentication failures over time

```spl
index=linuxx sshd authentication failure | timechart count
```

### Failure sources by country

```spl
index=linuxx sshd authentication failure
| rex field=_raw "rhost=(?<remote_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
| iplocation remote_ip
| geostats count by Country
```

