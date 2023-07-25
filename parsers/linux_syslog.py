import re

def linux_syslog(log):
    """
    Function to parse Linux rsyslog logs and convert them to CEF format.
    """
    # CEF mapping fields
    cef_prefix = 'CEF:0|Unix|Unix||rsyslog|1.0|'

    # Define log patterns
    log_patterns = [
        {
            'pattern': r"<(\d+)>\d (\w{3} \d{2} \d{4} \d{2}:\d{2}:\d{2}) (\w+) (\w+) (\d+) ID(\d+) - (.*)",
            'fields': ['severity', 'timestamp', 'hostname', 'process', 'pid', 'id', 'message'],
        },
        {
            'pattern': r"(\w{3} \d{2} \d{2}:\d{2}:\d{2}) (\w+) (\w+\[\d+\]): (.*)",
            'fields': ['timestamp', 'hostname', 'process', 'message'],
        },
        {
            'pattern': r"\(<(\d+)>\) (\w{3} \d{2} \d{2}:\d{2}:\d{2}) (\w+) \[(\w+)\]: \((\w+)\) (\w+) \((.*)\)",
            'fields': ['severity', 'timestamp', 'hostname', 'process', 'info1', 'info2', 'message'],
        },
        {
            'pattern': r"<(\d+)>\d (\w{3} \d{2} \d{4} \d{2}:\d{2}:\d{2}) (\w+) (\w+\[\d+\]): (.*)",
            'fields': ['severity', 'timestamp', 'hostname', 'process', 'pid', 'message'],
         },
        {
            'pattern': r"<(\d+)>(\w{3} \d{2} \d{2}:\d{2}:\d{2}) (\w+) (\w+\[\d+\]): (.*)",
            'fields': ['priority', 'timestamp', 'hostname', 'process', 'message'],
        },
        {
            'pattern': r"<(\d+)>(\w{3} \d{2} \d{2}:\d{2}:\d{2}) (\w+) (\w+\[\d+\]): (.*)",
            'fields': ['severity', 'timestamp', 'hostname', 'process', 'message'],
        },
        {
            'pattern': r"<(\d+)>(\w{3} \d{2} \d{2}:\d{2}:\d{2}) (\w+) (\w+\[\d+\]): (.*)",
            'fields': ['priority', 'timestamp', 'hostname', 'process', 'message'],
        },
        {             
            'pattern': r"<(\d+)>(\w{3} \d{2} \d{2}:\d{2}:\d{2}) (\w+) (\w+\[\d+\]): (.*)",
            'fields': ['severity', 'timestamp', 'hostname', 'process', 'message'],
        },
        {
            'pattern': r"<(\d+)>(\w{3} \d{2} \d{2}:\d{2}:\d{2}) (\w+) ([\w-]+\[\d+\]): (.*)",
            'fields': ['severity', 'timestamp', 'hostname', 'process', 'message'],
        },
    ]
    field_mapping = {
        'priority':'cs1',
        'severity': 'sev',
        'timestamp': 'end',
        'hostname': 'dvchost',
        'process': 'deviceProcessName',
        'pid': 'deviceProcessId',
        'id': 'externalId',
        'message': 'msg',
        'audit_type': 'deviceEventClassId',
        'audit': 'deviceEventId',
        'apparmor': 'apparmor',
        'operation': 'deviceCustomString1',
    }

    for pattern_info in log_patterns:
        pattern = pattern_info['pattern']
        fields = pattern_info['fields']
        match = re.search(pattern, log)

        if match:
            #field_values = {field: match.group(index) for index, field in enumerate(fields, start=1)}
            #timestamp = field_values.pop('timestamp', '')
            #hostname = field_values.pop('hostname', '') 
            cef_values = ' '.join(f"{field_mapping[field]}={match.group(index)}" for index, field in enumerate(fields, start=1))
            cef_log = f'{cef_prefix}{cef_values}'
            #cef_log = f'{timestamp} {hostname} {cef_prefix}{cef_values}'
            return cef_log

    return None