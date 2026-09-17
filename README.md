# OpenCTI Add On for Splunk

The OpenCTI Add-on for Splunk allows users to interconnect Splunk with OpenCTI platform.

## Key features

- Ability to ingest Indicators exposed through an OpenCTI live stream
- Ability to trigger OpenCTI actions in response of Alerts and to investigate them directly in OpenCTI

## Installation

### Installation from Splunkbase

1. Log in to the Splunk Web UI and navigate to "Apps" and click on "Find more Apps"
2. Search for "OpenCTI Add-on for Splunk"
3. Click Install
The app is installed

### Installing from file

1. Download latest version of the Splunk App: [TA-opencti-add-on-1.1.7.tar.gz](https://github.com/OpenCTI-Platform/splunk-add-on/releases/download/1.1.7/TA-opencti-add-on-1.1.7.tar.gz)
2. Log in to the Splunk Web UI and navigate to "Apps" and click on "Manage Apps"
3. Click "Install app from file"
4. Choose file and select the "TA-opencti-add-on-1.1.7.tar.gz" file
5. Click on Upload
The app is installed

## General Configuration

### OpenCTI user account

Before configuring the App, we strongly recommend that you create a dedicated account in OpenCTI with the same properties as for a connector user account.
To create this account, please refer to [Connector users and Tokens](https://docs.opencti.io/latest/deployment/connectors/?h=connector+user#connector-users-and-tokens) documentation.

### General Add-On settings

1. Navigate to Splunk Web UI home page, open the "OpenCTI add-on for Splunk" and navigate to "Configuration" page.
2. Click on "Add-on settings" tab and complete the form with the required settings:

| Parameter                  | Description                                                     |
|----------------------------|-----------------------------------------------------------------|
| `OpenCTI URL`              | The URL of the OpenCTI platform (A HTTPS connection is required |
| `OpenCTI API Key`          | The API Token of the previously created user                    |

![](./.github/img/addon_settings.png "Add-on settings")


If a proxy configuration is required to connect to OpenCTI platform, you can configure it on the Proxy page

| Parameter         | Description                                                                 |
|-------------------|-----------------------------------------------------------------------------|
| `Enable Proxy`    | Determines whether a proxy is required to communicate with OpenCTI platform |
| `Proxy Host`      | The proxy hostname or IP address                                            |
| `Proxy Port`      | The proxy port                                                              |
| `Proxy Username`  | An optional proxy username                                                  |
| `Proxy Password`  | An optional proxy password                                                  |


## OpenCTI Indicators Inputs Configuration

The “OpenCTI Add-On for Splunk” enables Splunk to be feed with indicators exposed through a live stream. To do this, the add-on implements and manages Splunk modular inputs. 
Indicators are stored in a dedicated kvstore named “opencti_indicators”. 
A default lookup definition named "opencti_lookup" is also implemented to facilitate indicator management.

Proceed as follows to enable the ingestion of indicators:

1. From the "OpenCTI add-on" sub menus, select the "Inputs" sub menu.
2. Click on "Create new input" button to define a new indicators input.
3. Complete the form with the following settings:

| Parameter       | Description                                                                                                    |
|-----------------|----------------------------------------------------------------------------------------------------------------|
| `Name`          | Unique name for the input being configured                                                                     |
| `Interval`      | Time interval of input in seconds. Leave as default (0) to allow continuous execution of the ingestion process |
| `Index`         | The index that the data will be stored in (default)                                                            |
| `Stream Id`     | The Live Stream ID of the OpenCTI stream to consume                                                            |
| `Import from`   | The number of days to go back for the initial data collection (default: 30) (optional)                         |

4. Once the Input parameters have been correctly configured click "Add".

![](./.github/img/config_input.png "Indicators Input Configuration")

5. Validate the newly created Input and ensure it's set to "Enabled".

As soon as the input is created, the ingestion of indicators begins.
You can monitor the import of these indicators using the following Splunk query that list all indicators ingested in the kvstore: 

```
| inputlookup opencti_lookup
```

You can also consult the "Indicators Dashboard" which gives an overview of the data ingested.

![](./.github/img/indicators_dashoard.png "Indicators Dashboard")


The ingestion process can also be monitored by consulting the log file ```ta_opencti_add_on_opencti_indicators.log``` present in the directory ```$SPLUNK_HOME/var/log/splunk/```

### Ingested indicators

Only indicators whose `pattern_type` is `stix` are ingested. Indicators written in another
language (`yara`, `sigma`, `snort`, `suricata`, `spl`, `eql`, ...) are skipped and reported in the log.

A STIX pattern is ingested when it compares one of the attributes below with the `=` operator.
The `type` field of the KV store is set to the value in the right-hand column:

| Observable                                             | `type` in the KV store  |
|--------------------------------------------------------|-------------------------|
| `autonomous-system:number`                             | `autonomous-system`     |
| `cryptocurrency-wallet:value`                          | `cryptocurrency-wallet` |
| `directory:path`                                       | `directory`             |
| `domain-name:value`                                    | `domain-name`           |
| `email-addr:value`                                     | `email-addr`            |
| `email-message:subject`                                | `email-message`         |
| `file:hashes.'MD5' / 'SHA-1' / 'SHA-256' / 'SHA-512'`  | `md5` / `sha1` / `sha256` / `sha512` |
| `file:name`                                            | `filename`              |
| `hostname:value`                                       | `hostname`              |
| `ipv4-addr:value`                                      | `ipv4-addr`             |
| `ipv6-addr:value`                                      | `ipv6-addr`             |
| `mac-addr:value`                                       | `mac-addr`              |
| `mutex:name`                                           | `mutex`                 |
| `phone-number:value`                                   | `phone-number`          |
| `text:value`                                           | `text`                  |
| `url:value`                                            | `url`                   |
| `user-account:account_login` / `user_id`               | `user-account`          |
| `user-agent:value`                                     | `user-agent`            |
| `windows-registry-key:key`                             | `windows-registry-key`  |

Patterns using another operator (`!=`, `LIKE`, `MATCHES`, `IN`) are not ingested, and are
reported as an unsupported pattern in the log.

> **Note:** an indicator is stored as a single KV store entry. When its pattern compares several
> observables, for instance a file carrying both its MD5 and its SHA-256, only the first one is
> kept in the lookup.


## OpenCTI custom alert actions

You can use the "OpenCTI Add-on for Splunk" to create custom alert actions that automatically create 'incidents' or/and 'incident response cases' or/and 'sighting' in response to alert trigger by Splunk.

### Create an incident or/and an incident response case or/and a sighting in OpenCTI

You can create an incident or an incident response case in OpenCTI from a custom alert action.
1. Write a Splunk search query.
2. Click Save As > Alert.
3. Fill out the Splunk Alert form. Give your alert a unique name and indicate whether the alert is a real-time alert or a scheduled alert.
4. Under Trigger Actions, click Add Actions.
5. From the list, select "OpenCTI - Create Incident" if you want the alert to create an incident in OpenCTI or "OpenCTI - Create Incident Response" if you want to create an incident response case in OpenCTI or "OpenCTI - Create Sighting" if you want to create a sighting in OpenCTI.

![](./.github/img/alert_actions.png "Custom Alert Actions")

6. To create and incident or an incident response case, complete the form with the following settings:

| Parameter                | Description                                           | Scope                             |
|--------------------------|-------------------------------------------------------|-----------------------------------|
| `Name`                   | Name of the incident                                  | Incident & Incident response case |
| `Description`            | Description of the incident or incident response case | Incident & Incident response case |                              
| `Type`                   | Incident Type or incident response case type          | Incident & Incident response case |                              
| `Severity`               | Severity of the incident or incident response case    | Incident & Incident response case | 
| `Priority`               | Priority of the incident response case                | Incident response case            | 
| `Labels`                 | Labels (separated by a comma) to be applied           | Incident & Incident response case | 
| `TLP`                    | Markings to be applied                                | Incident & Incident response case | 
| `Observables extraction` | Method for extracting observables                     | Incident & Incident response case | 

7. To create a sighting, complete the form with the following settings:

| Parameter                | Description                                                   | Scope      |
|--------------------------|---------------------------------------------------------------|------------|
| `Sighting Of (value)`    | Value of what was sighted                                     | Sighting   |
| `Sighting Of (type)`     | Type of what was sighted (see below)                          | Sighting   |                              
| `Where Sighted (value)`  | Value of the 'System' or 'Organization' that saw the sighting | Sighting   |                              
| `Where Sighted (type)`   | 'System' or 'Organization' that saw the sighting              | Sighting   | 
| `Count`                  | Number of times the indicator was seen (default: 1)           | Sighting   | 
| `First Seen`             | Start of the sighting, epoch seconds or ISO 8601 (default: the event time) | Sighting   | 
| `Last Seen`              | End of the sighting, epoch seconds or ISO 8601 (default: the event time)   | Sighting   | 
| `Labels`                 | Labels (separated by a comma) to be applied                   | Sighting   | 
| `TLP`                    | Markings to be applied                                        | Sighting   | 

The `Sighting Of (type)` setting decides whether the sighting is attached to an **indicator** or to an **observable** in OpenCTI:

| Type                                    | `Sighting Of (value)` expects                    | Sighting is attached to                                     |
|-----------------------------------------|--------------------------------------------------|-------------------------------------------------------------|
| `Indicator (OpenCTI id or STIX pattern)`| an indicator id (`indicator--...`) or a STIX pattern | the indicator itself                                     |
| `URL / Domain / IPV4 / IPV6 / Hostname / Email Address / File Name / MD5 / SHA-1 / SHA-256 / SHA-512 Indicator` | the raw value | the indicator built from that value, also linked `based-on` the observable |
| `URL / Domain / IPV4 / IPV6 Observable` | the raw value                                    | the observable only (behaviour of previous versions)         |

Use one of the *Indicator* types to have the sighting counted on the IOC itself, which is what feeds the indicator decay and scoring in OpenCTI. The indicator id is derived the same way OpenCTI derives it, so the sighting attaches to the indicator that already exists on the platform instead of creating a duplicate.

When the alert is driven by the `opencti_lookup` KV store, the cleanest option is `Indicator (OpenCTI id or STIX pattern)` with `Sighting Of (value)` set to the `id` field returned by the lookup, for example `$result.id$`.

#### Count the matches instead of sending one sighting per match

By default the alert action sends one sighting per result of the alert, with a `count` of 1 and
`first_seen` / `last_seen` set to the time of the event. To report the number of matches instead,
aggregate the results in the search and hand the aggregates to the `Count`, `First Seen` and
`Last Seen` parameters. `Count` expects a whole number, the two dates accept an epoch in seconds,
which is the form of `_time`, `min(_time)` and `max(_time)`, or an ISO 8601 date. When only one of
the two dates is given the sighting is that instant.

Example of a search counting, per index, the matches of every indicator over the last day:

```
index=* earliest=-24h
| lookup opencti_lookup value as url_domain OUTPUT id as match_ioc_id
| search match_ioc_id=*
| stats count min(_time) as first_seen max(_time) as last_seen by match_ioc_id, index
```

with the "OpenCTI - Create Sighting" action configured as follows:

| Parameter               | Value                                    |
|-------------------------|------------------------------------------|
| `Sighting Of (type)`    | `Indicator (OpenCTI id or STIX pattern)` |
| `Sighting Of (value)`   | `$result.match_ioc_id$`                  |
| `Where Sighted (type)`  | `System`                                 |
| `Where Sighted (value)` | `Splunk - $result.index$`                |
| `Count`                 | `$result.count$`                         |
| `First Seen`            | `$result.first_seen$`                    |
| `Last Seen`             | `$result.last_seen$`                     |

> **Important:** set the alert to trigger **for each result**. Splunk resolves the `$result.*$` tokens
> once per trigger, from the first result, so an alert triggered *once* for several results would
> report the first indicator and the first index for all of them.

The id of the sighting is derived from the indicator and from the system, so every run of the alert
lands on the same sighting in OpenCTI. On that update OpenCTI extends `first_seen` and `last_seen` to
the reported window and adds the reported count to the existing one whenever the window grows. A run
reporting a window already covered leaves the count unchanged, so re-running an alert does not count
the same matches twice. The count of a window that only partly overlaps the previous one is added in
full, so schedule the alert on windows that do not overlap, for instance every hour over
`earliest=-1h@h latest=@h`.

The system named in `Where Sighted (value)` is created in OpenCTI when it does not exist yet and
reused otherwise, which makes `Splunk - $result.index$` a convenient way to get one system per
Splunk index.

You can use [Splunk "tokens"](https://docs.splunk.com/Documentation/Splunk/9.2.2/Alert/EmailNotificationTokens#Result_tokens) as variables in the form to contextualize the data imported into OpenCTI.
Tokens represent data that a search generates. They work as placeholders or variables for data values that populate when the search completes.

Example of a configuration to create an incident in OpenCTI

![](./.github/img/alert_example.png "Alert Example")

### Observables extraction

To extract and model alert fields as OpenCTI observables attached to the incident or incident response case, the Add-on purpose two methods describe below.

#### CIM model

The “CIM model” method is based on the definition of CIM model fields. With this method, the Add-on will extract all the following fields and model them as follows:

| CIM Field         | Observable type                     |
|-------------------|-------------------------------------|
| `url`             | URL observable                      | 
| `url_domain`      | Domain observable                   |                       
| `user`            | User account observable             |                            
| `user_name`       | User account observable             | 
| `user_agent`      | User agent Observable               |
| `http_user_agent` | User agent Observable               |
| `dest`            | IPv4 or IPv6 or Hostname observable |
| `dest_ip`         | IPv4 or IPv6 observable             |
| `src`             | IPv4 or IPv6 or Hostname observable |
| `src_ip`          | IPv4 or IPv6 observable             |
| `file_hash`       | File observable                     |
| `file_name`       | File observable                     |


#### Field mapping

The “Field mapping” method searches for event fields starting with the string “octi_” and ending with an observable type.
The following list describe list of supported fields:

| OCTI Field                         | Observable type                       |
|------------------------------------|---------------------------------------|
| `octi_ip`                          | IPv4 or IPv6 observable               | 
| `octi_url`                         | URL observable                        |
| `octi_domain`                      | Domain observable                     |                       
| `octi_hash`                        | File observable                       |                       
| `octi_email_addr`                  | Email address observable              |                       
| `octi_user_agent`                  | User agent observable                 |                       
| `octi_mutex`                       | Mutex observable                      |                       
| `octi_text`                        | Text observable                       |                       
| `octi_windows_registry_key`        | Windows Registry Key observable       |                       
| `octi_windows_registry_value_type` | Windows Registry Key Value observable |                       
| `octi_directory`                   | Directory observable                  |                       
| `octi_email_message`               | Email message observable              |    
| `octi_file_name`                   | File observable                       |    
| `octi_mac_addr`                    | MAC address observable                | 
| `octi_user_account`                | User account address observable       |    

You can use the Splunk ```eval``` command to create a new field based on the value of another field.

Example:

```sourcetype=* | lookup opencti_lookup value as url_domain OUTPUT id as match_ioc_id | search match_ioc_id=* | eval octi_domain=url_domain | eval octi_url=url ```


Logs related to OpenCTI customer alerts are available in the following two log file:

```$SPLUNK_HOME/var/log/splunk/opencti_create_incident_modalert.log```

```$SPLUNK_HOME/var/log/splunk/opencti_create_incident_response_modalert.log```
