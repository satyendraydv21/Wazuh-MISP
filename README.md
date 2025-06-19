Introduction
Adonay T.
Adonay T.
7 min read
·
Jan 23, 2024

This blog entry details how we can automate Wazuh to take advantage of the MISP API. This automation serves as a great benefit because our analysts will not have to manually correlate a Wazuh alert with MISP to find possible IoCs. For example, when a DNS query is made by an endpoint, Wazuh will strip out that domain and send it to MISP asking if MISP has this value within its threat feeds. If the value does exist within MISP, MISP will respond with the event id and more metadetails around the IoC. A positive response from MISP will generate a high severity Wazuh alert stating “IoC found”. Our SOC team is now immediately notified with enriched data rather than manually searching for IoCs.
Step I. Setting up MISP for Integration

    1. MISP Overview

    2. Installing MISP on Ubuntu 22.04

    3. Change Admin Password

    4. Create an Organization

    5. Enable Threat Intel Feeds

Step II. Setting up WAZUH for Integration

    1. WAZUH Overview

    2. Step-by-Step Installation

    3. Adding Windows Wazuh Agent

Step III. Setting up Sysmon on Wazuh Agent

    1. Sysmon Overview

    2. Sysmon Installation and Configuration Steps

Step IV. Integrating MISP API with WAZUH

    1. Download Integration Script

    2. Script Permissions

    3. Add Integration Block to ossec.conf

    4. Creating MISP Custom Rules

Step I — Setting up MISP for Integration
1. MISP Overview

MISP (Malware Information Sharing Platform and Threat Sharing) is an open-source threat intelligence platform that allows you to share, collate, analyze, and distribute threat intelligence. It is used across industries and governments worldwide to share and analyze information about the latest threats. This series aims to give you the knowledge you need to get up and running with MISP as quickly as possible.
Installing MISP on Ubuntu 22.04

sudo apt-get update -y && sudo apt-get upgrade -y

sudo apt-get install mysql-client -y

wget https://raw.githubusercontent.com/MISP/MISP/2.4/INSTALL/INSTALL.sh

chmod +x INSTALL.sh

./INSTALL.sh -A

sudo ufw allow 80/tcp

sudo ufw allow 443/tcp

Change admin password

Browse to https://<"your misp instance ip">/users/login
Username: admin@admin.test
Password: admin
Enter new password

Create an organization

Select Administration > Add Organisations
Enter "<ORG name> into Organisation Identifier
Select "Generate UUID"

Select “Submit” at the bottom

Enable threat intel feeds

To use feeds in MISP, you must be logged in as an Administrator user. Once logged in, you will find feeds under the Sync Actions menu as Feeds.

Clicking Feeds will bring you to the Feeds screen. Here, you will see the default feeds listed.

Click the Load default feed metadata button to load all the default feeds. This will populate the Feeds screen with all the default threat intelligence feeds that come with your MISP instance..

To use a feed, you need to enable it and enable caching for said feed. Caching a feed will download all the feed’s IOCs as attributes onto your MISP instance’s Redis server. You can search these attributes and see correlations between data published in your MISP instance and that stored in your cache. To do this, select the feed(s) you want to use and click the Enable selected and Enable caching for selected buttons.
Step II— Setting up WAZUH for Integration
2. WAZUH Overview

Wazuh is a popular open-source security platform that provides an extensive range of threat detection, visibility, and response capabilities. It is designed to help organizations to monitor and manage their security posture more effectively by collecting, analyzing, and correlating security-related data from various sources across their network infrastructure. The platform leverages a combination of host-based intrusion detection (HIDS), log analysis, and security event correlation to detect, identify, and respond to potential security incidents.

At its core, Wazuh consists of three primary components: the Wazuh server, agents, and the Wazuh app. The Wazuh server is responsible for collecting and analyzing security data from various sources, while the agents are installed on the monitored endpoints to collect security-relevant data such as system events, network traffic, and file integrity. The Wazuh app provides a web-based user interface that allows security analysts to view and analyze security events, configure rules, and manage the Wazuh infrastructure. With its robust feature set and flexible architecture, Wazuh has become a popular choice for security professionals who seek to improve their organization’s security posture while minimizing the risk of security breaches.
2.1. Step-by-Step Installation
Install Wazuh

apt install -y curl apt-transport-https unzip wget libcap2-bin software-properties-common lsb-release gnupg
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add -
echo "deb https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list
apt-get update

Install Wazuh Manager

apt install -y wazuh-manager

systemctl daemon-reload
systemctl enable --now wazuh-manager
systemctl status wazuh-manager

Install Elasticsearch

apt install -y elasticsearch-oss opendistroforelasticsearch

curl -so /etc/elasticsearch/elasticsearch.yml https://packages.wazuh.com/resources/4.2/open-distro/elasticsearch/7.x/elasticsearch_all_in_one.yml
curl -so /usr/share/elasticsearch/plugins/opendistro_security/securityconfig/roles.yml https://packages.wazuh.com/resources/4.2/open-distro/elasticsearch/roles/roles.yml
curl -so /usr/share/elasticsearch/plugins/opendistro_security/securityconfig/roles_mapping.yml https://packages.wazuh.com/resources/4.2/open-distro/elasticsearch/roles/roles_mapping.yml
curl -so /usr/share/elasticsearch/plugins/opendistro_security/securityconfig/internal_users.yml https://packages.wazuh.com/resources/4.2/open-distro/elasticsearch/roles/internal_users.yml

Create certificate

rm /etc/elasticsearch/esnode-key.pem /etc/elasticsearch/esnode.pem /etc/elasticsearch/kirk-key.pem /etc/elasticsearch/kirk.pem /etc/elasticsearch/root-ca.pem -f

curl -so ~/wazuh-cert-tool.sh https://packages.wazuh.com/resources/4.2/open-distro/tools/certificate-utility/wazuh-cert-tool.sh
curl -so ~/instances.yml https://packages.wazuh.com/resources/4.2/open-distro/tools/certificate-utility/instances_aio.ymlbash ~/wazuh-cert-tool.shmkdir /etc/elasticsearch/certs/
mv ~/certs/elasticsearch* /etc/elasticsearch/certs/
mv ~/certs/admin* /etc/elasticsearch/certs/
cp ~/certs/root-ca* /etc/elasticsearch/certs/mkdir -p /etc/elasticsearch/jvm.options.d
echo '-Dlog4j2.formatMsgNoLookups=true' > /etc/elasticsearch/jvm.options.d/disabledlog4j.options
chmod 2750 /etc/elasticsearch/jvm.options.d/disabledlog4j.options
chown root:elasticsearch /etc/elasticsearch/jvm.options.d/disabledlog4j.optionssystemctl daemon-reload
systemctl enable elasticsearch
systemctl start elasticsearchexport JAVA_HOME=/usr/share/elasticsearch/jdk/ && /usr/share/elasticsearch/plugins/opendistro_security/tools/securityadmin.sh -cd /usr/share/elasticsearch/plugins/opendistro_security/securityconfig/ -nhnv -cacert /etc/elasticsearch/certs/root-ca.pem -cert /etc/elasticsearch/certs/admin.pem -key /etc/elasticsearch/certs/admin-key.pem

Install Filebeat

apt install -y filebeat

Config Filebeat

curl -so /etc/filebeat/filebeat.yml https://packages.wazuh.com/resources/4.2/open-distro/filebeat/7.x/filebeat_all_in_one.yml

curl -so /etc/filebeat/wazuh-template.json https://raw.githubusercontent.com/wazuh/wazuh/4.2/extensions/elasticsearch/7.x/wazuh-template.json
chmod go+r /etc/filebeat/wazuh-template.json

Install Module Filebeat

curl -s https://packages.wazuh.com/4.x/filebeat/wazuh-filebeat-0.1.tar.gz | tar -xvz -C /usr/share/filebeat/module

Copy certs

mkdir /etc/filebeat/certs
cp ~/certs/root-ca.pem /etc/filebeat/certs/
mv ~/certs/filebeat* /etc/filebeat/certs/

Restart Daemon

systemctl daemon-reload
systemctl enable filebeat
systemctl start filebeat

Configure Filebeat

filebeat test output

Install Kibana

apt install -y opendistroforelasticsearch-kibana

Download kibana config

curl -so /etc/kibana/kibana.yml https://packages.wazuh.com/resources/4.2/open-distro/kibana/7.x/kibana_all_in_one.yml

Prepare directory

mkdir /usr/share/kibana/data
chown -R kibana:kibana /usr/share/kibana/data

Kibana plugin

cd /usr/share/kibana
sudo -u kibana /usr/share/kibana/bin/kibana-plugin install https://packages.wazuh.com/4.x/ui/kibana/wazuh_kibana-4.2.6_7.10.2-1.zip

Elasticsearch certificates

mkdir /etc/kibana/certs
cp ~/certs/root-ca.pem /etc/kibana/certs/
mv ~/certs/kibana* /etc/kibana/certs/
chown kibana:kibana /etc/kibana/certs/*

Configure systemd

systemctl daemon-reload
systemctl enable kibana
systemctl start kibana

2.3. Adding Windows Wazuh Agent

Open Wazuh Manager https://<ip_wazuh_manager>

    Input wazuh server address and copy the Enrollment Command
    Open Windows Terminal Open a powershell Tab as administrator in the windows agent agent and past the Enrollment Command

Step III — Setting up Sysmon on wazuh Agent

    System Monitor (Sysmon) is a Windows system service and device driver that, once installed on a system, remains resident across system reboots to monitor and log system activity to the Windows event log. It provides detailed information about process creations, network connections, and changes to file creation time.

Sysmon installation and configuration steps:

    You can download Sysmon at this link: sysmon.zip
    Extract the zip file.
    Download sysmon-config at this link: sysmon-config
    and put them together as shown below

4. Launch powershell with administrator privileges and Run the below command

./sysmon64.exe -i sysmon.xml

If it returns that it is already installed or running run the below command and try again

./sysmon64.exe -u

5. Configure Wazuh agent to monitor Sysmon events

It is necessary to tell this agent that we want to monitor Sysmon events. For that, we need to include this code as part of the configuration of the agent by modifying ossec.conf accordingly:

<localfile>
<location>Microsoft-Windows-Sysmon/Operational</location>
<log_format>eventchannel</log_format>
</localfile>

Must Restart the agent to apply the changes.

6. Change the default rule level on the wazuh manager rulset of DNSEvent /61650/ to get alerts from

<rule id="61650" level="0" overwrite="yes">
<if_sid>61600</if_sid>
<field name="win.system.eventID">^22$</field>
<description>Sysmon - Event ID 22: DNSEvent (DNS query)</description>
<options>no_full_log</options>
<group>sysmon_event_22,</group>
</rule>

to

<rule id="61650" level="8" overwrite="yes">
<if_sid>61600</if_sid>
<field name="win.system.eventID">^22$</field>
<description>Sysmon - Event ID 22: DNSEvent (DNS query)</description>
<options>no_full_log</options>
<group>sysmon_event_22,</group>
</rule>

Must Restart the Wazuh Manager to apply the changes.
Step IV : Integrating MISP Api with Wazuh

To Integrate wazuh with MISP-API , we need to tell Wazuh how to make the API request to MISP. We are going to use a custom Python script to do so.

    Download the script follow this link : custom-misp.py
    Put the Custom-MISP with out “.py” to “/var/ossec/integrations” by providing the misp instance ip and API-Key of misp
    Give the integration script correct permissions of :

chown root:wazuh custom-misp && chmod 750 custom-misp

4. Add Integration Block To Wazuh’s ossec.conf

<integration>
<name>custom-misp</name>
<group>sysmon_event1,sysmon_event3,sysmon_event6,sysmon_event7,sysmon_event_15,sysmon_event_22,syscheck</
group>
<alert_format>json</alert_format>
</integration>

Must Restart the Wazuh Manager to apply the changes.

5. Creating MISP custom rules

Lastly, we need to configure custom rules so that Wazuh can generate an alert if MISP responds with a positive hit.

<group name="misp,">
<rule id="100620" level="10">
<field name="integration">misp</field>
<match>misp</match>
<description>MISP Events</description>
<options>no_full_log</options>
</rule>
<rule id="100621" level="5">
<if_sid>100620</if_sid>
<field name="misp.error">\.+</field>
<description>MISP - Error connecting to API</description>
<options>no_full_log</options>
<group>misp_error,</group>
</rule>
<rule id="100622" level="12">
<field name="misp.category">\.+</field>
<description>MISP - IoC found in Threat Intel - Category: $(misp.category), Attribute: $(misp.value)</description>
<options>no_full_log</options>
<group>misp_alert,</group>
</rule>
</group>
