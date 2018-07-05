## IBM X-Force Exchange   
  https://exchange.xforce.ibmcloud.com/

### Overview
IBM X-Force Exchange is a cloud-based threat intelligence sharing platform enabling users to rapidly research the latest security threats, aggregate actionable intelligence and collaborate with peers.  
IBM X-Force Exchange is supported by human- and machine-generated intelligence leveraging the scale of IBM X-Force.

 
##### Lookups integrated with IBM X-Force Exchange

##### Retrieve DNS records 
Returns live and passive DNS records.
- input : An IP address or domain or URL to be queried
```
_fetch $SrcIP from threatsample limit 1
>>_lookup ibmxforce get_dns_record $SrcIP
```
###### Sample Output 
![get_dns_record](https://user-images.githubusercontent.com/37173181/42326369-933920fe-8086-11e8-8d6a-80b68d0b1115.jpg)

The Lookup call returns output in the following structure for available data

  | Fields        | Description  |
|:------------- |:-------------|
| $IBMError    | Error message for failure of the |
| $IBMMX      | Mail exchange servers for the queried |
| $IBMTXT | List of scans returning positive detection |
| $IBMTotalRecords | List of scans returning negative detection |
| $IBMIPv4Records | Count of positive detection |
| $IBMIPv6Records | If the queried url is present in VirusTotal database it returns 1 ,if absent returns 0 and if the requested item is still queued for analysis it will be -2 |
| $IBMRDNS | Count of positive and negative detections |
| $IBMUrlRecordTypeA |  |
#####  Retrieve Domain reports
The domain for which you want to retrieve the report
- input : a domain name.

```
_fetch $Domain from threatsample limit 1
>>_lookup virustotal get_domain_report $Domain
```

##### Sample Output 
  ![domain_report](https://user-images.githubusercontent.com/37173181/38144398-2936c2ee-3462-11e8-922b-204e30abdbfd.jpg)


The Lookup call returns output in the following structure for available data

 | Fields        | Description  |
|:------------- |:-------------|
| $VTURL      | List of URL processed by VirusTotal and hosted on the domain |
| $VTCategories | Domain category assigned by VirusTotal |
| $VTWebsenseThreatSeekercategory |Domain category assigned by Websense Threat Seeker |
| $VTDomainList | List of domains that lie on the same DNS hierarchical level |
| $VTSubDomainList | List of sub-domains |
| $VTSiteClass | Site-Classification assigned by VirusTotal |
| $VTWebutationVerdict  | Webutation Domain verdict |
| $VTWebutationSafetyScore | Webutationx Domain score  |
| $VTForcepointThreatSeekerCategory | Domain category assigned by Forcepoint Threat Seeker |
| $VTPassiveDNSReplication | The queried domain has been seen to resolve the list of ip address |
| $VTResponseCode | If the queried domain is present in VirusTotal database it returns 1 ,if absent returns 0 and if the requested item is still queued for analysis it will be -2 |
| $VTWHOIS | Registered domain owners and meta-data from WHOIS |   


##### Retrieve IP address reports

The IP address for which you want to retrieve the report
- input : a valid IPv4 address in dotted quad notation, for the time being only IPv4 addresses are supported.

```
_fetch $SrcIP from threatsample limit 1
>>_lookup virustotal get_ip_report $SrcIP
```
##### Sample Output 
![ip_report](https://user-images.githubusercontent.com/37173181/38144512-a3ed30c2-3462-11e8-9e00-cf11cfaddb34.jpg)

The Lookup call returns output in the following structure for available data  

 | Fields        | Description  |
|:------------- |:-------------|
| $VTOwner      | Autonomous system owner detail |
| $VTURL | List of latest url hosted on the queried ip address |
| $VTPassiveDNSReplication | Domain resolved to the queried ip address |
| $VTASN | Autonomous system number |
| $VTCN | Country |
| $VTCommunicatingSamples | SHA256 of files that communicate with the queried ip address  |
| $VTDownloadedSamples  | SHA256 of files that downloaded from the queried ip address |
| $VTResponseCode | If the queried IP address is present in VirusTotal database it returns 1 ,if absent returns 0 and if the submitted IP address is invalid -1. |



#####  Retrieve file  scan  reports by MD5/SHA-1/SHA-256 hash
  
File report of MD5/SHA-1/SHA-256 hash for which you want to retrieve the most recent antivirus report
- input : a md5/sha1/sha256 hash will retrieve the most recent report on a given sample
```
_fetch $Filehash from threatsample limit 1
>>_lookup virustotal get_filehash_report $Filehash
```
##### Sample Output 
![filehash](https://user-images.githubusercontent.com/37173181/38144583-f6cb7dc6-3462-11e8-9706-ae4c3c5b063a.jpg)


The Lookup call returns output in the following structure for available data

 | Fields        | Description  |
|:------------- |:-------------|
| $VTmd5      | Corresponding MD5 hash of quried hash present in VirusTotal DB |
| $VTsha1 | Corresponding SHA-1 hash of quried hash present in VirusTotal DB |
| $VTsha256 | Corresponding SHA-256 hash of quried hash present in VirusTotal DB |
| $VTPermalink | Permalink of report stored in VirusTotal |
| $VTPositive | List of scans returning positive detection |
| $VTNegative | List of scans returning negative detection |
| $VTPositives | Count of positive detection |
| $VTResponseCode | If the queried item is present in VirusTotal database it returns 1 ,if absent returns 0 and if the requested item is still queued for analysis it will be -2 |
| $VTTotal | Count of positive and negative detections |
| $VTSystemTstamp | Scan Date |



### Using the IBM X-Force Exchange API and DNIF  
The VirusTotal API is found on github at 

  https://github.com/dnif/lookup-ibmxforce

#### Getting started with IBM X-Force Exchange API and DNIF

1. #####    Login to your Data Store, Correlator, and A10 containers.  
   [ACCESS DNIF CONTAINER VIA SSH](https://dnif.it/docs/guides/tutorials/access-dnif-container-via-ssh.html)
2. #####    Move to the `/dnif/<Deployment-key>/lookup_plugins` folder path.
```
$cd /dnif/CnxxxxxxxxxxxxV8/lookup_plugins/
```
3. #####   Clone using the following command  
```  
git clone https://github.com/dnif/lookup-ibmxforce.git ibmxforce
```
4. #####   Move to the `/dnif/<Deployment-key>/lookup_plugins/ibmxforce/` folder path and open dnifconfig.yml configuration file     
    
   Replace the tag: <Add_your_api_key_here> with your IBM X-Force Exchange api key and password
```
lookup_plugin:
  IBMXFORCE_API_KEY: <Add_your_api_key_here>
  IBMXFORCE_API_PASS: <Add_your_api_pass_here>

```
