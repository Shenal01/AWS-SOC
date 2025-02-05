# AWS-SOC-Project<br>
SoC Project - Combining Security Onion, AWS Cloud Trail 
Events and Alert Monitoring
Creating IAM Users, Groups
Creating VMs and configure Inbound Outbound Rules

![image](https://github.com/user-attachments/assets/1f98f9f3-4519-4037-9d7d-55b1eb43c07c)
![image](https://github.com/user-attachments/assets/73708803-d0d4-4199-a560-438eb00683b4)



### Creating a VPC - Virtual private Cloud

- Change the IP to - /24 subnet

![Pasted image 20250203122419](https://github.com/user-attachments/assets/4d6b3e05-0250-496a-bf54-29f587e4679b)

![Pasted image 20250203122655](https://github.com/user-attachments/assets/79dcff33-19bf-43d5-b525-977b474432c5)

### Creating EC2 server for Security Onion

- Go to EC2
- Then Create ( search for Security Onion - free trial)
- Then Select it

![Pasted image 20250203124209](https://github.com/user-attachments/assets/585090ae-3dfc-48fd-acd4-cd6b51567e30)


- Edit Network settings 
- set VPC ---> That you created
- set subnet to public-1

![Pasted image 20250203134111](https://github.com/user-attachments/assets/79c2c7ca-3e5d-437e-9e09-086914694b0b)

#### Add security Group Rule

- type: All traffic
- source type: My IP

![Pasted image 20250203134538](https://github.com/user-attachments/assets/1ccb25c1-3752-4681-bf88-c91a5c29a23b)


- Need 2 Network interfaces One for Security Onion Console
- Another for monitoring and sniffing

###### Successfully Launched EC2 Instance for Security Onion.

![Pasted image 20250203135158](https://github.com/user-attachments/assets/8ebeb4c0-7ebf-46c8-9955-60ba1d3bebe1)

---
- Need an elastic IP address to the management network interface
- Go to Network and Security --> Elastic IP

![Pasted image 20250203135446](https://github.com/user-attachments/assets/aa4adb44-f4ca-41fd-9be6-7e21ed0e918c)


- Allocate an IP address

![Pasted image 20250203135606](https://github.com/user-attachments/assets/77946d61-e589-4f0e-a20e-243e6cfe463f)


#### Associate Elastic IP via Network Interface

- Go to the Elastic IP and then Select actions and click associate elastic IP

![Pasted image 20250203140215](https://github.com/user-attachments/assets/5723a91f-c459-48bc-bfc5-7dfa94f7b45f)


- set resource type ---> Network Interface
- Set the correct network interface
- set private IP
- allow reassociate

![Pasted image 20250203140848](https://github.com/user-attachments/assets/14158f06-5329-402f-8257-ffb79da49a4d)


- Now go to the Instances, then you can see a public IP will be assigned to the EC2 Instance.
---

### Login via SSH Using PUTTY

- open PUTTY
- Then Paste the IP
- go to SSH Credentials then select the private key that you downloaded earlier.
- Click open
- Click Accept

![Pasted image 20250203141924](https://github.com/user-attachments/assets/6247730f-db4c-4190-b58c-1b3cebb799af)


![Pasted image 20250203142106](https://github.com/user-attachments/assets/c421a70c-f42e-4903-ac6a-9f518219f692)


- Default user ----> ==onion==
- then set up the VM
- yes ---> Standalone Install 

![Pasted image 20250203150533](https://github.com/user-attachments/assets/fec6b9f3-ac21-4dd5-9358-a293e22b799c)


#### Change the Host File in Windows

- Go to note pad (run as Administrator)
- PATH ---> C:\Windows\System32\drivers\etc
- select all file types then select hosts file, add the host to the file

#### Login to Security Onion

![Pasted image 20250203150533](https://github.com/user-attachments/assets/70d21e32-0fe4-4e24-907a-9cda5c8a5d65)


![Pasted image 20250203161858](https://github.com/user-attachments/assets/2e52aa02-b383-4e39-9de8-2b8c20f745eb)


![Pasted image 20250203161942](https://github.com/user-attachments/assets/3d800777-154b-4dd6-802a-ce70ecea4409)


---
### Create a Security Group

![Pasted image 20250203163032](https://github.com/user-attachments/assets/ac445daa-b093-48ae-93fc-cb2fa5356f46)


- Create new group
- set inbound rule 
- Type ----> All traffic
- Source -----> Custom
- IP Range -----> 10.0.100.0/24 (make sure to keep the communication among internal network)

- Sniffing interface is the other interface. (not the public IP)

![Pasted image 20250203163708](https://github.com/user-attachments/assets/e24c42a8-f847-43a1-bc4d-05bf7e3c8104)


- Go to actions on network interface 
- Then change the security group

---

### Create the Linux Instance

- Instance type -----> t3.nano
- create the Key Pair (PPK) --> login via PUTTY
- put it to the same VPC that you created
- Enable auto assign IP, Source:0.0.0.0/0
- This allows all IP to access your instance which is not good practice (this is only for the easiness of the project )

![Pasted image 20250205112253](https://github.com/user-attachments/assets/cacab12d-0a30-4781-ae71-9c03b684944f)


### Setting UP Traffic Mirroring

- Capture and monitor your Network Traffic on your VPC.

- Go to the Console ---> VPC ----> Traffic Mirroring

![Pasted image 20250205113132](https://github.com/user-attachments/assets/a588c385-77c7-45e4-843e-0ec4dc2ae992)


##### Create mirror traffic filter

![Pasted image 20250205113642](https://github.com/user-attachments/assets/209e378a-f498-4542-b38d-adc951ac623f)


(This is Insecure only for the project do not configure like this on real world scenario.....!)

##### Create Traffic Mirror Target

- Select the network interface for the sniffing one (not the management it is for monitoring that with a public IP)

![Pasted image 20250205114352](https://github.com/user-attachments/assets/67b90c56-69ff-4078-b505-9d9b6224e2da)

##### Creating a Mirror Session

- Set Mirror Source ---> Linux Network Interface ID
- Set Mirror Target
- Set Mirror Filter

![Pasted image 20250205115906](https://github.com/user-attachments/assets/de9dfb9a-c7b8-44e9-9fb0-dd1828265b4c)


![Pasted image 20250205115933](https://github.com/user-attachments/assets/1f932b51-5c18-4233-a8c3-36ac48cec9a8)


##### Login using Key files to Both Linux machine and Security Onion

```
Linux ----> ec2-user
Security Onion ----> onion
```


##### Set up TCP dump Listener

![Pasted image 20250205132611](https://github.com/user-attachments/assets/3886df0b-ba32-4515-8009-d60597d3a86a)


```sh
[onion@projectso ~]$ sudo tcpdump -i eth1 host 10.0.100.12
```

```sh
curl -sSL https://raw.githubusercontent.com/3CORESec/testmynids.org/master/tmNIDS -o /tmp/tmNIDS && chmod +x /tmp/tmNIDS && /tmp/tmNIDS
```

- Paste above command to generate some malicious requests
- GitHub: https://github.com/3CORESec/testmynids.org

![Pasted image 20250205133404](https://github.com/user-attachments/assets/2a1d80e4-e106-4ac6-af88-d89d5a54d898)


(to paste just use the right click)
- type 11 to perform a IP lookup

- This will may not work because it doesn't allow internal traffic so add a new rule

![Pasted image 20250205134052](https://github.com/user-attachments/assets/b4d8525f-5d79-4ca1-b1cc-34f8656262b3)


### Installing windows server instance

- Choose Windows server
- t3 medium
- set up network configurations
- auto assign IP ---> Enable

![Pasted image 20250205171652](https://github.com/user-attachments/assets/ffb67ac3-f282-4536-a8e7-102b996e35b7)


- To get the password click " Get Password"

![Pasted image 20250205172035](https://github.com/user-attachments/assets/4bac60c2-7141-4343-a21b-36799e663821)


- Upload .PEM file then click decrypt password
![Pasted image 20250205172407](https://github.com/user-attachments/assets/5b8ef3a5-91cc-4681-827b-53e54ff4c41d)


```
Password: W)C6vUh5D!2nA&f5)gJnCkNykip-tb;-
```

![Pasted image 20250205192854](https://github.com/user-attachments/assets/87b686b4-a77e-4e7f-b104-651b7010b952)

### Installing Sysmon

- **Sysmon** (short for System Monitor) is a powerful tool developed by Microsoft as part of the Sysinternals suite. It's designed to monitor and log system activity on Windows machine

###### View Windows logs using Windows Event Viewer

![Pasted image 20250205193100](https://github.com/user-attachments/assets/5b610bda-584e-482a-b21f-b1dfaf105514)


![Pasted image 20250205193542](https://github.com/user-attachments/assets/12907faf-c70a-42ec-a8c5-8bce450850bd)


- Going to Apply swift on security, (sys internal configuration file template with default high quality event tracing)
- GitHub : [GitHub - SwiftOnSecurity/sysmon-config: Sysmon configuration file template with default high-quality event tracing](https://github.com/SwiftOnSecurity/sysmon-config)

![Pasted image 20250205194111](https://github.com/user-attachments/assets/4383a94f-f9b6-441c-a847-c2b3c636fc45)


![Pasted image 20250205194504](https://github.com/user-attachments/assets/99161b47-67dc-4e1c-b4c4-6040192f7b82)


- extract the file and open config file with Notepad.
- Copy that file into sysmon folder

![Pasted image 20250205195223](https://github.com/user-attachments/assets/05fc5449-7e49-4d30-9959-397116ee79a7)


- Now there must be Sysmon file in Windows Event listener

![Pasted image 20250205195733](https://github.com/user-attachments/assets/2f9f6f42-3a28-4f34-9bb8-6589d6dc7f0b)

- Also check the services 

![Pasted image 20250205200018](https://github.com/user-attachments/assets/e5ef7430-2ec5-430b-875f-e8658924e686)


- Now it is confirm that Sysmon is working correctly.

### Configuring Windows to Send logs to the Security Onion 

###### Change the Hosts File

![Pasted image 20250205200620](https://github.com/user-attachments/assets/ba8dcbe3-eabc-4191-948c-c963930cda43)


- Copy the IP Address of Security Onion (public IP) and then paste it.

![Pasted image 20250205200920](https://github.com/user-attachments/assets/dff08813-3998-41b3-951d-ffc658f9fc68)


- Now Login to the Dashboard of Security Onion using your creds....

```url
https://projectso/
```

![Pasted image 20250205201758](https://github.com/user-attachments/assets/422e3329-7857-4384-adc8-1c1879797cc3)


#### Installing Elastic Agent

- Go to download on Security Onion Dashboard

![Pasted image 20250205202519](https://github.com/user-attachments/assets/89b84a07-9be4-41dd-aa4a-bfc97a7dd77d)


- Go to the "firewall.hostgroups.elastic_agent_endpoint"
- Put Your Windows Server IP on the Grid Configuration -----> Firewall
- Paste the IP and save (on All host groups)

![Pasted image 20250205203122](https://github.com/user-attachments/assets/d7b74927-96d0-43eb-8ac0-3a02746690c2)


![Pasted image 20250205203558](https://github.com/user-attachments/assets/edb8aa0e-f5d1-4397-8021-5fe6d4bcf2c5)

- If this didn't work check firewall rules 
- Read the txt file and find out the ERROR
- (check inbound/ outbound rules)

![Pasted image 20250205211528](https://github.com/user-attachments/assets/c87326a8-6d0f-4a8f-8281-01862544c632)

- Now go to the Elastic Fleet

![Pasted image 20250205211748](https://github.com/user-attachments/assets/a0a56d79-258b-4074-996b-45f5633fb52a)


![Pasted image 20250205211805](https://github.com/user-attachments/assets/186f319b-89f8-4135-b873-4ebc2e8954e6)

- use same creds that you used on Security Onion.

```
Elastic Fleet is a component of the Elastic Stack (ELK Stack) that provides centralized management for Elastic Agents. Elastic Agents are unified agents that collect logs, metrics, and other types of data from hosts. Fleet allows you to manage these agents, update their policies, and coordinate actions across multiple agents. It simplifies the deployment and management of monitoring and security solutions across your infrastructure.
```

![Pasted image 20250205212341](https://github.com/user-attachments/assets/81580a07-a62a-4114-b344-e45f773e26e6)

- You can see that Hosts names are same

### AWS Logs

- #### Create IAM user - must have correct permissions
- #### Create Cloud Trail Logs with S3 Buckets
- #### Create SQS Queue - Enable SNS - make sure JSON policy is correct
- #### Elastic Agent Integration with AWS
- #### Test and search with event ID

![Pasted image 20250205213613](https://github.com/user-attachments/assets/a9fcea29-7c36-43b7-a70b-605e0374a2db)


- Creating Cloud Trail ---> Create S3 Bucket ----> Create SQS (Amazon Simple Queue Service (SQS))
- Cloud trail forwards the traffic onto SQS 
- Then SQS Forwards it to Security Onion

![Pasted image 20250205214552](https://github.com/user-attachments/assets/70cd705b-c412-4d14-aee0-35f4098fda78)

- Go to AWS ----> ADD AWS

![Pasted image 20250205214659](https://github.com/user-attachments/assets/2a053223-5dd0-40bb-82a9-5b1ac3518418)


- Before Configure this You need to Create a IAM user.

![Pasted image 20250205215218](https://github.com/user-attachments/assets/2fc3802c-f88c-4fe2-8c5b-766b64803755)


- You need to create a group with above permissions

![Pasted image 20250205215302](https://github.com/user-attachments/assets/c91a1692-96e4-4abd-9700-a1d383201a3e)


- Only provide above access Do not provide Full access for Groups.
- Violates Least amount of PRIVILEGES

![Pasted image 20250205220904](https://github.com/user-attachments/assets/560be52f-74c9-4c74-9020-149c881929b3)

![Pasted image 20250205220922](https://github.com/user-attachments/assets/eaf1f12a-3382-48a1-b585-b0efec672981)

![Pasted image 20250205220943](https://github.com/user-attachments/assets/9256888a-81a7-47cc-a9f2-a62cfc78ba58)


- Create Access key

![Pasted image 20250205221313](https://github.com/user-attachments/assets/1d7ed365-a602-4c93-be23-1e1277af42ad)


![Pasted image 20250205221451](https://github.com/user-attachments/assets/cd18083a-52da-4e82-acbc-3795de6ae0e2)


```
Access Key: AKIAR7HWX7VVTSCBOXUP : 7bvjm/SWZMIbM9PykeLHQxTHHM/t2pfmm3n+qiOj
```

#### Create Cloud Trail

```
arn:aws:s3:::aws-cloudtrail-logs-135808941419-48a60a5c
```

![Pasted image 20250205222603](https://github.com/user-attachments/assets/d851a9be-5ba8-48bc-a10a-3d86ede03e53)

![Pasted image 20250205222456](https://github.com/user-attachments/assets/03bebc74-9732-4175-ac62-5dfb918087dc)

![Pasted image 20250205223022](https://github.com/user-attachments/assets/784e14ab-1925-422c-bd02-02eb9f5a7f9a)


```
https://www.elastic.co/guide/en/observability/current/monitor-aws-elastic-agent.html
```

```json
{
  "Version": "2012-10-17",
  "Id": "example-ID",
  "Statement": [
    {
      "Sid": "example-statement-ID",
      "Effect": "Allow",
      "Principal": {
        "AWS": "*"
      },
      "Action": "SQS:SendMessage",
      "Resource": "<sqs-arn>", 
      "Condition": {
        "StringEquals": {
          "aws:SourceAccount": "<source-account>" 
        },
        "ArnLike": {
          "aws:SourceArn": "<s3-bucket-arn>" 
        }
      }
    }
  ]
}
```

- Create it without SQS ARN
- After creating it you can edit it again in Queue Policies and add the SQS ARN

```
arn:aws:sqs:us-east-1:135808941419:videodemo

https://sqs.us-east-1.amazonaws.com/135808941419/videodemo
```

- Enable Event Notifications on S3 buckets
- Go to Properties
- Then scroll down and turn on Event Notification

![Pasted image 20250205224137](https://github.com/user-attachments/assets/865f909b-e490-43e1-9bd1-55007a58a724)

![Pasted image 20250205224208](https://github.com/user-attachments/assets/f68e3a27-61a8-4f43-a004-7417c62e7eb6)

![Pasted image 20250205224258](https://github.com/user-attachments/assets/d137bc2a-1b9b-4699-a15a-e7e723f30cd6)

- Click All Objects
- set Destination -----> SQS
- Then Choose the SQS You created

![Pasted image 20250205224412](https://github.com/user-attachments/assets/9829296f-5cb5-4eda-9457-280cbb423fa9)

##### Testing Cloud Trail

- Create a user and Add user to a group
- It must be shown in Event Log

![Pasted image 20250205230903](https://github.com/user-attachments/assets/68a04bef-1708-4cca-bc89-f30cbb1aa84e)


```
AKIAR7HWX7VV2ZXEF22L
w0c6BTVeEnTzaZ4neBVN+ht1wzBdoFBf6XREuN8V
```
If the events wont work properly please ensure that your JSON code, Configurations are correct otherwise it won't work properly.....
Make sure Your Access Key has been used by the Security Onion 

![image](https://github.com/user-attachments/assets/a325453b-4b95-4de6-8962-c591ef8200a4)

##### Credits<br>Nicole Enesse - <a href='https://www.youtube.com/watch?v=cwhvndEfuRw'> YouTube Channel </a><br>

#### Thank You.... ! 
<br> By SHENAL MARIO 










