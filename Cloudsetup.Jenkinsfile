import groovy.json.JsonSlurperClassic
import groovy.json.JsonBuilder
import java.security.MessageDigest



def runAWS(accessKey, accessSecret, defaultRegion, command) {
    try {
        return docker.image("releaseworks/awscli:latest").inside("--entrypoint \"\" -e AWS_ACCESS_KEY_ID=${accessKey} -e AWS_SECRET_ACCESS_KEY=${accessSecret} -e AWS_DEFAULT_REGION=${defaultRegion}") {
            return sh(returnStdout: true, script: "aws ${command}")
        }
    } catch (ClassNotFoundException e) {
        throw new Exception("Docker Pipeline plugin required")
    }
}

def parseIPAsInteger(String ipString) {
    int[] ip = new int[4];
    String[] parts = ipString.split("\\.");

    for (int i = 0; i < 4; i++) {
        ip[i] = Integer.parseInt(parts[i]);
    }

    long ipNumbers = 0;
    for (int i = 0; i < 4; i++) {
        ipNumbers += ip[i] << (24 - (8 * i));
    }

    return ipNumbers
}

class Globals {

    static String parseJson(String json) {
        return new JsonSlurperClassic().parseText(json);
    }

    static String dumpJson(Object obj) {
        new JsonBuilder(obj).toString();
    }

    static String generateMD5_String(String s) {
        return MessageDigest.getInstance("MD5").digest(s.bytes).encodeHex().toString()
    }

}

@NonCPS
String parseJson(String json) {
    return new JsonSlurperClassic().parseText(json);
}


class AWSRunner {
    def accessKey, accessSecret, defaultRegion, script

    AWSRunner(accessKey, accessSecret, defaultRegion, script) {
        this.accessKey = accessKey;
        this.accessSecret = accessSecret;
        this.defaultRegion = defaultRegion;
        this.script = script;
    }

    def run(command) {
        return script.runAWS(accessKey, accessSecret, defaultRegion, command);
    }

    def addTag(resource, key, value) {
        return run("ec2 create-tags --resources ${resource} --tags Key=${key},Value=${value}");
    }

    def waitForStatus(cmd, expected, closure) {
        def result = closure(Globals.parseJson(run(cmd)));
        while (result != expected) {
            result = closure(Globals.parseJson(run(cmd)));
        }
    }

    def searchForImage(searchString, query) {
        return run("ec2 describe-images --owners self --filters Name=tag:Name,Values=[${searchString}] --query ${query}")
    }

}

class VPCSubNetCidrs {

    def privateNetwork1, privateNetwork2, publicNetwork1, publicNetwork2;

    @NonCPS
    def convertToCidr(subnet) {
        return subnet + "/27";
    }

    VPCSubNetCidrs(prvtNetwork1, prvtNetwork2, pubNetwork1, pubNetwork2) {
        this.privateNetwork1 = convertToCidr(prvtNetwork1);
        this.privateNetwork2 = convertToCidr(prvtNetwork2);
        this.publicNetwork1 = convertToCidr(pubNetwork1);
        this.publicNetwork2 = convertToCidr(pubNetwork2);
    }

}

class KeyHelper {
    AWSRunner aws

    KeyHelper(AWSRunner aws) {
        this.aws = aws;
    }

    def createKey(name) {
        def resp = aws.run("ec2 create-key-pair --key-name=${name}");
        return Globals.parseJson(resp).KeyMaterial;
    }
}

class SecurityGroupHelper {
    AWSRunner aws

    SecurityGroupHelper(AWSRunner aws) {
        this.aws = aws;
    }

    def createSecurityGroup(name, vpcId) {
        def resp = aws.run("ec2 create-security-group --description=full-access-${name} --group-name=full-access-${name} --vpc-id=${vpcId}");
        return Globals.parseJson(resp).GroupId;
    }

    def addRule(groupId, cidr) {
        aws.run("ec2 authorize-security-group-ingress --group-id=${groupId} --protocol all --port all --cidr=${cidr}");
    }
}

class EC2InstanceHelper {
    static final DESC_INSTANCE_CMD = "ec2 describe-instances --instance-ids=%s";
    AWSRunner aws

    EC2InstanceHelper(AWSRunner aws) {
        this.aws = aws;
    }

    def createInstance(ami, name, keyName, instanceType, vpcId, securityGroupId, subnetId) {
        def resp = aws.run("ec2 run-instances --image-id=${ami} --count=1 --instance-type=${instanceType} --key-name=${keyName} --security-group-ids=${securityGroupId} --subnet-id=${subnetId}")

        def instances = Globals.parseJson(resp).Instances;
        assert instances instanceof List && instances.size() > 0;
        def instanceId = instances[0].InstanceId;
        aws.addTag(instanceId, 'Name', name);
        return instanceId;
    }

    def describeInstance(instanceId) {
        return Globals.parseJson(aws.run(String.format(DESC_INSTANCE_CMD, instanceId))).Reservations[0].Instances[0];
    }

    def restartInstance(instanceId) {
        return aws.run("ec2 reboot-instances --instance-ids ${instanceId}");
    }

    def waitForInit(instanceId) {
        aws.waitForStatus(String.format(DESC_INSTANCE_CMD, instanceId), 'running', {output -> output.Reservations[0].Instances[0].State.Name});
    }
}

class VPCHelper {

    static final VPC_DESC_CMD = "ec2 describe-vpcs --vpc-ids=%s"
    AWSRunner aws

    VPCHelper(AWSRunner aws) {
        this.aws = aws;
    }

    def createVPC(client, subnet) {
        def subnetWithCIDR = subnet + "/23";
        def resp = aws.run("ec2 create-vpc --cidr-block=${subnetWithCIDR}")
        def vpcId = Globals.parseJson(resp).Vpc.VpcId
        aws.addTag(vpcId, 'Name', client);
        return vpcId;
    }

    def createSubnet(name, vpcId, cidr, availabilityZone) {
        def resp = aws.run("ec2 create-subnet --cidr-block=${cidr} --vpc-id=${vpcId} --availability-zone=${availabilityZone}");
        def subnetId = Globals.parseJson(resp).Subnet.SubnetId;
        aws.addTag(subnetId, 'Name', name);
        return subnetId;
    }

    def createVPCPeering(clientVPCId, profilingVPCId) {
        def resp = aws.run("ec2 create-vpc-peering-connection --vpc-id ${clientVPCId} --peer-vpc-id ${profilingVPCId}")
        def peeringId = Globals.parseJson(resp).VpcPeeringConnection.VpcPeeringConnectionId
        aws.run("ec2 accept-vpc-peering-connection --vpc-peering-connection-id ${peeringId}")
        return peeringId;
    }

    def getVpcMainRouteTable(vpcId) {
        def resp = aws.run("ec2 describe-route-tables --filters=Name=vpc-id,Values=[${vpcId}] --query='RouteTables[?Associations[?Main == `true`]]'");
        return Globals.parseJson(resp)[0].RouteTableId;
    }

    def createInternetGateWay(name) {
        def resp = aws.run("ec2 create-internet-gateway");
        def gatewayId = Globals.parseJson(resp).InternetGateway.InternetGatewayId;
        aws.addTag(gatewayId, 'Name', name);
        return gatewayId;
    }

    def attachInternetGateway(gatewayId, vpcId) {
        aws.run("ec2 attach-internet-gateway --internet-gateway-id=${gatewayId} --vpc-id=${vpcId}");
    }

    def createRoute(routeTableId, cidr, deviceId, deviceCmd) {
        return aws.run("ec2 create-route --destination-cidr-block=${cidr} ${deviceCmd}=${deviceId} --route-table-id=${routeTableId}");
    }

	def createPeeringRoute(routeTableId, cidr, peeringId) {
        return aws.run("ec2 create-route --destination-cidr-block=${cidr} --route-table-id=${routeTableId} --vpc-peering-connection-id=${peeringId}");
    }

    def associateRouteTable(subnetID, routeTableId) {
        return aws.run("ec2 associate-route-table --route-table-id=${routeTableId} --subnet-id=${subnetID}");
    }

    def describeVPC(id) {
        return Globals.parseJson(aws.run(String.format(VPC_DESC_CMD, id)));
    }

    def partitionVPCSubnets(subnet) {

        def splitIp = subnet.split('\\.');

        splitIp[3] = '32';

        def privateNetwork2 = splitIp.join('.');

        splitIp[2] = ((splitIp[2] as Integer) + 1).toString();

        def publicNetwork2 = splitIp.join('.');

        splitIp[3] = '0';

        def publicNetwork1 = splitIp.join('.');

        return new VPCSubNetCidrs(subnet, privateNetwork2, publicNetwork1, publicNetwork2);
    }

    def waitForInit(id) {
        aws.waitForStatus(String.format(VPC_DESC_CMD, id), 'available', {output -> output.Vpcs[0].State});
    }

}

class GateWayHelper extends VPCHelper {

    static final ATTACHMENT_DESC_CMD = "ec2 describe-transit-gateway-attachments --transit-gateway-attachment-ids=%s";

    GateWayHelper(AWSRunner aws) {
        super(aws);
    }

    def createElasticIP() {
        def resp = aws.run("ec2 allocate-address --domain vpc");
        return Globals.parseJson(resp).AllocationId;
    }

    def createNatGateway(name, subnetId, elasticIPAllocId) {
        def resp = aws.run("ec2 create-nat-gateway --allocation-id=${elasticIPAllocId} --subnet-id=${subnetId}");
        def natId = Globals.parseJson(resp).NatGateway.NatGatewayId;
        aws.addTag(natId, 'Name', name);
        return natId;
    }

    def createRouteTable(name, vpcId) {
        def resp = aws.run("ec2 create-route-table --vpc-id=${vpcId}")
        def routeTableId = Globals.parseJson(resp).RouteTable.RouteTableId;
        aws.addTag(routeTableId, 'Name', name);
        return routeTableId;
    }

    def createTransitGatewayAttachment(name, transitGatewayId, vpcId, pubSubnet1, pubSubnet2) {
        def resp = aws.run("ec2 create-transit-gateway-vpc-attachment --transit-gateway-id=${transitGatewayId} --vpc-id=${vpcId} --subnet-ids=" + '[\\"' + pubSubnet1 + '\\",\\"' + pubSubnet2 + '\\"]');
        def attachmentId = Globals.parseJson(resp).TransitGatewayVpcAttachment.TransitGatewayAttachmentId;
        aws.addTag(attachmentId, 'Name', name);
        return attachmentId;
    }

    def addRouteToTransitGatewayRouteTable(cidr, transitGatewayRouteTableId, transitGatewayAttachmentId) {
        aws.run("ec2 create-transit-gateway-route --destination-cidr=${cidr} --transit-gateway-attachment-id=${transitGatewayAttachmentId} --transit-gateway-route-table-id=${transitGatewayRouteTableId}");
    }

    def createTransitGatewayRoute(routeTableId, cidr, tGatewayID) {
        super.createRoute(routeTableId, cidr, tGatewayID, "--transit-gateway-id");
    }

    def createNatRoute(routeTableId, cidr, natID) {
        super.createRoute(routeTableId, cidr, natID, "--nat-gateway-id");
    }

    def createInternetGateWayRoute(routeTableId, cidr, iGatewayID) {
        super.createRoute(routeTableId, cidr, iGatewayID, "--gateway-id");
    }

    def waitForInit(transitGatewayAttachmentId) {
        aws.waitForStatus(String.format(ATTACHMENT_DESC_CMD, transitGatewayAttachmentId),
        'available',
        {output -> output.TransitGatewayAttachments[0].State});
    }
}

class DBDetails {
    String dnsName;
    String resourceID;
    String dbName;
    String username;
    String password;

    DBDetails(dbName, resourceID, username, password) {
        this.dbName = dbName;
        this.resourceID = resourceID;
        this.username = username;
        this.password = password;
    }
}

class AWSDBHelper {
    static final DESC_DB_CMD = "rds describe-db-instances --db-instance-identifier=%s";
    AWSRunner aws

    AWSDBHelper(AWSRunner aws) {
        this.aws = aws;
    }

    def createDbSubnetGroup(groupName, subnets) {
        def cmd = "rds create-db-subnet-group --db-subnet-group-name=${groupName} --db-subnet-group-description=${groupName} --subnet-ids=[";

        assert subnets.size() > 0;

        def i = 0;
        for (; i < subnets.size()-1; i++) {
            cmd = cmd + '\\"' + subnets[i] + '\\",';
        }

        cmd = cmd + '\\"' + subnets[subnets.size() - 1] + '\\"]';

        def resp = aws.run(cmd);
        return Globals.parseJson(resp).DBSubnetGroup.DBSubnetGroupName;
    }

    def describeDb(instanceName) {
        return Globals.parseJson(aws.run("rds describe-db-instances --db-instance-identifier=${instanceName}")).DBInstances[0];
    }

    def createDbInstance(instanceName, dbName, dbPass, securityGroupId, subnetGroupName, engine, engineVersion, parameterGroupName, instanceType) {
        def resp = aws.run("rds create-db-instance --engine=${engine} --vpc-security-group-ids=${securityGroupId} --engine-version=${engineVersion} --db-instance-class=${instanceType} --db-parameter-group-name=${parameterGroupName} --db-name=${dbName} --master-username=cyberx --db-instance-identifier=${instanceName} --db-subnet-group-name=${subnetGroupName} --allocated-storage=100 --master-user-password=${dbPass}")
        def dbDetails = Globals.parseJson(resp).DBInstance;
        return new DBDetails(dbName, dbDetails.DbiResourceId, dbDetails.MasterUsername, dbPass);
    }

    def waitForInit(dbInstanceName) {
        aws.waitForStatus(String.format(DESC_DB_CMD, dbInstanceName), 'backing-up', {output -> output.DBInstances[0].DBInstanceStatus});
    }
}

class AWSLoadBalancerHelper {
    AWSRunner aws

    AWSLoadBalancerHelper(AWSRunner aws) {
        this.aws = aws;
    }

    def createLoadBalancer(client, description, vpcId, securityGroupId, subnets, type) {
        def nameHash = Globals.generateMD5_String("123${client}cyberx");
        def cmd = "elbv2 create-load-balancer --name ${nameHash} --tags Key=Description,Value=${description} Key=Client,Value=${client} --type ${type} --subnets ";

        for (subnet in subnets) {
            cmd = cmd + subnet + " ";
        }

        if (type == 'application') {
            cmd = cmd + "--security-group ${securityGroupId}";
        }
        def resp = aws.run(cmd);
        return Globals.parseJson(resp).LoadBalancers[0].LoadBalancerArn;
    }

    def createTargetGroup(name, protocol, vpcId, port) {
        def resp = aws.run("elbv2 create-target-group --target-type instance --name=${name} --protocol=${protocol} --port=${port} --vpc-id=${vpcId}");
        return Globals.parseJson(resp).TargetGroups[0].TargetGroupArn;
    }

    def registerTargets(targetGroupARN, target) {
        aws.run("elbv2 register-targets --target-group-arn=${targetGroupARN} --targets Id=${target}");
    }

    def createHTTPSListener(loadBalancerARN, port, certificateARN, targetGroupARN) {
        def resp = aws.run("elbv2 create-listener \
    --load-balancer-arn ${loadBalancerARN} \
    --protocol HTTPS \
    --port ${port} \
    --certificates CertificateArn=${certificateARN} \
    --ssl-policy ELBSecurityPolicy-FS-1-2-2019-08 --default-actions Type=forward,TargetGroupArn=${targetGroupARN}");
    }

    def createListener(loadBalancerARN, protocol, port, targetGroupARN) {
        def resp = aws.run("elbv2 create-listener \
    --load-balancer-arn ${loadBalancerARN} \
    --protocol ${protocol} \
    --port ${port} \
    --default-actions Type=forward,TargetGroupArn=${targetGroupARN}");
    }

    def getLoadBalancerDetails(loadBalancerARN) {
        return aws.run("elbv2 describe-load-balancers --load-balancer-arns ${loadBalancerARN}");
    }

    def getLoadBalancerDNSName(loadBalancerARN) {
        def resp = getLoadBalancerDetails(loadBalancerARN);
        return Globals.parseJson(resp).LoadBalancers[0].DNSName;
    }

    def getLoadBalancerHostedZone(loadBalancerARN) {
        def resp = getLoadBalancerDetails(loadBalancerARN);
        return Globals.parseJson(resp).LoadBalancers[0].CanonicalHostedZoneId;
    }

}

class Route53Helper {

    static final DESC_ROUTE_CMD = "route53  get-change --id=%s";
    AWSRunner aws;

    Route53Helper(AWSRunner aws) {
        this.aws = aws;
    }

    def generateCmdJson(client, action, dnsName, target, targetHostedZoneId, type) {
        def cmdMap = [
            'Comment': "adding route for ${client}",
            'Changes': [
                [
                    'Action': action,
                    'ResourceRecordSet': [
                        'Name': dnsName,
                        'Type': type,
                        'AliasTarget': [
                            'HostedZoneId': targetHostedZoneId,
                            'DNSName': target,
                            'EvaluateTargetHealth': false
                        ]
                    ]
                ]
            ]
        ]
        return Globals.dumpJson(cmdMap);
    }

    def executeRouteCmd(hotedZoneId, cmdFilePath) {
        return Globals.parseJson(aws.run("route53 change-resource-record-sets --hosted-zone-id ${hotedZoneId} --change-batch=file://${cmdFilePath}"))
    }

    def waitForInit(id) {
        aws.waitForStatus(String.format(DESC_ROUTE_CMD, id), 'INSYNC', {output -> output.ChangeInfo.Status});
    }
}




def CLIENT
def SUBNET
def vpcId
def AWS
def KEYNAME
def SECURITY_GROUP_ID
def ArrayList VPC_SUBNETS = [];
def TRANSIT_GATEWAY_ID
def TRANSIT_GATEWAY_ROUTE_TABLE_ID
def INTERNET_GATEWAY_ID
def CLIENT_IPS
def CHRONOS_AMI
def SISENSE_AMI
def CHRONOS_ID
def SISENSE_ID
def CERTIFICATE_ARN
def APP_LOADBALANCER_ARN
def NET_LOADBALANCER_ARN
def ROUTE53_HOSTED_ZONE_ID
def DB_INSTANCE_NAME
def NAT_ID
def ARTIFACTS_DIR
def PROFILER_VPC_ID
def PROFILER_VPC_CIDR
def INSTANCES = [];
def OUTPUT = [:]

pipeline {
    agent any


    parameters {
        string(name: 'Client Name', description: 'Client Name', defaultValue: 'Jenkins-Run')
        string(name: 'Route53 Hosted Zone ID', description: 'Hosted zone Id of Route53', defaultValue: 'Z3JV3UDQF4KI9H')
        string(name: 'Subnet', description: 'A netmask of /23 will be added, e.g. 1.1.1.1 -> 1.1.1.1/23', defaultValue: '10.0.200.0')
        extendedChoice(
            name: 'Version',
            description: 'IOT Version',
            type: 'PT_SINGLE_SELECT',
            value: '0.3,1.4',
            defaultValue: '1.4'
        )
        string(name: 'Transit GateWay ID', description: 'ID for AWS transit gateway', defaultValue: 'tgw-0af1a7488fcd8a750')
        string(name: 'Transit Route Table ID', description: 'ID for AWS transit gateway route table', defaultValue: 'tgw-rtb-066be0ddd1d5c622a')
        string(name: 'Client IPs', description: 'IP addresses for client collectors, separated by a comma', defaultValue: '')
        string(name: 'Certificate ARN', description: 'ARN for HTTPS load balancer Certificate', defaultValue: 'arn:aws:acm:eu-central-1:818597735158:certificate/<blank>')
        string(name: 'VPC Profiling service', description: 'the ID of the VPC Profiling', defaultValue: 'vpc-0ac28b7b30c272a31')
    }

    stages {

        stage('prep') {
            steps {
                script {
                    CLIENT = params['Client Name'];
                    SUBNET = params['Subnet'];
                    def version = params['Version'];
                    def versionsConf = Globals.parseJson(readFile('versions.json'));
                    CHRONOS_AMI = versionsConf[version]['chronos_ami'];
                    SISENSE_AMI = versionsConf[version]['sisense_ami'];
                    TRANSIT_GATEWAY_ID = params['Transit GateWay ID'];
                    TRANSIT_GATEWAY_ROUTE_TABLE_ID = params['Transit Route Table ID'];
                    CLIENT_IPS = params['Client IPs'];
                    CERTIFICATE_ARN = params['Certificate ARN'];
                    ROUTE53_HOSTED_ZONE_ID = params['Route53 Hosted Zone ID'];
                    PROFILER_VPC_ID = params['VPC Profiling service'];
                    AWS = new AWSRunner('<blank>', '<blank>', 'eu-central-1', this);
                    echo "building version: ${version}"
                }
            }
        }

        stage('create key') {
            steps {
                script {
                    echo "creating a new key"
                    KEYNAME = CLIENT
                    KeyHelper keyHelper = new KeyHelper(AWS);
                    writeFile file: "${KEYNAME}.pem", text:keyHelper.createKey(KEYNAME)
                    archiveArtifacts artifacts: "${KEYNAME}.pem", fingerprint: true
                }
            }
        }

        stage('setup VPC') {
            steps {
                script {
                    VPCHelper hVPC = new VPCHelper(AWS)
                    vpcId = hVPC.createVPC(CLIENT, SUBNET)
                    hVPC.waitForInit(vpcId);
                    echo "got vpc ${vpcId}"
                }
            }
        }

        stage('setup subnets') {
            steps {
                script {
                    VPCHelper hVPC = new VPCHelper(AWS)

                    echo (SUBNET);

                    echo ((SUBNET.split('\\.').length).toString());

                    echo (SUBNET.split('\\.')[0]);

                    def subnetPartition = hVPC.partitionVPCSubnets(SUBNET);

                    VPC_SUBNETS.add(hVPC.createSubnet(CLIENT + '-Private-1', vpcId, subnetPartition.privateNetwork1, 'eu-central-1a'));
                    VPC_SUBNETS.add(hVPC.createSubnet(CLIENT + '-Private-2', vpcId, subnetPartition.privateNetwork2, 'eu-central-1b'));
                    VPC_SUBNETS.add(hVPC.createSubnet(CLIENT + '-Public-1', vpcId, subnetPartition.publicNetwork1, 'eu-central-1a'));
                    VPC_SUBNETS.add(hVPC.createSubnet(CLIENT + '-Public-2', vpcId, subnetPartition.publicNetwork2, 'eu-central-1b'));

                }
            }
        }

        stage('create NAT and Internet Gateways') {
            steps {
                script {
                    GateWayHelper gatewayHelper = new GateWayHelper(AWS);

                    INTERNET_GATEWAY_ID = gatewayHelper.createInternetGateWay("${CLIENT}-InternetGateway");
                    gatewayHelper.attachInternetGateway(INTERNET_GATEWAY_ID, vpcId);

                    def eipId = gatewayHelper.createElasticIP();

                    NAT_ID = gatewayHelper.createNatGateway("${CLIENT}-NAT", VPC_SUBNETS[2], eipId);

                    echo "created nat gateway ${NAT_ID}"
                }
            }
        }

        stage('setup vpc routes') {
            steps {
                script {
                    GateWayHelper gatewayHelper = new GateWayHelper(AWS);

                    echo "attaching public subnets to transit gateway: " + Globals.dumpJson([VPC_SUBNETS[2], VPC_SUBNETS[3]]);
                    def transitGatewayAttachmentId = gatewayHelper.createTransitGatewayAttachment("${CLIENT}-gateway-attachment", TRANSIT_GATEWAY_ID, vpcId, VPC_SUBNETS[2], VPC_SUBNETS[3]);

                    gatewayHelper.waitForInit(transitGatewayAttachmentId);

                    gatewayHelper.addRouteToTransitGatewayRouteTable("${SUBNET}/23", TRANSIT_GATEWAY_ROUTE_TABLE_ID, transitGatewayAttachmentId);

                    def vpcRouteTableId = gatewayHelper.getVpcMainRouteTable(vpcId);

                    AWS.addTag(vpcRouteTableId, 'Name', "${CLIENT}-Private");
                    gatewayHelper.createNatRoute(vpcRouteTableId, "0.0.0.0/0", NAT_ID);

                    gatewayHelper.createTransitGatewayRoute(vpcRouteTableId, "192.168.0.0/16", TRANSIT_GATEWAY_ID);
                    gatewayHelper.createTransitGatewayRoute(vpcRouteTableId, "10.212.143.192/28", TRANSIT_GATEWAY_ID);

                    echo "finished setting up routes for vpc ${vpcId}"
                }
            }
        }

        stage('setup vpc peering') {
            steps {
                script {
					/* Connect newly created VPC to the profiler service VPC by creating a new 'peering' connection.
					 * 1. Create new 'peering connection'
					 * 2. Connect new vpc to profiler VPC using peering connection
					 * 3. Route all Profiler IPs to peering connection in the newly created VPC
					 * 4. Route all newly created VPC IPs to peering connection in the profiler's VPC.
					*/
					GateWayHelper gatewayHelper = new GateWayHelper(AWS)
					PROFILER_VPC_CIDR = gatewayHelper.describeVPC(PROFILER_VPC_ID).Vpcs[0].CidrBlock;
					def peeringId = gatewayHelper.createVPCPeering(vpcId, PROFILER_VPC_ID);
					AWS.addTag(peeringId, 'Name', "${CLIENT}-profiler-peering")
					def vpcRouteTableId = gatewayHelper.getVpcMainRouteTable(vpcId);
					gatewayHelper.createPeeringRoute(vpcRouteTableId, PROFILER_VPC_CIDR, peeringId);
					def profilerVPCMainRouteTable = gatewayHelper.getVpcMainRouteTable(PROFILER_VPC_ID);
					gatewayHelper.createPeeringRoute(profilerVPCMainRouteTable, "${SUBNET}/23", peeringId);

					echo "created peering ${peeringId} for vpc ${vpcId}"
                }
            }
        }

        stage('setup Public Route Table') {
            steps {
                script {
                    GateWayHelper gatewayHelper = new GateWayHelper(AWS);
                    VPCHelper hVPC = new VPCHelper(AWS);

                    def publicRouteTableId = gatewayHelper.createRouteTable("${CLIENT}-Public", vpcId);

                    gatewayHelper.createInternetGateWayRoute(publicRouteTableId, '0.0.0.0/0', INTERNET_GATEWAY_ID);

                    gatewayHelper.createTransitGatewayRoute(publicRouteTableId, '192.168.0.0/16', TRANSIT_GATEWAY_ID);

                    hVPC.associateRouteTable(VPC_SUBNETS[2], publicRouteTableId);
                    hVPC.associateRouteTable(VPC_SUBNETS[3], publicRouteTableId);
                }
            }
        }

        stage('create security group') {
            steps {
                script {
                    echo "creating security group for vpc ${vpcId}"

                    SecurityGroupHelper securityGroupHelper = new SecurityGroupHelper(AWS);

                    SECURITY_GROUP_ID = securityGroupHelper.createSecurityGroup("${CLIENT}-full-access", vpcId);

                    securityGroupHelper.addRule(SECURITY_GROUP_ID, "${SUBNET}/23");
                    securityGroupHelper.addRule(SECURITY_GROUP_ID, "37.142.39.186/32");
                    securityGroupHelper.addRule(SECURITY_GROUP_ID, "192.168.0.0/16");
                    securityGroupHelper.addRule(SECURITY_GROUP_ID, "10.212.143.192/28");
                    if (CLIENT_IPS != '') {
                        for (String clientIpAddr: CLIENT_IPS.split(',')) {
                            securityGroupHelper.addRule(SECURITY_GROUP_ID, "${clientIpAddr}/32");
                        }
                    }
                }
            }
        }

        stage('setup chronos') {
            steps {
                script {
                    echo "starting up a new chronos machine"

                    EC2InstanceHelper ec2InstanceHelper = new EC2InstanceHelper(AWS);
                    def instanceName = "IOT-${CLIENT}-CHRONOS";
                    CHRONOS_ID = ec2InstanceHelper.createInstance(CHRONOS_AMI, instanceName, KEYNAME, 't2.2xlarge', vpcId, SECURITY_GROUP_ID, VPC_SUBNETS[0])

                    ec2InstanceHelper.waitForInit(CHRONOS_ID);

                    echo "created Chronos instance: ${CHRONOS_ID}"
                }
            }
        }

        stage('setup sisense machine') {
            steps {
                script {
                    echo "starting up a new Sisense machine"

                    EC2InstanceHelper ec2InstanceHelper = new EC2InstanceHelper(AWS);

                    def instanceName = "IOT-${CLIENT}-SISENSE";
                    SISENSE_ID = ec2InstanceHelper.createInstance(SISENSE_AMI, instanceName, KEYNAME, 't2.2xlarge', vpcId, SECURITY_GROUP_ID, VPC_SUBNETS[0])

                    ec2InstanceHelper.waitForInit(SISENSE_ID);

                    echo "created Sisense instance: ${SISENSE_ID}"
                }
            }
        }

        stage('setup db') {
            steps {
                script {
                    echo "setting up a new database"

                    AWSDBHelper dbHelper = new AWSDBHelper(AWS);

                    def subnetGroupName = dbHelper.createDbSubnetGroup("${CLIENT}-DB-Subnet-group", VPC_SUBNETS);

                    echo "created subnet group: ${subnetGroupName}"

                    def dbPass = Globals.parseJson(AWS.run("secretsmanager get-random-password --exclude-punctuation")).RandomPassword;

                    echo "generated db pass: " + dbPass

                    DB_INSTANCE_NAME = "${CLIENT}-IOT-DB";
                    def dbDetails = dbHelper.createDbInstance(DB_INSTANCE_NAME, "cyberx", dbPass, SECURITY_GROUP_ID, subnetGroupName, 'mariadb', '10.2.21', 'iot-db', 'db.m5.large');

                    echo Globals.dumpJson(dbDetails);

                    OUTPUT['database'] = dbDetails;
                }
            }
        }

        stage('setup load balancers') {
            steps {
                script {
                    echo "setting up load balancers"

                    AWSLoadBalancerHelper loadBalancerHelper = new AWSLoadBalancerHelper(AWS);

                    NET_LOADBALANCER_ARN = loadBalancerHelper.createLoadBalancer(CLIENT, "${CLIENT}-network-lb", vpcId, SECURITY_GROUP_ID, [VPC_SUBNETS[2], VPC_SUBNETS[3]], 'network');

                    echo "created network load balancer: ${NET_LOADBALANCER_ARN}"

                    APP_LOADBALANCER_ARN = loadBalancerHelper.createLoadBalancer(CLIENT, "${CLIENT}-app-lb", vpcId, SECURITY_GROUP_ID, [VPC_SUBNETS[2], VPC_SUBNETS[3]], 'application');

                    echo "created application load balancer: ${APP_LOADBALANCER_ARN}"

                    def chronosTargetGroup = loadBalancerHelper.createTargetGroup("IOT-${CLIENT}-CHRONOS", "TCP", vpcId, 48879);
                    def chronosTunnelTargetGroup = loadBalancerHelper.createTargetGroup("IOT-${CLIENT}-TUNNEL", "TCP", vpcId, 22);
                    def chronosAPITargetGroup = loadBalancerHelper.createTargetGroup("IOT-${CLIENT}-CHRONOS-API", "HTTP", vpcId, 8080);
                    def sisenseTargetGroup = loadBalancerHelper.createTargetGroup("IOT-${CLIENT}-Sisense", "HTTP", vpcId, 8081);

                    loadBalancerHelper.registerTargets(chronosTargetGroup, CHRONOS_ID);
                    loadBalancerHelper.registerTargets(chronosTunnelTargetGroup, CHRONOS_ID);
                    loadBalancerHelper.registerTargets(chronosAPITargetGroup, CHRONOS_ID);
                    loadBalancerHelper.registerTargets(sisenseTargetGroup, SISENSE_ID);

                    loadBalancerHelper.createListener(NET_LOADBALANCER_ARN, 'TCP', '48879', chronosTargetGroup);
                    loadBalancerHelper.createListener(NET_LOADBALANCER_ARN, 'TCP', '48880', chronosTunnelTargetGroup);

                    loadBalancerHelper.createHTTPSListener(APP_LOADBALANCER_ARN, '443', CERTIFICATE_ARN, sisenseTargetGroup);
                    loadBalancerHelper.createHTTPSListener(APP_LOADBALANCER_ARN, '8443', CERTIFICATE_ARN, chronosAPITargetGroup);

                    echo "finished setting up load balancers"
                }
            }
        }

        stage ('Setup Route 53') {
            steps {
                script {
                    AWSLoadBalancerHelper loadBalancerHelper = new AWSLoadBalancerHelper(AWS);
                    Route53Helper routeHelper = new Route53Helper(AWS);

                    def loadBalancerDNSName = loadBalancerHelper.getLoadBalancerDNSName(APP_LOADBALANCER_ARN);
                    def loadBalancerHostedZoneId = loadBalancerHelper.getLoadBalancerHostedZone(APP_LOADBALANCER_ARN);

                    def route53URL = Globals.generateMD5_String("123${CLIENT}cyberx-route") + ".cx-cloud.info";
                    def loadBalancerURL = "dualstack.${loadBalancerDNSName}";
                    def cmdJson = routeHelper.generateCmdJson(CLIENT, 'CREATE', route53URL, loadBalancerURL, loadBalancerHostedZoneId, "A");

                    def route53CmdFilename = "${CLIENT}-route53.json";
                    writeFile file: route53CmdFilename, text: cmdJson;
                    def resp = routeHelper.executeRouteCmd(ROUTE53_HOSTED_ZONE_ID, "${WORKSPACE}/${route53CmdFilename}");
                    routeHelper.waitForInit(resp.ChangeInfo.Id);

                    echo "created route: ${route53URL}"
                    echo Globals.dumpJson(resp);

                    OUTPUT['Route53'] = ['dnsName': route53URL, 'loadBalancerDNSName': loadBalancerURL];
                }
            }
        }

        stage('restart sisense') {
            steps {
                script {
                    echo "rebooting sisense instance ${SISENSE_ID}"
                    def EC2InstanceHelper ec2InstanceHelper = new EC2InstanceHelper(AWS);

                    ec2InstanceHelper.waitForInit(SISENSE_ID);
                    ec2InstanceHelper.restartInstance(SISENSE_ID);
                    ec2InstanceHelper.waitForInit(SISENSE_ID);
                    echo "sisense instance ${SISENSE_ID} has successfully rebooted"
                }
            }
        }

        stage('create details json') {
            steps {
                script {
                    echo "deployment details"
                    def AWSDBHelper dbHelper = new AWSDBHelper(AWS);
                    dbHelper.waitForInit(DB_INSTANCE_NAME);

                    def dbDescription = dbHelper.describeDb(DB_INSTANCE_NAME);
                    echo Globals.dumpJson(dbDescription);
                    def dbDNS = dbDescription.Endpoint.Address;
                    OUTPUT['database'].dnsName = dbDNS;

                    def EC2InstanceHelper ec2InstanceHelper = new EC2InstanceHelper(AWS);
                    ec2InstanceHelper.waitForInit(SISENSE_ID);
                    ec2InstanceHelper.waitForInit(CHRONOS_ID);

                    def sisenseIP = ec2InstanceHelper.describeInstance(SISENSE_ID).PrivateIpAddress;
                    def chronosIP = ec2InstanceHelper.describeInstance(CHRONOS_ID).PrivateIpAddress;

                    AWSLoadBalancerHelper loadBalancerHelper = new AWSLoadBalancerHelper(AWS);
                    def chronosLoadBalancerDNSName = loadBalancerHelper.getLoadBalancerDNSName(NET_LOADBALANCER_ARN);

                    OUTPUT['collector-remote-host'] = chronosLoadBalancerDNSName;
                    OUTPUT['instances'] = [ 'sisenseIP': sisenseIP, 'chronosIP': chronosIP];

                    echo Globals.dumpJson(OUTPUT);

                    writeFile file: "${CLIENT}.json", text: Globals.dumpJson(OUTPUT)
                    archiveArtifacts artifacts: "${CLIENT}.json", fingerprint: true

                    echo "finished setting up ${CLIENT}"
                }
            }
        }

        stage('Copy Artifacts') {
            steps {
                script {
                    ARTIFACTS_DIR = "/share/build/aws-deployments/${CLIENT}/${env.BRANCH_NAME}/${env.BUILD_NUMBER}/";
                    sh(returnStdout: false, script: "mkdir -p ${ARTIFACTS_DIR}")

                    sh(returnStdout: false, script: "cp ${CLIENT}.pem ${ARTIFACTS_DIR}");
                    sh(returnStdout: false, script: "cp ${CLIENT}.json ${ARTIFACTS_DIR}");

                    echo "copied artifacts to ${ARTIFACTS_DIR}"
                }
            }
        }
    }

    post {
        success {
            slackSend (color: '#12E057', message: "Finished Job: '${env.JOB_NAME} [${env.BUILD_NUMBER}]' (${env.BUILD_URL}) for Client: ${CLIENT} \n Build artifacts are available in :${ARTIFACTS_DIR}")
        }

        failure {
            slackSend (color: '#E31B14', message: "Job Failed: '${env.JOB_NAME} [${env.BUILD_NUMBER}]' (${env.BUILD_URL}) for Client: ${CLIENT}")
        }
    }
}
