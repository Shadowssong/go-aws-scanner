package main

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/lair-framework/go-nmap"
	"os/exec"
)

type Instance struct {
	name                   string
	ip                     string
	dns                    string
	securityGroups         []*ec2.GroupIdentifier
	rawXmlScanResult       string
	parsedXmlScanResult    *nmap.NmapRun
	NmapOpenPorts          []OpenPort
	SecurityGroupOpenPorts []OpenPort
}

type OpenPort struct {
	Protocol string
	Port     int
	Type     string
}

func getName(tags []*ec2.Tag) string {
	for _, element := range tags {
		if *element.Key == "Name" {
			return *element.Value
		}
	}
	return ""
}

// Given instance object lets parse out important info
func parseInstanceInfo(inst *ec2.Instance) Instance {
	instanceInfo := Instance{}
	// Grab these pointers first and nil check them
	ip := inst.PublicIpAddress
	dns := inst.PublicDnsName
	sg := inst.SecurityGroups
	instanceInfo.name = getName(inst.Tags)

	// Do nil checks or go explodes then deref to get values
	if ip != nil {
		instanceInfo.ip = *inst.PublicIpAddress
	}
	if dns != nil {
		instanceInfo.dns = *inst.PublicDnsName
	}
	if sg != nil {
		instanceInfo.securityGroups = inst.SecurityGroups
	}

	return instanceInfo
}

func scanHost(host *Instance) {
	cmd := exec.Command("nmap", "-Pn", "-n", "-F", "--host-timeout", "300", "--open", "-T4", host.ip, "-oX", "-")
	stdout, err := cmd.Output()

	if err != nil {
		println(err.Error())
		return
	}

	host.rawXmlScanResult = string(stdout)
}

func parseOpenPorts(instance *Instance) {
	if len(instance.parsedXmlScanResult.Hosts) > 0 {
		fmt.Println("Open ports on host: ")
		for _, host := range instance.parsedXmlScanResult.Hosts {
			for _, ports := range host.Ports {
				openPort := OpenPort{Protocol: ports.Protocol, Port: ports.PortId, Type: ports.Service.Name}
				instance.NmapOpenPorts = append(instance.NmapOpenPorts, openPort)
				//fmt.Println(instance.NmapOpenPorts)
				//fmt.Printf("%+v\n", ports)
			}
		}
	} else {
		fmt.Println("No open ports found")
	}
}

//func describeSecurityGroups(svc *ec2.EC2, groupId []*ec2.GroupIdentifier) {
func describeSecurityGroups(svc *ec2.EC2, instance *Instance) {
	//groupId []*ec2.GroupIdentifier) {
	//func describeSecurityGroups(svc string, groupId []string) {
	//fmt.Printf("%+v\n", groupId)
	for _, sgGroupId := range instance.securityGroups {
		params := &ec2.DescribeSecurityGroupsInput{
			GroupIds: []*string{
				aws.String(*sgGroupId.GroupId),
			},
		}
		//resp, err := svc.DescribeSecurityGroups(params)
		resp, err := svc.DescribeSecurityGroups(params)
		if err != nil {
			panic(err)
		}
		//fmt.Printf("%+v\n", resp)
		for _, openPorts := range resp.SecurityGroups[0].IpPermissions {
			//openPort := OpenPort{Protocol: ports.Protocol, Port: ports.PortId, Type: ports.Service.Name}
			//instance.NmapOpenPorts = append(instance.NmapOpenPorts, openPort)
			//if openPorts.FromPort != nil {
			//	fmt.Println(*openPorts.FromPort)
			//}
			//if openPorts.ToPort != nil {
			//	fmt.Println(*openPorts.ToPort)
			//}
			//if openPorts.IpProtocol != nil {
			//	fmt.Println(*openPorts.IpProtocol)
			//}
			if openPorts.IpRanges != nil {
				//fmt.Println("Ranges open for ports ", *openPorts.FromPort, "to", *openPorts.ToPort)
				for _, ranges := range openPorts.IpRanges {
					if *ranges.CidrIp == "0.0.0.0/0" {
						fmt.Println("Found open SG, comparing...")
						var port int
						if openPorts.FromPort != nil {
							port = *openPorts.FromPort
						}
					}
					//fmt.Println(ranges)
				}
			}
			// compare

		}
	}
}

func main() {
	svc := ec2.New(session.New(), &aws.Config{Region: aws.String("us-east-1")})

	// Call the DescribeInstances Operation
	resp, err := svc.DescribeInstances(nil)
	if err != nil {
		panic(err)
	}

	fmt.Println("> Number of reservation sets: ", len(resp.Reservations))

	for idx := range resp.Reservations {
		for _, inst := range resp.Reservations[idx].Instances {
			// for each instance lets parse out the info we want
			instance := parseInstanceInfo(inst)
			fmt.Println("Processing: ", instance.name, " (", instance.ip, ")")
			scanHost(&instance)
			instance.parsedXmlScanResult, err = nmap.Parse([]byte(instance.rawXmlScanResult))
			if err != nil {
				fmt.Println(err.Error())
				return
			}
			parseOpenPorts(&instance)
			describeSecurityGroups(svc, &instance)
			//fmt.Println(instance.securityGroups)
		}
	}
}
