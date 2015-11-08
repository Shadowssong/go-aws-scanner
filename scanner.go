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
	name             string
	ip               string
	dns              string
	securityGroups   []*ec2.GroupIdentifier
	rawXmlScanResult string
	//parsedXmlScanResult NmapRun
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
			fmt.Println("Processing: ", instance.name)
			scanHost(&instance)
			//fmt.Println(instance.RawXmlScanResult)
			//instance.parsedXmlScanResult = nmap.Parse([]byte(instance.xmlScanResult))
			parsedScan, err := nmap.Parse([]byte(instance.rawXmlScanResult))
			if err != nil {
				fmt.Println(err.Error())
				return
			}
			fmt.Println("Open ports on host: ")
			for _, host := range parsedScan.Hosts {
				for _, ports := range host.Ports {
					fmt.Println(ports)
				}
			}
		}
	}
}
